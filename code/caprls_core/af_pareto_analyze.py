"""Read-only audit and paired-round analysis of a completed AF study.

This tool validates the retained dataset before computing ratios. It does not
rerun queries, choose favorable cases, or rewrite baselines. Versioned execution
profiles are audited against retained session observations; upstream issuer
capabilities and general concurrent authorization guarantees are not certified.
"""

from __future__ import annotations

import argparse
from collections import Counter
import csv
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import random
import re
import statistics
from typing import Any, Mapping, Sequence


SCHEMA = "af_pareto_analysis_v1"
PRIMARY = "median_end_to_end_ms_including_validation_and_client"
MEASURE_FIELDS = {
    PRIMARY: "database_total_ms",
    "median_postgres_planning_ms": "postgres_planning_ms",
    "median_postgres_query_execution_ms": "execution_ms",
}
COMPARATORS = ("af-old", "local-greedy", "native-pg-rls", "barrier-only", "injection-only")
FIXED_MODES = ("native-pg-rls", "local-greedy", "barrier-only", "injection-only")
TRUSTED_PROFILE_SCHEMA = "e3_trusted_explicit_execution_profile_v1"


class AnalysisError(ValueError):
    pass


def validated_round_orders(protocol: Mapping[str, Any], modes: Sequence[str],
                           warmup: int, measured: int) -> list[list[int]] | None:
    schedule = protocol.get("schedule", "casewise_deterministic_rotating_rounds")
    if schedule == "casewise_deterministic_rotating_rounds":
        return None
    require(schedule == "casewise_balanced_three_mode_rounds_v2", "unknown measurement schedule")
    rows = protocol.get("balanced_round_order_indices")
    require(len(modes) == 3 and isinstance(rows, list) and len(rows) == 6,
            "balanced schedule needs three modes and six orders")
    require(warmup >= 6 and measured >= 6 and warmup % 6 == measured % 6 == 0,
            "incomplete balanced phase cycles")
    for row in rows:
        require(isinstance(row, list) and len(row) == 3 and
                all(type(value) is int for value in row) and sorted(row) == [0, 1, 2],
                "invalid balanced round permutation")
    require(Counter((mode, position) for row in rows for position, mode in enumerate(row)) ==
            Counter({(mode, position): 2 for mode in range(3) for position in range(3)}),
            "unbalanced period positions")
    flat = [value for row in rows for value in row]
    require(Counter(zip([flat[-1]]+flat[:-1], flat)) ==
            Counter({(previous, current): 2 for previous in range(3) for current in range(3)}), "unbalanced predecessor transitions")
    return rows


def require(condition: Any, message: str) -> None:
    if not condition:
        raise AnalysisError(message)


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def json_digest(value: Any) -> str:
    return sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def number(value: Any, label: str, *, positive: bool = False) -> float:
    require(isinstance(value, (int, float)) and not isinstance(value, bool), "non-numeric " + label)
    result = float(value)
    require(math.isfinite(result) and (result > 0 if positive else result >= 0), "invalid " + label)
    return result


def integer(value: Any, label: str, *, minimum: int = 0) -> int:
    require(type(value) is int and value >= minimum, "invalid integer " + label)
    return value


def close(left: Any, right: Any, label: str) -> None:
    require(math.isclose(number(left, label), number(right, label), rel_tol=1e-12, abs_tol=1e-9),
            "inconsistent " + label)


def unique_strings(value: Any, label: str) -> list[str]:
    require(isinstance(value, list) and bool(value), "missing declarations: " + label)
    require(all(isinstance(item, str) and item for item in value), "invalid declarations: " + label)
    require(len(set(value)) == len(value), "duplicate declarations: " + label)
    return value


def inventory(root: Path) -> dict[str, Any]:
    result = {}
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), "input symlink is not an immutable retained file: " + str(path))
        if path.is_file():
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024*1024), b""):
                    digest.update(chunk)
            result[str(path.relative_to(root))] = {"bytes": path.stat().st_size,
                                                   "sha256": "sha256:"+digest.hexdigest()}
    return result


def read_json(root: Path, relative: str) -> Any:
    path = root/relative
    require(path.is_file(), "missing required file: " + relative)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        raise AnalysisError("invalid JSON file: " + relative) from exc


def source_digest(identity: Any, label: str) -> str:
    require(isinstance(identity, dict) and isinstance(identity.get("files"), dict) and identity["files"],
            "missing source identity: " + label)
    require(identity.get("digest") == json_digest(identity["files"]), "invalid source digest: " + label)
    for path, value in identity["files"].items():
        require(isinstance(path, str) and not Path(path).is_absolute() and ".." not in Path(path).parts,
                "invalid source path: " + label)
        require(isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value),
                "invalid source file hash: " + label)
    return identity["digest"]


def digest_field(value: Any, label: str) -> str:
    require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value),
            "invalid digest: " + label)
    return value


def execution_profile_audit(spec: Mapping[str, Any], selection: Mapping[str, Any], *,
                            query: str, policy: str, pg_env: Mapping[str, Any],
                            required_profile: str | None, label: str) -> dict[str, Any] | None:
    """Audit serialized profile v1 internally, without importing its issuer.

    Context/finite-fragment/receipt digests name upstream, source-bound evidence.
    Their missing source preimages are deliberately not guessed from today's
    e3_main constants or renderer.
    """
    bound = selection["bound_runner"]
    declared = selection.get("execution_profile")
    pieces = (spec.get("session_contract"), spec.get("execution_profile"),
              bound.get("session_contract"), bound.get("execution_profile"))
    profiled = any(piece is not None for piece in pieces) or declared == "trusted_explicit"
    if required_profile is not None:
        require(profiled, "required new execution profile is missing: " + label)
    if not profiled:
        require(declared is None or (type(declared) is str and declared in {
                    "native_rls", "legacy_native_cost_trusted_explicit_execution"}),
                "unsupported declared execution profile: " + label)
        return None
    require(declared == "trusted_explicit" and all(type(piece) is dict for piece in pieces),
            "partial or inconsistent execution profile metadata: " + label)
    contract, profile = pieces[:2]
    require(contract == pieces[2] and profile == pieces[3],
            "bound/spec execution contract or profile differs: " + label)
    require(set(contract) == {"role", "search_path", "gucs", "transaction_isolation", "read_only", "digest"},
            "execution contract fields differ from declared schema: " + label)
    require(type(contract["role"]) is str and contract["role"] and
            contract["search_path"] == ["pg_catalog", "public"] and
            type(contract["gucs"]) is dict and
            set(contract["gucs"]) == {"row_security", "jit", "max_parallel_workers_per_gather", "plan_cache_mode"} and
            all(type(value) is str and value for value in contract["gucs"].values()) and
            contract["gucs"]["row_security"] == "on" and
            contract["transaction_isolation"] == "repeatable read" and contract["read_only"] is True,
            "unsupported trusted execution session contract: " + label)
    reconstructed = {key: value for key, value in contract.items() if key != "digest"}
    require(contract["digest"] == json_digest(reconstructed) == bound.get("session_contract_digest"),
            "execution session contract digest mismatch: " + label)
    require(spec.get("role") == contract["role"] and spec.get("sql_source") != "rls" and
            spec.get("template_id") != "native_pg_rls_v1",
            "trusted explicit spec delegates native RLS or uses another role: " + label)
    profile_keys = {"schema", "name", "query_id", "policy_id", "principal_id", "policy_validation_role",
                    "execution_role", "session_user", "database", "context_digest", "receipt_digest",
                    "finite_fragment_digest", "catalog_claims", "session_contract_digest", "profile_digest"}
    require(set(profile) == profile_keys and profile.get("schema") == TRUSTED_PROFILE_SCHEMA and
            profile.get("name") == "trusted_explicit", "unsupported execution profile schema: " + label)
    for field in ("principal_id", "policy_validation_role", "execution_role", "session_user", "database"):
        require(type(profile[field]) is str and profile[field], "missing execution profile " + field + ": " + label)
    for field in ("context_digest", "receipt_digest", "finite_fragment_digest", "session_contract_digest", "profile_digest"):
        digest_field(profile[field], label+":"+field)
    require(profile["profile_digest"] == json_digest({key: value for key, value in profile.items() if key != "profile_digest"}),
            "execution profile intrinsic digest mismatch: " + label)
    require((profile["query_id"], profile["policy_id"]) == (query, policy) and
            profile["execution_role"] == profile["session_user"] == contract["role"] and
            profile["session_contract_digest"] == contract["digest"],
            "execution profile case/session binding mismatch: " + label)
    require(profile["session_user"] == pg_env.get("user") and profile["database"] == pg_env.get("database"),
            "execution profile differs from retained database connection: " + label)
    claims = profile["catalog_claims"]
    require(type(claims) is dict and set(claims) == {"database", "role", "relations", "artifact_validator"} and
            claims["database"] == profile["database"], "malformed source-bound catalog claims: " + label)
    role = claims["role"]
    require(type(role) is dict and set(role) == {"role_name", "is_superuser", "bypasses_rls", "member_of", "members"} and
            role["role_name"] == contract["role"] and type(role["is_superuser"]) is bool and
            type(role["bypasses_rls"]) is bool and (role["is_superuser"] or role["bypasses_rls"]),
            "invalid trusted catalog role flags: " + label)
    for field in ("member_of", "members"):
        require(type(role[field]) is list and all(type(value) is str and value for value in role[field]) and
                role[field] == sorted(set(role[field])), "invalid catalog role memberships: " + label)
    relations = claims["relations"]
    relation_keys = {"oid", "schema_name", "relation_name", "owner", "row_security_enabled", "force_row_security",
                     "relation_kind", "has_rules", "has_triggers", "has_subclasses", "is_partition", "builtin_columns_only"}
    require(type(relations) is list and relations, "missing finite catalog relation claims: " + label)
    names, oids = [], []
    for relation in relations:
        require(type(relation) is dict and set(relation) == relation_keys, "malformed finite relation claim: " + label)
        integer(relation["oid"], "catalog relation OID", minimum=1)
        require(all(type(relation[field]) is str and relation[field] for field in
                    ("schema_name", "relation_name", "owner", "relation_kind")) and
                all(type(relation[field]) is bool for field in
                    ("row_security_enabled", "force_row_security", "has_rules", "has_triggers",
                     "has_subclasses", "is_partition", "builtin_columns_only")),
                "invalid finite relation claim scalar types: " + label)
        names.append((relation["schema_name"], relation["relation_name"]))
        oids.append(relation["oid"])
        require(relation["schema_name"] == "public" and relation["owner"] == profile["session_user"] and
                relation["relation_kind"] == "r" and relation["builtin_columns_only"] is True and
                # Trigger presence is retained and type-checked above. Pure
                # SELECT cannot fire PG triggers; rules/views remain excluded.
                all(relation[field] is False for field in ("has_rules", "has_subclasses", "is_partition")) and
                relation["row_security_enabled"] == relation["force_row_security"],
                "unsupported finite catalog premise: " + label)
    require(names == sorted(set(names)) and len(set(oids)) == len(oids),
            "duplicate or unordered finite catalog claims: " + label)
    require(sum(relation["row_security_enabled"] for relation in relations) == 1,
            "finite profile has no unique protected RLS relation: " + label)
    validator = claims["artifact_validator"]
    require(type(validator) is dict and set(validator) == {"language", "security_definer", "config", "returns_boolean", "body"} and
            validator["language"] == "plpgsql" and validator["security_definer"] is False and
            validator["returns_boolean"] is True and
            validator["config"] is None and type(validator["body"]) is str and validator["body"],
            "invalid source-bound artifact validator claim: " + label)
    expected_environment = {
        "current_database": profile["database"], "session_user": profile["session_user"],
        "current_user": contract["role"], "search_path": ", ".join(contract["search_path"]),
        **contract["gucs"], "transaction_isolation": contract["transaction_isolation"],
        "transaction_read_only": "on", "role_is_superuser": role["is_superuser"],
        "role_bypasses_rls": role["bypasses_rls"],
    }
    return {"contract": contract, "profile": profile, "expected_environment": expected_environment}


def execution_environment_audit(observed: Any, profile_audit: Mapping[str, Any], label: str) -> dict[str, Any]:
    require(type(observed) is dict, "missing actual execution environment: " + label)
    require(set(observed) == set(profile_audit["expected_environment"]) | {"server_version_num"},
            "actual execution environment fields differ from supported schema: " + label)
    for field, expected in profile_audit["expected_environment"].items():
        require(type(observed.get(field)) is type(expected) and observed[field] == expected,
                "actual execution environment mismatch: " + label+":"+field)
    version = observed.get("server_version_num")
    require(type(version) is str and re.fullmatch(r"[1-9][0-9]*", version),
            "invalid actual server_version_num: " + label)
    return dict(observed)


def canonical_bag(value: Any, label: str) -> Counter:
    require(isinstance(value, dict) and isinstance(value.get("canonical_rows"), list), "invalid full bag: " + label)
    rows = value["canonical_rows"]
    require(all(isinstance(row, str) for row in rows), "non-text canonical row: " + label)
    require(integer(value.get("row_count"), label+" row_count") == len(rows), "row count mismatch: " + label)
    encoded = [row.encode("utf-8") for row in sorted(rows)]
    expected = sha(b"".join(f"{len(row):016x}:".encode()+row for row in encoded))
    require(value.get("result_digest") == expected, "canonical bag digest mismatch: " + label)
    return Counter(rows)


def indexed_rows(rows: Any, expected: set[tuple[str, str]], label: str) -> dict[tuple[str, str], dict[str, Any]]:
    require(isinstance(rows, list), "invalid rows: " + label)
    result = {}
    for row in rows:
        require(isinstance(row, dict), "invalid row: " + label)
        key = (row.get("case_id"), row.get("mode"))
        require(key in expected, "unexpected case/mode in " + label + ": " + str(key))
        require(key not in result, "duplicate case/mode in " + label + ": " + str(key))
        result[key] = row
    require(set(result) == expected, "missing case/mode in " + label)
    return result


def csv_matches_json(csv_row: Mapping[str, str], row: Mapping[str, Any], label: str) -> None:
    require(set(csv_row) == set(row), "CSV/JSON column mismatch: " + label)
    for key, expected in row.items():
        actual = csv_row[key]
        if expected is None:
            require(actual == "", "CSV/JSON null mismatch: " + label+":"+key)
        elif isinstance(expected, (int, float)) and not isinstance(expected, bool):
            try:
                parsed = float(actual)
            except ValueError as exc:
                raise AnalysisError("CSV/JSON numeric mismatch: " + label+":"+key) from exc
            close(parsed, expected, label+":"+key)
        else:
            require(actual == str(expected), "CSV/JSON value mismatch: " + label+":"+key)


def percentile(sorted_values: Sequence[float], q: float) -> float:
    position = (len(sorted_values)-1)*q
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    return sorted_values[lower] + (sorted_values[upper]-sorted_values[lower])*(position-lower)


def paired_bootstrap(new: Sequence[float], comparator: Sequence[float], *, draws: int, seed: int) -> dict[str, Any]:
    require(len(new) == len(comparator) and len(new) > 0, "paired vectors must have equal nonzero length")
    integer(draws, "bootstrap draws", minimum=1)
    new = [number(value, "AF sample", positive=True) for value in new]
    comparator = [number(value, "comparator sample", positive=True) for value in comparator]
    rng = random.Random(seed)
    n = len(new)
    ratios = []
    for _ in range(draws):
        # The same sampled round indices are used for both modes.
        indices = [rng.randrange(n) for _ in range(n)]
        ratios.append(statistics.median(comparator[i] for i in indices) /
                      statistics.median(new[i] for i in indices))
    ratios.sort()
    lower, upper = percentile(ratios, .025), percentile(ratios, .975)
    return {
        "ratio": statistics.median(comparator)/statistics.median(new),
        "ci95_lower": lower, "ci95_upper": upper,
        "classification": "W" if lower > 1 else "L" if upper < 1 else "N",
        "draws": draws, "seed": seed, "paired_rounds": n,
        "single_round_warning": n == 1,
    }


def _diagnostic_rows(root: Path, cells: Mapping[str, Any], modes: Sequence[str],
                     execution_rows: Mapping[tuple[str, str], Any],
                     observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for path in sorted((root/"diagnostics").glob("*.json")):
        found = [(case, mode) for case in cells for mode in modes if path.stem == case+"__"+mode]
        require(len(found) == 1, "unknown diagnostic file: " + path.name)
        case, mode = found[0]
        entry = cells[case]["entries"][mode]
        payload = read_json(root, str(path.relative_to(root)))
        spec = entry["spec"]
        require(payload.get("sql") == spec["sql"] and payload.get("sql_sha256") == sha(spec["sql"].encode()),
                "diagnostic SQL mismatch: " + path.name)
        require(payload.get("role") == spec.get("role"), "diagnostic role mismatch: " + path.name)
        audit = cells[case]["execution_audits"].get(mode)
        if audit is not None:
            environment = execution_environment_audit(payload.get("execution_environment"), audit, path.name)
            execution_rows[(case, mode)]["observed_diagnostic_count"] += 1
            observations.append({"case_id": case, "mode": mode, "phase": "diagnostic",
                "iteration": None, "input_path": str(path.relative_to(root)),
                "profile_digest": audit["profile"]["profile_digest"], **environment})
        explain = payload.get("explain")
        require(isinstance(explain, list) and len(explain) == 1 and isinstance(explain[0].get("Plan"), dict),
                "invalid diagnostic plan: " + path.name)
        plan = explain[0]["Plan"]
        common = {"case_id": case, "mode": mode, "diagnostic_path": str(path.relative_to(root)),
                  "role_requested": spec.get("role"), "plan_total_cost": plan.get("Total Cost"),
                  "root_temp_read_blocks": plan.get("Temp Read Blocks", 0),
                  "root_temp_written_blocks": plan.get("Temp Written Blocks", 0)}
        producers = []

        def visit(node: Mapping[str, Any], location: str) -> None:
            subplan = str(node.get("Subplan Name", ""))
            if subplan.startswith("CTE auth"):
                actual_rows = number(node.get("Actual Rows"), "diagnostic actual rows")
                loops = number(node.get("Actual Loops"), "diagnostic actual loops")
                producers.append({**common, "producer_subplan": subplan, "node_path": location,
                    "node_type": node.get("Node Type"), "actual_rows_per_loop": actual_rows,
                    "actual_loops": loops, "actual_rows_times_loops": actual_rows*loops,
                    "producer_temp_read_blocks": node.get("Temp Read Blocks", 0),
                    "producer_temp_written_blocks": node.get("Temp Written Blocks", 0)})
            for index, child in enumerate(node.get("Plans", [])):
                visit(child, location+"/Plans/"+str(index))

        visit(plan, "Plan")
        rows.extend(producers or [{**common, "producer_subplan": None, "node_path": None,
                                  "node_type": None, "actual_rows_per_loop": None,
                                  "actual_loops": None, "actual_rows_times_loops": None,
                                  "producer_temp_read_blocks": None, "producer_temp_written_blocks": None}])
    return rows


def analyze_run(input_dir: Path, *, draws: int = 10000, seed: int = 20261026) -> dict[str, Any]:
    root = input_dir.resolve()
    require(root.is_dir(), "input directory does not exist")
    initial_inventory = inventory(root)
    require("failure.json" not in initial_inventory, "campaign has a failure receipt")
    protocol = read_json(root, "protocol.json")
    require(protocol.get("schema") == "af_pareto_study_v1", "unsupported protocol schema")
    queries = unique_strings(protocol.get("queries"), "queries")
    policies = unique_strings(protocol.get("policies"), "policies")
    modes = unique_strings(protocol.get("modes"), "modes")
    require(all("/" not in value and "\\" not in value and value not in {".", ".."}
                for value in queries+policies), "case labels must be safe file identifiers")
    for field in ("manifest_sha256", "driver_sha256"):
        require(isinstance(protocol.get(field), str) and re.fullmatch(r"sha256:[0-9a-f]{64}", protocol[field]),
                "missing or invalid protocol " + field)
    require("af-new" in modes, "af-new was not declared")
    require(set(modes) <= {"af-new", *COMPARATORS}, "unknown declared study mode")
    required_new_profile = protocol.get("required_new_execution_profile")
    require(required_new_profile is None or required_new_profile == "trusted_explicit",
            "unsupported required new execution profile")
    warmup = integer(protocol.get("warmup"), "warmup")
    measured = integer(protocol.get("measured"), "measured", minimum=1)
    round_orders = validated_round_orders(protocol, modes, warmup, measured)
    require(protocol.get("correctness_only") is False, "correctness-only run has no promotable performance samples")
    cases = [query+"__"+policy for query in queries for policy in policies]
    require(len(cases) == len(set(cases)), "ambiguous case IDs")
    case_labels = {query+"__"+policy: (query, policy) for query in queries for policy in policies}
    expected = {(case, mode) for case in cases for mode in modes}
    terminal = read_json(root, "summary.json")
    require(terminal.get("status") == "completed", "campaign lacks a completed terminal summary")
    require(integer(terminal.get("cells"), "terminal cells") == len(cases) and
            integer(terminal.get("mode_results"), "terminal mode_results") == len(expected),
            "terminal counts differ from protocol")
    try:
        require(datetime.fromisoformat(terminal["finished_at"]) >= datetime.fromisoformat(protocol["started_at"]),
                "terminal timestamp precedes protocol")
    except (KeyError, TypeError, ValueError) as exc:
        raise AnalysisError("missing or invalid terminal timestamp") from exc
    rows = indexed_rows(terminal.get("summary"), expected, "terminal summary")
    require((root/"summary.csv").is_file(), "missing required file: summary.csv")
    with (root/"summary.csv").open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        require(reader.fieldnames and len(reader.fieldnames) == len(set(reader.fieldnames)), "duplicate CSV header fields")
        csv_rows = indexed_rows(list(reader), expected, "summary CSV")
    for key in expected:
        csv_matches_json(csv_rows[key], rows[key], str(key))
    before = read_json(root, "statistics_before_selection.json")
    after = read_json(root, "statistics_after_sampling.json")
    require(isinstance(before, dict) and isinstance(before.get("catalog_statistics"), dict) and
            isinstance(before["catalog_statistics"].get("relations"), list), "missing actual planner statistics")
    require(before == after, "planner statistics changed between selection and sampling")
    require(before.get("digest") == json_digest(before.get("catalog_statistics")), "invalid statistics digest")
    source_ids = {
        "af-old": source_digest(protocol.get("baseline_source"), "baseline"),
        "af-new": source_digest(protocol.get("current_source"), "current"),
    }
    database = read_json(root, "database.json")
    require(isinstance(database.get("pg_env"), dict), "missing database connection declaration")
    artifacts = read_json(root, "shared_artifacts.json")
    require(isinstance(artifacts, dict) and artifacts, "missing shared artifact preparation record")
    for artifact in artifacts.values():
        number(artifact.get("artifact_build_ms"), "shared artifact build")
        integer(artifact.get("artifact_rows"), "shared artifact rows")
        integer(artifact.get("keyed_artifact_rows"), "shared keyed artifact rows")
    validated_cells = {}
    allowed_prepared = set()
    choice_rows = []
    execution_rows = {}
    for case in cases:
        query, policy = case_labels[case]
        shared_path = "prepared/"+case+"/shared.json"
        shared = read_json(root, shared_path)
        allowed_prepared.add(shared_path)
        require((shared.get("case_id"), shared.get("query_id"), shared.get("policy_id")) == (case, query, policy),
                "prepared cell identity mismatch: " + case)
        entries_list = shared.get("modes")
        require(isinstance(entries_list, list) and [entry.get("mode") for entry in entries_list] == modes,
                "prepared mode inventory/order mismatch: " + case)
        entries = {entry["mode"]: entry for entry in entries_list}
        require(all(isinstance(entry.get("spec"), dict) for entry in entries_list),
                "unavailable or missing declared mode spec: " + case)
        workers = {}
        case_execution_audits = {}
        for variant in ("af-old", "af-new"):
            relative = "prepared/"+case+"/"+variant+".json"
            worker = read_json(root, relative)
            allowed_prepared.add(relative)
            require(worker.get("schema") == "af_pareto_worker_v1" and worker.get("status") == "pass",
                    "failed selection worker: " + case+":"+variant)
            require((worker.get("variant"), worker.get("query_id"), worker.get("policy_id")) == (variant, query, policy),
                    "worker identity mismatch: " + case+":"+variant)
            expected_source = protocol["current_source" if variant == "af-new" else "baseline_source"]
            require(worker.get("source_identity") == expected_source,
                    "worker source identity mismatch: " + case+":"+variant)
            require(worker.get("manifest_sha256") == protocol.get("manifest_sha256"),
                    "worker manifest identity mismatch: " + case+":"+variant)
            spec, selection = worker.get("spec"), worker.get("selection")
            require(isinstance(spec, dict) and isinstance(selection, dict), "missing worker spec/selection")
            bound = selection.get("bound_runner")
            require(isinstance(bound, dict), "missing selected bound runner")
            require(spec.get("mode") == variant and isinstance(spec.get("sql"), str) and spec["sql"], "invalid worker SQL")
            require(bound.get("runner_sql") == spec["sql"], "selected bound/executed SQL differs")
            require(selection.get("selected_runner_digest") == bound.get("runner_sql_digest") == json_digest({"exact_runner_sql": spec["sql"]}),
                    "selected SQL digest mismatch")
            require(selection.get("selected_template_id") == bound.get("template_id") == spec.get("template_id"),
                    "selected template identity mismatch")
            require(selection.get("selected_plan_id") == bound.get("plan_id"), "selected plan identity mismatch")
            require((bound.get("query_id"), bound.get("policy_id")) == (query, policy), "bound runner case identity mismatch")
            require(selection.get("measured_runtime_used_for_selection") is False, "selection used measured outcomes")
            case_execution_audits[variant] = execution_profile_audit(
                spec, selection, query=query, policy=policy, pg_env=database["pg_env"],
                required_profile=required_new_profile if variant == "af-new" else None,
                label=case+":"+variant,
            )
            workers[variant] = worker
            if variant in modes:
                require(entries[variant].get("spec") == spec and entries[variant].get("selection") == selection,
                        "prepared AF variant changed after selection")
        require(shared.get("reference") == workers["af-old"].get("reference"), "independent reference source mismatch")
        fixed = workers["af-old"].get("fixed_modes")
        require(isinstance(fixed, list) and [entry.get("mode") for entry in fixed] == list(FIXED_MODES),
                "baseline fixed-mode inventory mismatch")
        fixed = {entry["mode"]: entry for entry in fixed}
        for mode in modes:
            entry, row = entries[mode], rows[(case, mode)]
            spec = entry["spec"]
            expected_source = source_ids["af-new" if mode == "af-new" else "af-old"]
            require(entry.get("source_digest") == row.get("source_digest") == expected_source,
                    "mode source identity mismatch: " + case+":"+mode)
            require(row.get("status") == "pass", "mode summary not passing: " + case+":"+mode)
            require((row.get("query_id"), row.get("policy_id")) == (query, policy), "summary case-label mismatch")
            require(row.get("template_id") == spec.get("template_id") and spec.get("mode") == mode,
                    "mode/template identity mismatch")
            require(spec.get("result_columns") == shared["reference"].get("result_columns") and spec.get("result_columns"),
                    "result column contract mismatch")
            require(all(artifact_id in artifacts for artifact_id in spec.get("artifact_ids", [])),
                    "required artifact missing from preparation record")
            require(row.get("measured_repetitions") == measured, "summary repetition count mismatch")
            if mode in FIXED_MODES:
                require(spec.get("execution_profile") is None and spec.get("session_contract") is None,
                        "normal baseline unexpectedly carries an AF execution profile")
                require(entry.get("spec") == fixed[mode].get("spec"), "normal baseline SQL was modified")
                close(entry.get("generation_wall_ms"), fixed[mode].get("generation_wall_ms"), "baseline generation time")
            if mode.startswith("af-"):
                worker, selection = workers[mode], workers[mode]["selection"]
                for field in ("selection_wall_ms", "catalog_receipt_wall_ms"):
                    close(row.get(field), selection.get(field), case+":"+mode+":"+field)
                close(row.get("worker_request_wall_ms_infrastructure_only"), worker.get("worker_request_wall_ms"), "worker request time")
                close(entry.get("worker_request_wall_ms"), worker.get("worker_request_wall_ms"), "prepared worker time")
            else:
                require(row.get("selection_wall_ms") is None and row.get("catalog_receipt_wall_ms") is None,
                        "AF selection cost charged to ordinary baseline")
            input_ms = shared["stats"]["input_collection_wall_ms"] if mode.startswith("af-") else 0
            close(row.get("input_collection_wall_ms"), input_ms, "input collection cost")
            close(row.get("artifact_build_ms_shared_setup"), shared["stats"]["artifact_build_ms"], "artifact build cost")
            choice_rows.append({**row,
                "execution_role_requested": spec.get("role"),
                "connection_user": database["pg_env"].get("user"),
                "session_contract_digest": (entry.get("selection") or {}).get("bound_runner", {}).get("session_contract_digest"),
            })
            audit = case_execution_audits.get(mode)
            profiled = audit is not None
            execution_rows[(case, mode)] = {
                "case_id": case, "mode": mode,
                "execution_profile": "trusted_explicit" if profiled else None,
                "status": ("profile_bound_pending_observations" if profiled else
                           "legacy_af_role_alignment_not_certified" if mode.startswith("af-") else
                           "normal_baseline_no_af_profile_audit"),
                "session_contract_digest": audit["contract"]["digest"] if profiled else None,
                "profile_digest": audit["profile"]["profile_digest"] if profiled else None,
                "profile_intrinsic_digest_verified": profiled,
                "upstream_context_finite_and_receipt_digests": "source_bound_not_independently_rederived" if profiled else None,
                "finite_catalog_guard_evidence": (
                    "source_bound_successful_profile_execution_path_no_separate_catalog_receipt"
                    if profiled else "not_certified"),
                "observed_warmup_count": 0, "observed_measured_count": 0, "observed_diagnostic_count": 0,
            }
        correctness = read_json(root, "correctness/"+case+".json")
        require(correctness.get("method") == "full_row_jsonb_multiset_equality", "missing full-bag correctness method")
        require(set(correctness.get("modes", {})) == set(modes), "correctness mode denominator mismatch")
        reference_bag = canonical_bag(correctness.get("reference"), case+" reference")
        for mode in modes:
            item = correctness["modes"][mode]
            require(item.get("status") == "pass" and integer(item.get("actual_only_rows"), "actual-only rows") ==
                    integer(item.get("reference_only_rows"), "reference-only rows") == 0,
                    "full-bag check not passed: " + case+":"+mode)
            require(canonical_bag(item.get("actual"), case+":"+mode) == reference_bag,
                    "full-bag contents differ: " + case+":"+mode)
        validated_cells[case] = {"entries": entries, "shared": shared, "samples": {mode: {} for mode in modes},
                                 "execution_audits": case_execution_audits}
    require({str(path.relative_to(root)) for path in (root/"prepared").rglob("*.json")} == allowed_prepared,
            "unexpected prepared case/variant files")
    require({str(path.relative_to(root)) for path in (root/"correctness").rglob("*.json")} ==
            {"correctness/"+case+".json" for case in cases},
            "correctness case denominator mismatch")
    expected_samples = set()
    measured_count = warmup_count = 0
    execution_observations = []
    for case in cases:
        for mode_index, mode in enumerate(modes):
            entry = validated_cells[case]["entries"][mode]
            for phase, count in (("warmup", warmup), ("measured", measured)):
                for iteration in range(1, count+1):
                    relative = f"samples/{case}__{mode}__{phase}{iteration:02d}.json"
                    expected_samples.add(relative)
                    sample = read_json(root, relative)
                    require((sample.get("case_id"), sample.get("mode"), sample.get("phase"), sample.get("iteration")) ==
                            (case, mode, phase, iteration), "sample framing mismatch: " + relative)
                    round_index = iteration-1 + (warmup if phase == "measured" else 0)
                    require(sample.get("round_index") == round_index, "paired-round identity mismatch: " + relative)
                    if round_orders is None:
                        require(sample.get("order_index") == (mode_index-round_index) % len(modes),
                                "declared rotation order mismatch: " + relative)
                    else:
                        order = round_orders[round_index % 6]
                        position = order.index(mode_index)
                        require(sample.get("order_index") == position,
                                "declared balanced order mismatch: " + relative)
                        previous = (modes[order[position-1]] if position else
                                    modes[round_orders[(round_index-1) % 6][-1]] if round_index else None)
                        require(sample.get("preceding_mode") == previous,
                                "actual predecessor record mismatch: " + relative)
                    require(sample.get("sql_sha256") == sha(entry["spec"]["sql"].encode()), "sample SQL changed: " + relative)
                    require(sample.get("source_identity") == entry["source_digest"], "sample source identity changed: " + relative)
                    require(sample.get("selection") == entry.get("selection"), "sample selection identity changed: " + relative)
                    values = sample.get("measurement")
                    require(isinstance(values, dict), "missing sample measurement")
                    for field in MEASURE_FIELDS.values():
                        number(values.get(field), field, positive=field == "database_total_ms")
                    audit = validated_cells[case]["execution_audits"].get(mode)
                    if audit is not None:
                        environment = execution_environment_audit(values.get("execution_environment"), audit, relative)
                        execution_rows[(case, mode)]["observed_"+phase+"_count"] += 1
                        execution_observations.append({"case_id": case, "mode": mode, "phase": phase,
                            "iteration": iteration, "input_path": relative,
                            "profile_digest": audit["profile"]["profile_digest"], **environment})
                    if phase == "measured":
                        measured_count += 1
                        validated_cells[case]["samples"][mode][round_index] = values
                    else:
                        warmup_count += 1
            values = list(validated_cells[case]["samples"][mode].values())
            row = rows[(case, mode)]
            for summary_field, sample_field in MEASURE_FIELDS.items():
                close(row.get(summary_field), statistics.median(value[sample_field] for value in values),
                      case+":"+mode+":"+summary_field)
            selection = entry.get("selection") or {}
            first_use = row[PRIMARY] + row["input_collection_wall_ms"] + selection.get("selection_wall_ms", 0) + selection.get("catalog_receipt_wall_ms", 0) + entry.get("generation_wall_ms", 0)
            close(row.get("first_use_estimate_ms_excluding_artifact_build"), first_use, "first-use estimate")
            if mode.startswith("af-") or entry["spec"].get("artifact_ids"):
                first_use += row["artifact_build_ms_shared_setup"]
            close(row.get("first_use_estimate_with_artifact_build_ms"), first_use, "first-use estimate with build")
    require({str(path.relative_to(root)) for path in (root/"samples").rglob("*.json")} == expected_samples,
            "unexpected or duplicate sample files")
    comparisons = []
    declared_comparators = [mode for mode in COMPARATORS if mode in modes]
    for case in cases:
        samples = validated_cells[case]["samples"]
        ordered_rounds = sorted(samples["af-new"])
        for comparator in declared_comparators:
            require(sorted(samples[comparator]) == ordered_rounds, "comparator paired rounds do not align")
            pair_seed = int.from_bytes(hashlib.sha256(f"{seed}:{case}:{comparator}".encode()).digest()[:8], "big")
            interval = paired_bootstrap(
                [samples["af-new"][index]["database_total_ms"] for index in ordered_rounds],
                [samples[comparator][index]["database_total_ms"] for index in ordered_rounds],
                draws=draws, seed=pair_seed)
            comparisons.append({"case_id": case, "query_id": case_labels[case][0],
                "policy_id": case_labels[case][1], "comparator": comparator,
                "af_new_median_ms": rows[(case, "af-new")][PRIMARY],
                "comparator_median_ms": rows[(case, comparator)][PRIMARY],
                **interval})
    aggregates = {}
    for comparator in declared_comparators:
        group = [item for item in comparisons if item["comparator"] == comparator]
        ratios = [item["ratio"] for item in group]
        aggregates[comparator] = {
            "cases": len(group), "geometric_mean_ratio": math.exp(statistics.mean(math.log(value) for value in ratios)),
            "median_ratio": statistics.median(ratios),
            "wins": sum(item["classification"] == "W" for item in group),
            "within_interval": sum(item["classification"] == "N" for item in group),
            "losses": sum(item["classification"] == "L" for item in group),
            "all_losses": [item for item in group if item["classification"] == "L"],
        }
        aggregates[comparator]["W_N_L"] = [aggregates[comparator][field] for field in ("wins", "within_interval", "losses")]
    diagnostics = _diagnostic_rows(root, validated_cells, modes, execution_rows, execution_observations)
    for execution_row in execution_rows.values():
        if execution_row["execution_profile"] is not None:
            execution_row["status"] = "bound_profile_and_all_retained_session_observations_match"
    require(inventory(root) == initial_inventory, "input files changed during analysis")
    return {
        "schema": SCHEMA, "analysis_ready": True, "input_dir": str(root),
        "terminal_receipt": "summary.json:status=completed", "statistics_digest": before["digest"],
        "metric": PRIMARY, "ratio_direction": "comparator_median_over_af_new_median",
        "classification": "W if paired bootstrap95 lower >1; L if upper <1; N otherwise",
        "bootstrap": {"draws": draws, "base_seed": seed,
                      "estimator": "ratio of medians; resample identical round indices in both modes",
                      "interval": "percentile 95%, linear interpolation"},
        "protocol_scope": {key: value for key, value in protocol.items()
                           if key not in {"current_source", "baseline_source"}},
        "readiness_scope": "complete declared retained measurements/provenance; supported execution profiles are checked against retained actual session observations, not general semantic environment equivalence or innovation",
        "measurement_schedule_audit": {"schedule": protocol.get("schedule", "casewise_deterministic_rotating_rounds"),
            "balanced_orders": round_orders,
            "scope": "declared positions and immediate predecessors; no guarantee of all higher-order cache effects"},
        "execution_identity_audit_scope": {
            "profile_schema_supported": TRUSTED_PROFILE_SCHEMA,
            "legacy_records": "accepted without retroactively certifying role alignment",
            "verified": "bound/spec/selection metadata, intrinsic profile and serialized SessionContract digests, all retained warmup/measured and available diagnostic session observations",
            "finite_catalog_guard": "source-bound successful profile execution path; raw records do not contain a separate execution-time table/catalog observation receipt",
            "upstream_digests": "context, finite-fragment, and receipt digests remain upstream issuer/source-bound; missing preimages are not guessed from current implementation",
            "not_certified": ["origin issuance capability", "general AuthorizedExecution",
                              "complete concurrent policy execution TOCTOU", "upstream finite-fragment theorem replay"],
        },
        "choice_first_use_scope": "selection/catalog/input costs are separate original observations; first_use fields are estimates, not directly measured complete first requests",
        "diagnostics_scope": "separate post-primary observations; producer rows/loops and temp blocks are not primary samples or additive across plan nodes",
        "counts": {"declared_cases": len(cases), "declared_modes": len(modes), "case_modes": len(expected),
                   "summary_rows": len(rows), "measured_samples": measured_count, "warmup_samples": warmup_count,
                   "prepared_variant_files": len(cases)*2, "correctness_files": len(cases),
                   "diagnostic_files": len(list((root/"diagnostics").glob("*.json"))),
                   "input_files": len(initial_inventory), "input_bytes": sum(item["bytes"] for item in initial_inventory.values())},
        "not_declared_comparators": [mode for mode in COMPARATORS if mode not in modes],
        "comparisons": comparisons, "aggregates": aggregates,
        "all_losses": [item for item in comparisons if item["classification"] == "L"],
        "choice_and_first_use": choice_rows, "diagnostics": diagnostics,
        "execution_identity_audit": list(execution_rows.values()),
        "execution_environment_observations": execution_observations,
        "missing_optional_diagnostics": [case+":"+mode for case in cases for mode in modes
            if not (root/"diagnostics"/(case+"__"+mode+".json")).exists()],
        "input_files": initial_inventory,
        "analyzer_sha256": sha(Path(__file__).read_bytes()),
    }


def write_outputs(report: Mapping[str, Any], output_dir: Path, input_dir: Path) -> None:
    output = output_dir.resolve()
    try:
        output.relative_to(input_dir.resolve())
    except ValueError:
        pass
    else:
        raise AnalysisError("analysis output must be outside the original run directory")
    output.mkdir(parents=True, exist_ok=False)
    with (output/"analysis.json").open("x", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    for filename, rows in (("comparisons.csv", report["comparisons"]),
                           ("choice-and-first-use.csv", report["choice_and_first_use"]),
                           ("diagnostics.csv", report["diagnostics"]),
                           ("execution-identity-audit.csv", report["execution_identity_audit"]),
                           ("execution-environment-observations.csv", report["execution_environment_observations"]),
                           ("all-losses.csv", report["all_losses"])):
        fields = list(rows[0]) if rows else ["case_id", "mode"]
        with (output/filename).open("x", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--bootstrap-draws", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=20261026)
    args = parser.parse_args(argv)
    try:
        report = analyze_run(Path(args.input_dir), draws=args.bootstrap_draws, seed=args.seed)
        write_outputs(report, Path(args.output_dir), Path(args.input_dir))
    except (AnalysisError, OSError, ValueError, KeyError, TypeError) as exc:
        print("analysis rejected: " + str(exc), file=__import__("sys").stderr)
        return 1
    print(json.dumps({"analysis_ready": True, "counts": report["counts"], "aggregates": report["aggregates"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
