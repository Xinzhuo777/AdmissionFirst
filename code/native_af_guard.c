/*
 * A necessary built-in LIKE prefix, followed by the unchanged exact RLS.
 *
 * The raw child reads visible heap candidates using only catalog-leakproof
 * bounds. Its actual full tuple (including every policy input and CTID)
 * crosses one edge with the exact policy pending. ExecScan applies that
 * policy BEFORE the original user predicates and final projection.
 *
 * Scope is deliberately finite: one top-level heap occurrence, one rewritten
 * RLS expression, plain text Var / non-NULL Const LIKE, explicit C collation,
 * built-in text_pattern_ops B-tree, no joins/CTEs/rowmarks/parallel/EPQ.
 *
 * The same residual-placement generator also constructs the late-policy
 * order. Production admission rejects it BEFORE costing. An isolated build
 * compiled with NATIVE_AF_GUARD_DIAGNOSTIC_UNSAFE can cost and publish that
 * same rejected structure for synthetic counterfactual execution. There is
 * deliberately no runtime setting that bypasses admission.
 */
#include "postgres.h"

#include <math.h>

#include "access/genam.h"
#include "access/htup_details.h"
#include "access/nbtree.h"
#include "access/parallel.h"
#include "access/stratnum.h"
#include "access/sysattr.h"
#include "access/table.h"
#include "catalog/index.h"
#include "catalog/pg_am.h"
#include "catalog/pg_am_d.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_collation_d.h"
#include "catalog/pg_inherits.h"
#include "catalog/pg_namespace_d.h"
#include "catalog/pg_opclass_d.h"
#include "catalog/pg_opfamily_d.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_type_d.h"
#include "commands/explain.h"
#include "executor/executor.h"
#include "executor/nodeSubplan.h"
#include "miscadmin.h"
#include "nodes/extensible.h"
#include "nodes/makefuncs.h"
#include "nodes/nodeFuncs.h"
#include "nodes/supportnodes.h"
#include "optimizer/cost.h"
#include "optimizer/clauses.h"
#include "optimizer/native_af.h"
#include "optimizer/native_af_admission.h"
#include "optimizer/native_af_binding.h"
#include "optimizer/native_af_guard.h"
#include "optimizer/optimizer.h"
#include "optimizer/pathnode.h"
#include "optimizer/paths.h"
#include "optimizer/planner.h"
#include "optimizer/restrictinfo.h"
#include "optimizer/tlist.h"
#include "parser/parsetree.h"
#include "parser/parse_relation.h"
#include "utils/fmgroids.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/plancache.h"
#include "utils/snapshot.h"
#include "utils/syscache.h"
#include "utils/timestamp.h"

typedef struct GuardDescriptor
{
	RestrictInfo *original_policy;
	RestrictInfo *policy;
	RestrictInfo *like;
	Var        *title;
	List       *users;
	List       *bounds;
	IndexOptInfo *index;
	bool        late_policy;
	const char *rejection;
	List       *policy_binding;
	RestrictInfo *closed_proof;
	RestrictInfo *hash_proof;
} GuardDescriptor;

typedef struct GuardState
{
	CustomScanState css;
	PlanState  *child;
	bool        first_fetch;
	bool        counted;
	Snapshot    snapshot;
} GuardState;

/* Per-backend, passive diagnostics. No timing/counter value controls a path. */
static uint64 guard_generated;
static uint64 guard_admitted;
static uint64 guard_rejected;
static uint64 guard_pruned;
static uint64 guard_retained;
static uint64 guard_published;
static uint64 guard_executed;
static uint64 guard_unsafe_executed;
static int64 guard_admission_us;
static char *guard_counts_setting;
static bool guard_repeated_policy_estimation = true;

static Plan *guard_plan(PlannerInfo *, RelOptInfo *, CustomPath *, List *, List *, List *);
static Node *guard_create(CustomScan *);
static void guard_begin(CustomScanState *, EState *, int);
static TupleTableSlot *guard_exec(CustomScanState *);
static void guard_end(CustomScanState *);
static void guard_rescan(CustomScanState *);
static void guard_explain(CustomScanState *, List *, ExplainState *);

static const CustomPathMethods guard_path_methods = {
	.CustomName = "AF Prefix Guard", .PlanCustomPath = guard_plan,
};
static const CustomScanMethods guard_scan_methods = {
	.CustomName = "AF Prefix Guard", .CreateCustomScanState = guard_create,
};
static const CustomExecMethods guard_exec_methods = {
	.CustomName = "AF Prefix Guard", .BeginCustomScan = guard_begin,
	.ExecCustomScan = guard_exec, .EndCustomScan = guard_end,
	.ReScanCustomScan = guard_rescan, .ExplainCustomScan = guard_explain,
};

static const char *
guard_show_counts(void)
{
	return psprintf("{\"generated\":" UINT64_FORMAT ",\"admitted\":" UINT64_FORMAT
		",\"rejected\":" UINT64_FORMAT ",\"pruned\":" UINT64_FORMAT
		",\"retained\":" UINT64_FORMAT ",\"published\":" UINT64_FORMAT
		",\"actual_executions\":" UINT64_FORMAT ",\"unsafe_diagnostic_executions\":" UINT64_FORMAT
		",\"admission_us\":" INT64_FORMAT "}", guard_generated, guard_admitted,
		guard_rejected, guard_pruned, guard_retained, guard_published,
		guard_executed, guard_unsafe_executed, guard_admission_us);
}

static void
guard_assign_repeated_policy(bool value, void *extra)
{
    if (guard_repeated_policy_estimation != value)
        ResetPlanCache();
}

void
native_af_guard_initialize(void)
{
    DefineCustomBoolVariable("native_af.repeated_policy_cost",
        "Use PostgreSQL repeat-index IO costing for bound correlated exact checks.",
        NULL, &guard_repeated_policy_estimation, true, PGC_USERSET, 0,
        NULL, guard_assign_repeated_policy, NULL);
	DefineCustomStringVariable("native_af.guard_counts",
		"Prefix descriptor admission and actual execution counts in this backend.",
		NULL, &guard_counts_setting, "", PGC_INTERNAL,
		GUC_NOT_IN_SAMPLE | GUC_DISALLOW_IN_FILE, NULL, NULL, guard_show_counts);
	RegisterCustomScanMethods(&guard_scan_methods);
}

static Const *
guard_oid(Oid oid)
{
	return makeConst(OIDOID, -1, InvalidOid, sizeof(Oid),
					 ObjectIdGetDatum(oid), false, true);
}

static Float *
guard_number(double number)
{
	return makeFloat(psprintf("%.17g", number));
}

static bool
plain_var(Var *var, Index rti)
{
	return var->varno == rti && var->varlevelsup == 0 && var->varattno > 0 &&
		bms_is_empty(var->varnullingrels);
}

/* COLLATE is metadata, not a value-producing cast or a user function. PG's
 * preprocessor normalizes it to RelabelType; preserve the actual expression
 * in the final post-policy target, and only inspect its unchanged origin. */
static Var *
guard_output_var(Node *node, Index rti)
{
	Node *value = node;
	if (IsA(value, CollateExpr))
	{
		CollateExpr *collate = castNode(CollateExpr, value);
		if (collate->collOid != C_COLLATION_OID)
			return NULL;
		value = (Node *) collate->arg;
	}
	else if (IsA(value, RelabelType))
	{
		RelabelType *relabel = castNode(RelabelType, value);
		if (!IsA(relabel->arg, Var) || relabel->resultcollid != C_COLLATION_OID ||
			relabel->resulttype != castNode(Var, relabel->arg)->vartype ||
			relabel->resulttypmod != castNode(Var, relabel->arg)->vartypmod ||
			relabel->relabelformat != COERCE_IMPLICIT_CAST)
			return NULL;
		value = (Node *) relabel->arg;
	}
	if (!IsA(value, Var) || !plain_var(castNode(Var, value), rti) ||
		(value != node && castNode(Var, value)->vartype != TEXTOID))
		return NULL;
	return castNode(Var, value);
}

/* A query-derived support function receives syntax/Const data, not rows. */
static bool
guard_function(Oid function)
{
	return get_func_namespace(function) == PG_CATALOG_NAMESPACE &&
		get_func_leakproof(function) && func_volatile(function) == PROVOLATILE_IMMUTABLE;
}

static bool
guard_am(void)
{
	HeapTuple tuple = SearchSysCache1(AMOID, ObjectIdGetDatum(BTREE_AM_OID));
	bool valid = HeapTupleIsValid(tuple) &&
		((Form_pg_am) GETSTRUCT(tuple))->amhandler == F_BTHANDLER;

	if (HeapTupleIsValid(tuple))
		ReleaseSysCache(tuple);
	return valid;
}

static bool
guard_heap(Oid oid)
{
	HeapTuple tuple = SearchSysCache1(RELOID, ObjectIdGetDatum(oid));
	bool valid = HeapTupleIsValid(tuple) &&
		((Form_pg_class) GETSTRUCT(tuple))->relam == HEAP_TABLE_AM_OID;
	if (HeapTupleIsValid(tuple))
		ReleaseSysCache(tuple);
	return valid;
}

static bool
guard_index(IndexOptInfo *index, RelOptInfo *rel, Var *title)
{
	return index->rel == rel && index->relam == BTREE_AM_OID && guard_am() &&
		index->amhasgettuple && index->nkeycolumns == 1 &&
		index->indexkeys[0] == title->varattno && index->indexprs == NIL &&
		index->indpred == NIL && index->opfamily[0] == TEXT_PATTERN_BTREE_FAM_OID &&
		get_index_column_opclass(index->indexoid, 1) == TEXT_BTREE_PATTERN_OPS_OID &&
		index->opcintype[0] == TEXTOID && index->indexcollations[0] == C_COLLATION_OID &&
		get_opfamily_proc(TEXT_PATTERN_BTREE_FAM_OID, TEXTOID, TEXTOID,
						 BTORDER_PROC) == F_BTTEXT_PATTERN_CMP &&
		guard_function(F_BTTEXT_PATTERN_CMP);
}

/* First prototype has full ordinary fields and CTID, no whole-row/system recovery. */
/* Validate actual support output, not just the original LIKE's spelling. */
static bool
guard_bounds(List *bounds, Var *title)
{
	ListCell *cell;

	if (bounds == NIL || list_length(bounds) > 2)
		return false;
	foreach(cell, bounds)
	{
		OpExpr *op;
		Oid function;
		int strategy;
		if (!IsA(lfirst(cell), OpExpr))
			return false;
		op = lfirst_node(OpExpr, cell);
		function = get_opcode(op->opno);
		if (function == F_TEXT_PATTERN_GE)
			strategy = BTGreaterEqualStrategyNumber;
		else if (function == F_TEXT_PATTERN_LT)
			strategy = BTLessStrategyNumber;
		else if (function == F_TEXTEQ)
			strategy = BTEqualStrategyNumber;
		else
			return false;
		if (op->opretset || op->opresulttype != BOOLOID ||
			op->inputcollid != C_COLLATION_OID || list_length(op->args) != 2 ||
			!equal(linitial(op->args), title) || !IsA(lsecond(op->args), Const) ||
			lsecond_node(Const, op->args)->consttype != TEXTOID ||
			lsecond_node(Const, op->args)->constisnull || !guard_function(function) ||
			get_opfamily_member(TEXT_PATTERN_BTREE_FAM_OID, TEXTOID, TEXTOID,
							strategy) != op->opno)
			return false;
	}
	return true;
}

static bool
guard_scope(PlannerInfo *root, RelOptInfo *rel, RangeTblEntry *rte)
{
	Query *query = root->parse;
	RTEPermissionInfo *permission;
	ListCell *cell;

	if (root->parent_root != NULL || !native_af_readonly_statement(root) ||
		query->hasTargetSRFs || query->cteList != NIL || query->setOperations ||
		query->hasAggs || query->hasWindowFuncs || query->groupClause != NIL ||
		query->distinctClause != NIL || query->havingQual ||
		query->jointree == NULL || list_length(query->jointree->fromlist) != 1 ||
		!IsA(linitial(query->jointree->fromlist), RangeTblRef) ||
		linitial_node(RangeTblRef, query->jointree->fromlist)->rtindex != rel->relid ||
		IsParallelWorker() || rel->reloptkind != RELOPT_BASEREL ||
		rel->lateral_relids != NULL || rte->rtekind != RTE_RELATION ||
		rte->relkind != RELKIND_RELATION || rte->tablesample ||
		(rte->inh && has_subclass(rte->relid)) || rte->perminfoindex == 0 ||
		planner_rt_fetch(rel->relid, root) != rte ||
		list_length(rte->securityQuals) != 1 ||
		list_length(linitial(rte->securityQuals)) != 1)
		return false;
	permission = getRTEPermissionInfo(query->rteperminfos, rte);
	if (permission->relid != rte->relid || OidIsValid(permission->checkAsUser) ||
		(permission->requiredPerms & ACL_SELECT) == 0 ||
		!guard_heap(rte->relid))
		return false;
	/* A full raw tuple is not an excuse to run target expressions early. */
	foreach(cell, query->targetList)
	{
		TargetEntry *entry = lfirst_node(TargetEntry, cell);
		if (guard_output_var((Node *) entry->expr, rel->relid) == NULL)
			return false;
	}
	return true;
}

static bool
guard_find(PlannerInfo *root, RelOptInfo *rel, RangeTblEntry *rte,
			GuardDescriptor *descriptor)
{
	ListCell *cell;
	Node *policy = linitial(linitial(rte->securityQuals));

	foreach(cell, rel->baserestrictinfo)
	{
		RestrictInfo *rinfo = lfirst_node(RestrictInfo, cell);
		OpExpr *op;
		if (rinfo->security_level == 0 && equal(rinfo->clause, policy))
		{
			if (descriptor->policy != NULL)
				return false;
			descriptor->policy = rinfo;
			continue;
		}
		if (rinfo->pseudoconstant || rinfo->security_level == 0)
			return false;
		descriptor->users = lappend(descriptor->users, rinfo);
		if (!IsA(rinfo->clause, OpExpr))
			continue;
		op = castNode(OpExpr, rinfo->clause);
		if (get_opcode(op->opno) != F_TEXTLIKE || op->inputcollid != C_COLLATION_OID ||
			op->opretset || list_length(op->args) != 2 ||
			!IsA(linitial(op->args), Var) || !IsA(lsecond(op->args), Const))
			continue;
		if (descriptor->like != NULL)
			return false;
		descriptor->title = linitial_node(Var, op->args);
		if (!plain_var(descriptor->title, rel->relid) ||
			descriptor->title->vartype != TEXTOID ||
			descriptor->title->varcollid != C_COLLATION_OID ||
			lsecond_node(Const, op->args)->constisnull ||
			lsecond_node(Const, op->args)->consttype != TEXTOID)
			return false;
		descriptor->like = rinfo;
		{
			char *pattern = TextDatumGetCString(lsecond_node(Const, op->args)->constvalue);
			int length = strlen(pattern);
			int escapes = 0;
			while (length > escapes && pattern[length - escapes - 1] == '\\')
				escapes++;
			pfree(pattern);
			/* Preserve ordinary error behavior for an incomplete escape. */
			if (escapes % 2 != 0)
				return false;
		}
	}
	descriptor->original_policy = descriptor->policy;
	return descriptor->policy != NULL && descriptor->like != NULL &&
		!contain_volatile_functions((Node *) descriptor->policy->clause) &&
		get_func_support(F_TEXTLIKE) == F_TEXTLIKE_SUPPORT;
}

/* Admission runs before any path constructor or candidate cost evaluation. */
static bool
guard_admit(PlannerInfo *root, RelOptInfo *rel, RangeTblEntry *rte,
			const NativeAfScanRequirement *need, PathTarget *input,
			GuardDescriptor *descriptor)
{
	TimestampTz start = GetCurrentTimestamp();
	bool valid;

	guard_generated++;
	valid = guard_scope(root, rel, rte) && descriptor->policy && descriptor->original_policy && descriptor->like &&
		native_af_serial_policy(root, (Node *) descriptor->policy->clause) &&
		equal(descriptor->original_policy->clause, linitial(linitial(rte->securityQuals))) &&
		guard_index(descriptor->index, rel, descriptor->title) &&
		guard_bounds(descriptor->bounds, descriptor->title);
	if (!valid)
		descriptor->rejection = "source_or_guard_binding";
	else if (!equal(descriptor->policy->clause, descriptor->original_policy->clause) &&
		(descriptor->closed_proof == NULL || descriptor->hash_proof == NULL ||
		 !equal(descriptor->closed_proof->clause, descriptor->original_policy->clause) ||
		 !IsA(descriptor->original_policy->clause, AlternativeSubPlan) ||
		 !IsA(descriptor->policy->clause, AlternativeSubPlan) ||
		 list_length(castNode(AlternativeSubPlan, descriptor->policy->clause)->subplans) != 1 ||
		 !list_member(castNode(AlternativeSubPlan, descriptor->original_policy->clause)->subplans,
			linitial(castNode(AlternativeSubPlan, descriptor->policy->clause)->subplans))))
	{
		valid = false;
		descriptor->rejection = "unproved_original_pg_policy_arm";
	}
	else
	{
		NativeAfScanDelivery delivery;
		NativeAfScanRule rule = {
			.input = input,
			.output = rel->reltarget,
			.target_filter = (Node *) descriptor->like->clause,
			.before_check = descriptor->late_policy ?
				lappend(list_copy(descriptor->bounds), descriptor->like->clause) : descriptor->bounds,
			.after_check = get_actual_clauses(descriptor->users),
			.exact_check = (Node *) descriptor->policy->clause,
			.validated_prefix = descriptor->bounds,
			.identity = SelfItemPointerAttributeNumber
		};

		descriptor->rejection = native_af_admit_checked_scan(need, &rule, &delivery);
		valid = descriptor->rejection == NULL;
	}
	if (valid)
		guard_admitted++;
	else
		guard_rejected++;
	guard_admission_us += GetCurrentTimestamp() - start;
	return valid;
}

/* Only expose the already validated PG alternatives. This creates syntax and
 * bindings, never chooses/costs a candidate before admission. A one-arm AS
 * makes the actually executed policy match the corresponding staged cost. */
static List *
guard_policy_variants(PlannerInfo *root, GuardDescriptor *base,
					  RestrictInfo *closed, RestrictInfo *completed)
{
	List *variants = NIL;
	AlternativeSubPlan *original;
	AlternativeSubPlan *hash_expression;
	SubPlan *hash;
	Var *key = NULL;
	ListCell *cell;
	if (closed == NULL || completed == NULL ||
		!equal(closed->clause, base->original_policy->clause) ||
		!IsA(base->original_policy->clause, AlternativeSubPlan) ||
		!IsA(completed->clause, AlternativeSubPlan))
		return list_make1(base);
	original = castNode(AlternativeSubPlan, base->original_policy->clause);
	hash_expression = castNode(AlternativeSubPlan, completed->clause);
	if (list_length(hash_expression->subplans) != 1 ||
		!IsA(linitial(hash_expression->subplans), SubPlan))
		return list_make1(base);
	hash = linitial_node(SubPlan, hash_expression->subplans);
	if (!hash->useHashTable || !list_member(original->subplans, hash) ||
		!IsA(hash->testexpr, OpExpr))
		return list_make1(base);
	foreach(cell, castNode(OpExpr, hash->testexpr)->args)
		if (IsA(lfirst(cell), Var))
			key = lfirst_node(Var, cell);
	if (key == NULL || key->vartype != INT8OID)
		return list_make1(base);
	foreach(cell, original->subplans)
	{
		SubPlan *arm = lfirst_node(SubPlan, cell);
		GuardDescriptor *variant;
		AlternativeSubPlan *one;
		PlannerInfo *source_root;
		List *relations = NIL;
		ListCell *relation_cell;
		if (arm->plan_id <= 0 || arm->plan_id > list_length(root->glob->subroots))
			continue;
		if (!native_af_serial_policy(root, (Node *) arm))
			continue;
		if (arm->useHashTable)
		{
			if (!equal(arm, hash))
				continue;
		}
		else if (arm != linitial(original->subplans) || arm->subLinkType != EXISTS_SUBLINK ||
			arm->testexpr != NULL || arm->setParam != NIL || list_length(arm->parParam) != 1 ||
			list_length(arm->args) != 1 || !equal(linitial(arm->args), key))
			continue;
		source_root = list_nth(root->glob->subroots, arm->plan_id - 1);
		foreach(relation_cell, source_root->parse->rtable)
		{
			RangeTblEntry *source = lfirst_node(RangeTblEntry, relation_cell);
			if (source->rtekind == RTE_RELATION)
				relations = list_append_unique_oid(relations, source->relid);
		}
		if (relations == NIL)
			continue;
		variant = palloc(sizeof(*variant));
		*variant = *base;
		one = makeNode(AlternativeSubPlan);
		one->subplans = list_make1(copyObject(arm));
		variant->policy = make_restrictinfo(root, (Expr *) one, closed->is_pushed_down,
			closed->has_clone, closed->is_clone, closed->pseudoconstant, closed->security_level,
			closed->required_relids, closed->incompatible_relids, closed->outer_relids);
		variant->closed_proof = closed;
		variant->hash_proof = completed;
		variant->policy_binding = list_make4(makeString(arm->useHashTable ?
			"native_pg_hash_arm" : "native_pg_correlated_arm"), makeInteger(arm->plan_id),
			makeInteger(key->varattno), relations);
		variants = lappend(variants, variant);
	}
	return variants != NIL ? variants : list_make1(base);
}

/* All ordinary fields and an actual CTID carrier, never a user expression. */
static PathTarget *
guard_target(RelOptInfo *rel, Oid heap)
{
	PathTarget *target = create_empty_pathtarget();
	Relation relation = table_open(heap, AccessShareLock);
	AttrNumber attribute;
	for (attribute = 1; attribute <= RelationGetDescr(relation)->natts; attribute++)
	{
		HeapTuple tuple = SearchSysCache2(ATTNUM, ObjectIdGetDatum(heap),
									  Int16GetDatum(attribute));
		Form_pg_attribute column;
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "AF prefix missing heap attribute");
		column = (Form_pg_attribute) GETSTRUCT(tuple);
		if (!column->attisdropped)
			add_column_to_pathtarget(target,
				(Expr *) makeVar(rel->relid, attribute, column->atttypid,
					column->atttypmod, column->attcollation, 0), 0);
		ReleaseSysCache(tuple);
	}
	add_column_to_pathtarget(target,
		(Expr *) makeVar(rel->relid, SelfItemPointerAttributeNumber,
						TIDOID, -1, InvalidOid, 0), 0);
	table_close(relation, AccessShareLock);
	return target;
}

static List *
guard_restrictions(PlannerInfo *root, List *bounds)
{
	List *result = NIL;
	ListCell *cell;
	foreach(cell, bounds)
		result = lappend(result, make_simple_restrictinfo(root, lfirst(cell)));
	return result;
}

static RelOptInfo *
guard_relation(PlannerInfo *root, RelOptInfo *rel, PathTarget *target, List *bounds)
{
	RelOptInfo *raw = palloc(sizeof(*raw));
	memcpy(raw, rel, sizeof(*raw));
	raw->reltarget = target;
	set_pathtarget_cost_width(root, raw->reltarget);
	raw->baserestrictinfo = guard_restrictions(root, bounds);
	raw->baserestrict_min_security = 0;
	raw->pathlist = NIL;
	raw->partial_pathlist = NIL;
	raw->joininfo = NIL;
	raw->consider_parallel = false;
	raw->rows = clamp_row_est(rel->tuples *
		clauselist_selectivity(root, raw->baserestrictinfo, rel->relid, JOIN_INNER, NULL));
	cost_qual_eval(&raw->baserestrictcost, raw->baserestrictinfo, root);
	return raw;
}

static Path *
guard_child(PlannerInfo *root, RelOptInfo *raw, GuardDescriptor *descriptor,
			bool indexed)
{
	IndexOptInfo *index;
	IndexClause *clause;
	if (!indexed)
		return create_seqscan_path(root, raw, NULL, 0);
	index = palloc(sizeof(*index));
	memcpy(index, descriptor->index, sizeof(*index));
	index->rel = raw;
	index->indrestrictinfo = raw->baserestrictinfo;
	clause = makeNode(IndexClause);
	clause->rinfo = linitial_node(RestrictInfo, raw->baserestrictinfo);
	clause->indexquals = raw->baserestrictinfo;
	clause->indexcol = 0;
	/* Conditions themselves are exact bounds; original LIKE stays above. */
	clause->lossy = false;
	return (Path *) create_index_path(root, index, list_make1(clause), NIL, NIL,
		build_index_pathkeys(root, index, ForwardScanDirection),
		ForwardScanDirection, false, NULL, 1.0, false);
}

/*
 * Reprice repeated correlated index-only probes with PostgreSQL's own
 * loop_count cache model.  This is cost-only: no source Path, Plan, SubPlan,
 * policy expression or execution binding is changed.
 *
 * Deliberately bounded support: an optional projection, an INNER nested loop,
 * and built-in B-tree index-only leaves with all-visible heap statistics.
 * Binding is checked against the actual chosen SubPlan Plan and PG's exact
 * fractional-path selector. Other shapes retain the original policy cost.
 */
static bool
guard_same_cost(double left, double right)
{
    return isfinite(left) && isfinite(right) &&
        fabs(left - right) <= 1e-9 * Max(1.0, Max(fabs(left), fabs(right)));
}

static bool
guard_repeated_indexes(PlannerInfo *source_root, Path *path, Plan *plan,
                       double repetitions, double inner_loops,
                       double per_policy_loops, int joins,
                       Path **revised, List **indices, const char **reason)
{
    if (path == NULL || plan == NULL || repetitions <= 1.0 ||
        !isfinite(inner_loops) || !isfinite(per_policy_loops) ||
        inner_loops <= 0 || per_policy_loops <= 0)
    {
        *reason = "invalid_bound_source";
        return false;
    }
    if (IsA(path, ProjectionPath))
    {
        ProjectionPath *projection = castNode(ProjectionPath, path);
        Path *child;
        ProjectionPath *copy;
        if (IsA(plan, Result))
        {
            Result *result = castNode(Result, plan);
            if (result->resconstantqual != NULL || plan->qual != NIL ||
                outerPlan(plan) == NULL || innerPlan(plan) != NULL)
            {
                *reason = "projection_plan_mismatch";
                return false;
            }
            plan = outerPlan(plan);
        }
        if (!guard_repeated_indexes(source_root, projection->subpath, plan,
                repetitions, inner_loops, per_policy_loops, joins,
                &child, indices, reason))
            return false;
        copy = palloc(sizeof(*copy));
        *copy = *projection;
        copy->subpath = child;
        copy->path.startup_cost += child->startup_cost - projection->subpath->startup_cost;
        copy->path.total_cost += child->total_cost - projection->subpath->total_cost;
        *revised = &copy->path;
        return true;
    }
    if (IsA(path, NestPath) && IsA(plan, NestLoop) && joins == 0)
    {
        NestPath *original = castNode(NestPath, path);
        JoinPath *join = &original->jpath;
        NestLoop *nested = castNode(NestLoop, plan);
        NestPath baseline = *original;
        NestPath *copy = palloc(sizeof(*copy));
        JoinCostWorkspace workspace;
        JoinPathExtraData extra;
        SpecialJoinInfo sjinfo;
        Path *outer;
        Path *inner;
        double outer_rows;
        if (join->jointype != JOIN_INNER || nested->join.jointype != JOIN_INNER ||
            join->inner_unique != nested->join.inner_unique ||
            join->outerjoinpath == NULL || join->innerjoinpath == NULL ||
            join->innerjoinpath->rows > 1.0)
        {
            *reason = "nested_loop_outside_bound_shape";
            return false;
        }
        /* Parameterized inner index clauses were removed from joinrestrictinfo
         * by create_nestloop_path. Restore their original RestrictInfo pointers
         * for PG's selectivity helper, then prove the reconstructed parent cost.
         */
        memset(&extra, 0, sizeof(extra));
        memset(&sjinfo, 0, sizeof(sjinfo));
        sjinfo.type = T_SpecialJoinInfo;
        sjinfo.jointype = JOIN_INNER;
        sjinfo.min_lefthand = sjinfo.syn_lefthand = join->outerjoinpath->parent->relids;
        sjinfo.min_righthand = sjinfo.syn_righthand = join->innerjoinpath->parent->relids;
        extra.sjinfo = &sjinfo;
        extra.inner_unique = join->inner_unique;
        extra.restrictlist = list_copy(join->joinrestrictinfo);
        if (join->innerjoinpath->param_info != NULL)
            extra.restrictlist = list_union_ptr(extra.restrictlist,
                join->innerjoinpath->param_info->ppi_clauses);
        if (join->inner_unique)
            compute_semi_anti_join_factors(source_root, join->path.parent,
                join->outerjoinpath->parent, join->innerjoinpath->parent,
                JOIN_INNER, &sjinfo, extra.restrictlist, &extra.semifactors);
        initial_cost_nestloop(source_root, &workspace, JOIN_INNER,
            join->outerjoinpath, join->innerjoinpath, &extra);
        final_cost_nestloop(source_root, &baseline, &workspace, &extra);
        if (!guard_same_cost(baseline.jpath.path.startup_cost, path->startup_cost) ||
            !guard_same_cost(baseline.jpath.path.total_cost, path->total_cost) ||
            baseline.jpath.path.rows != path->rows)
        {
            *reason = "nested_loop_cost_reconstruction_mismatch";
            return false;
        }
        outer_rows = clamp_row_est(join->outerjoinpath->rows);
        if (!guard_repeated_indexes(source_root, join->outerjoinpath,
                outerPlan(plan), repetitions, inner_loops, per_policy_loops,
                joins + 1, &outer, indices, reason) ||
            !guard_repeated_indexes(source_root, join->innerjoinpath,
                innerPlan(plan), repetitions, inner_loops * outer_rows,
                per_policy_loops * outer_rows, joins + 1, &inner, indices, reason))
            return false;
        *copy = *original;
        copy->jpath.outerjoinpath = outer;
        copy->jpath.innerjoinpath = inner;
        initial_cost_nestloop(source_root, &workspace, JOIN_INNER,
            outer, inner, &extra);
        final_cost_nestloop(source_root, copy, &workspace, &extra);
        *revised = &copy->jpath.path;
        return true;
    }
    if (IsA(path, IndexPath) && IsA(plan, IndexOnlyScan))
    {
        IndexPath *indexed = castNode(IndexPath, path);
        IndexOnlyScan *scan = castNode(IndexOnlyScan, plan);
        IndexPath original = *indexed;
        IndexPath repeated = *indexed;
        Cost saved;
        List *entry;
        if (indexed->path.pathtype != T_IndexOnlyScan ||
            indexed->indexinfo == NULL || indexed->indexinfo->rel == NULL ||
            indexed->indexinfo->relam != BTREE_AM_OID ||
            indexed->indexinfo->rel->allvisfrac != 1.0 ||
            indexed->path.parallel_aware || indexed->path.parallel_workers != 0 ||
            scan->indexid != indexed->indexinfo->indexoid ||
            scan->scan.scanrelid != indexed->path.parent->relid)
        {
            *reason = "index_only_binding_or_visibility_mismatch";
            return false;
        }
        /* Baseline reconstruction guards the inherited per-source loop count. */
        cost_index(&original, source_root, inner_loops, false);
        if (!guard_same_cost(original.path.startup_cost, indexed->path.startup_cost) ||
            !guard_same_cost(original.path.total_cost, indexed->path.total_cost))
        {
            *reason = "original_loop_cost_mismatch";
            return false;
        }
        cost_index(&repeated, source_root, inner_loops * repetitions, false);
        if (!guard_same_cost(repeated.path.startup_cost, original.path.startup_cost) ||
            repeated.path.rows != original.path.rows ||
            repeated.indexselectivity != original.indexselectivity ||
            !isfinite(repeated.path.total_cost))
        {
            *reason = "reprice_changed_non_io_inputs";
            return false;
        }
        saved = original.path.total_cost - repeated.path.total_cost;
        if (!isfinite(saved) || saved < 0)
        {
            *reason = "nonmonotone_repeated_index_cost";
            return false;
        }
        *revised = palloc(sizeof(repeated));
        memcpy(*revised, &repeated, sizeof(repeated));
        entry = list_make5(guard_oid(indexed->indexinfo->indexoid),
            guard_number(inner_loops), guard_number(inner_loops * repetitions),
            guard_number(per_policy_loops), guard_number(original.path.total_cost));
        entry = lappend(entry, guard_number(repeated.path.total_cost));
        entry = lappend(entry, guard_number(original.path.startup_cost));
        entry = lappend(entry, guard_number(per_policy_loops * saved));
        *indices = lappend(*indices, entry);
        return true;
    }
    *reason = "source_path_outside_bound_shape";
    return false;
}

static List *
guard_repeated_policy_cost(PlannerInfo *root, GuardDescriptor *descriptor,
                          double calls, QualCost *policy)
{
    const char *reason = "not_applicable";
    SubPlan *arm = NULL;
    PlannerInfo *source_root = NULL;
    RelOptInfo *final_rel = NULL;
    Path *selected = NULL;
    Plan *source_plan = NULL;
    Cost reduction = 0;
    Path *revised_path = NULL;
    List *indices = NIL;
    List *receipt;
    double old_per_call = policy->per_tuple;
    Cost old_startup = policy->startup;
    Cost source_startup = -1;
    Cost source_total = -1;
    int plan_id = 0;
    bool applied = false;

    if (!guard_repeated_policy_estimation)
        reason = "disabled";
    else if (!isfinite(calls) || calls <= 1.0 ||
             descriptor->policy_binding == NIL ||
             strcmp(strVal(linitial(descriptor->policy_binding)), "native_pg_correlated_arm") != 0 ||
             !IsA(descriptor->policy->clause, AlternativeSubPlan) ||
             list_length(castNode(AlternativeSubPlan, descriptor->policy->clause)->subplans) != 1)
        reason = "not_bound_correlated_exists";
    else
    {
        Node *item = linitial(castNode(AlternativeSubPlan, descriptor->policy->clause)->subplans);
        if (!IsA(item, SubPlan))
            reason = "source_arm_not_subplan";
        else
        {
            arm = castNode(SubPlan, item);
            plan_id = arm->plan_id;
            if (arm->useHashTable || arm->subLinkType != EXISTS_SUBLINK ||
                arm->parParam == NIL || plan_id <= 0 ||
                plan_id > list_length(root->glob->subplans) ||
                plan_id > list_length(root->glob->subroots))
                reason = "source_arm_outside_bound_exists";
            else
            {
                source_plan = planner_subplan_get_plan(root, arm);
                source_root = list_nth(root->glob->subroots, plan_id - 1);
                source_startup = source_plan->startup_cost;
                source_total = source_plan->total_cost;
                if (source_root == NULL || source_root->glob != root->glob ||
                    list_length(source_root->upper_rels[UPPERREL_FINAL]) != 1)
                    reason = "source_root_binding_mismatch";
                else if (source_plan->plan_rows != 1.0)
                    reason = "exists_fraction_outside_bound_shape";
                else
                {
                    final_rel = linitial(source_root->upper_rels[UPPERREL_FINAL]);
                    /* Exactly the selector used by make_subplan for EXISTS. */
                    selected = get_cheapest_fractional_path(final_rel, 1.0);
                    if (selected == NULL ||
                        !guard_same_cost(selected->startup_cost, source_startup) ||
                        !guard_same_cost(selected->total_cost, source_total))
                        reason = "selected_fractional_path_mismatch";
                    else if (guard_repeated_indexes(source_root, selected, source_plan,
                                 calls, 1.0, 1.0, 0, &revised_path, &indices, &reason))
                    {
                        Plan revised_plan = *source_plan;
                        SubPlan baseline_arm = *arm;
                        SubPlan revised_arm = *arm;
                        cost_subplan(root, &baseline_arm, source_plan);
                        reduction = selected->total_cost - revised_path->total_cost;
                        if (!guard_same_cost(revised_path->startup_cost, selected->startup_cost))
                            reduction = -1;
                        if (indices == NIL || !isfinite(reduction) || reduction < 0 ||
                            !guard_same_cost(baseline_arm.startup_cost, arm->startup_cost) ||
                            !guard_same_cost(baseline_arm.per_call_cost, arm->per_call_cost) ||
                            source_total - reduction < source_startup)
                            reason = "source_cost_reconstruction_mismatch";
                        else
                        {
                            revised_plan.total_cost -= reduction;
                            cost_subplan(root, &revised_arm, &revised_plan);
                            policy->startup += revised_arm.startup_cost - arm->startup_cost;
                            policy->per_tuple += revised_arm.per_call_cost - arm->per_call_cost;
                            if (!isfinite(policy->per_tuple) || policy->per_tuple < 0 ||
                                !guard_same_cost(policy->startup, old_startup))
                            {
                                policy->per_tuple = old_per_call;
                                policy->startup = old_startup;
                                reason = "invalid_adjusted_policy_cost";
                            }
                            else
                            {
                                reason = "pg_repeated_index_only_io";
                                applied = true;
                            }
                        }
                    }
                }
            }
        }
    }
    if (!applied)
        reduction = 0;
    receipt = list_make5(makeString(pstrdup(reason)), makeInteger(plan_id),
        guard_number(calls), guard_number(old_per_call), guard_number(policy->per_tuple));
    receipt = lappend(receipt, guard_number(reduction));
    receipt = lappend(receipt, guard_number(source_startup));
    receipt = lappend(receipt, guard_number(source_total));
    receipt = lappend(receipt, applied ? indices : NIL);
    return receipt;
}

/* Apply staged counts to the actual order, not a magic family discount. */
static Cost
guard_completion_cost(PlannerInfo *root, RelOptInfo *rel, GuardDescriptor *descriptor,
					  double candidates, List **receipt, Cost *startup)
{
	QualCost policy;
	ListCell *cell;
	List *user_stages = NIL;
    List *repeated_receipt;
	double authorized = clauselist_selectivity(root,
		list_make1(descriptor->policy), rel->relid, JOIN_INNER, NULL);
	double guard_selectivity = clauselist_selectivity(root,
		descriptor->bounds, rel->relid, JOIN_INNER, NULL);
	double remaining = descriptor->late_policy ? candidates : candidates * authorized;
	double policy_calls;
	double user_calls = remaining;
	Cost total = 0;
	Cost user_per_tuple = 0;

	cost_qual_eval(&policy, list_make1(descriptor->policy), root);
	*startup = policy.startup;
	foreach(cell, descriptor->users)
	{
		RestrictInfo *rinfo = lfirst_node(RestrictInfo, cell);
		QualCost qual;
		double selectivity = clause_selectivity(root, (Node *) rinfo,
			rel->relid, JOIN_INNER, NULL);
		cost_qual_eval(&qual, list_make1(rinfo), root);
		/* LIKE entails our guard; avoid charging the prefix selectivity twice. */
		if (rinfo == descriptor->like && guard_selectivity > 0)
			selectivity = Min(1.0, selectivity / guard_selectivity);
		user_stages = lappend(user_stages, list_make3(guard_number(remaining),
			guard_number(qual.per_tuple), guard_number(selectivity)));
		total += remaining * qual.per_tuple;
		user_per_tuple += qual.per_tuple;
		*startup += qual.startup;
		remaining *= selectivity;
	}
	policy_calls = descriptor->late_policy ? remaining : candidates;
    {
        Cost previous_startup = policy.startup;
        repeated_receipt = guard_repeated_policy_cost(root, descriptor, policy_calls, &policy);
        *startup += policy.startup - previous_startup;
    }
	total += *startup + policy_calls * policy.per_tuple;
	/* This second ExecScan is real work even when its output is a plain Var. */
	total += cpu_tuple_cost * candidates;
	*receipt = list_make5(guard_number(candidates), guard_number(policy_calls),
		guard_number(user_calls), guard_number(policy.per_tuple), guard_number(user_per_tuple));
	*receipt = lappend(*receipt, guard_number(total));
	*receipt = lappend(*receipt, user_stages);
	*receipt = lappend(*receipt, descriptor->policy_binding);
    *receipt = lappend(*receipt, repeated_receipt);
	return total;
}

static CustomPath *
guard_wrap(PlannerInfo *root, RelOptInfo *rel, RangeTblEntry *rte,
			GuardDescriptor *descriptor, Path *child, bool indexed)
{
	CustomPath *path = makeNode(CustomPath);
	List *costs;
	Cost startup;
	Cost completion = guard_completion_cost(root, rel, descriptor, child->rows, &costs, &startup);
	path->path.pathtype = T_CustomScan;
	path->path.parent = rel;
	path->path.pathtarget = rel->reltarget;
	path->path.rows = rel->rows;
	path->path.startup_cost = child->startup_cost + startup;
	path->path.total_cost = child->total_cost + completion;
	path->path.parallel_aware = false;
	path->path.parallel_safe = false;
	path->path.parallel_workers = 0;
	path->path.pathkeys = child->pathkeys;
	path->custom_paths = list_make1(child);
	path->methods = &guard_path_methods;
	path->custom_private = list_make5(descriptor->policy->clause,
		get_actual_clauses(descriptor->users), descriptor->bounds,
		guard_oid(rte->relid), guard_oid(indexed ? descriptor->index->indexoid : InvalidOid));
	path->custom_private = lappend(path->custom_private, makeInteger(descriptor->title->varattno));
	path->custom_private = lappend(path->custom_private, makeInteger(descriptor->late_policy));
	path->custom_private = lappend(path->custom_private, costs);
	path->custom_private = lappend(path->custom_private, guard_number(child->total_cost));
	if (strcmp(GetConfigOptionByName("native_af.trace", NULL, false), "on") == 0)
		ereport(NOTICE,
			(errmsg("native_af: AF Prefix Guard %s %s completion %s source %d candidates %.6f policy_calls %.6f startup %.6f total %.6f",
				indexed ? "index" : "seq", descriptor->late_policy ? "diagnostic-late" : "policy-first",
				descriptor->policy_binding == NIL ? "original_pg_policy" : strVal(linitial(descriptor->policy_binding)),
				descriptor->policy_binding == NIL ? 0 : intVal(lsecond(descriptor->policy_binding)),
				child->rows, floatVal(lsecond(costs)), path->path.startup_cost, path->path.total_cost)));
	return path;
}

static const char *
guard_sp_scope(PlannerInfo *root, List *paths, RestrictInfo *closed_policy, Node *original_policy)
{
	CustomPath *path;
	List *users;
	if (paths == NIL)
		return NULL;
	path = linitial_node(CustomPath, paths);
	users = lsecond(path->custom_private);
	if (root->parse->limitCount || root->parse->limitOffset || root->tuple_fraction > 0)
		return "outside_frozen_sp_fractional_parent";
	if (contain_volatile_functions((Node *) users))
		return "outside_frozen_sp_volatile_user";
	/* Exactly the generator's original builtin LIKE is fixed outside the slot.
	 * No other user function/SubPlan/selection is inferred pure from a flag. */
	if (list_length(users) != 1 || !IsA(linitial(users), OpExpr) ||
		get_opcode(linitial_node(OpExpr, users)->opno) != F_TEXTLIKE)
		return "outside_frozen_sp_user_language";
	/* Reuse the independently admitted core closed-ACL grammar, and bind it
	 * to this actual original policy. No STABLE/purity inference is made. */
	if (closed_policy == NULL ||
		!equal(closed_policy->clause, original_policy))
		return "outside_frozen_sp_exact_check_language";
	return NULL;
}

/*
 * Actual AF-private finite comparison, before publishing to add_path.
 * Both roots have the same pending exact policy and complete heap/CTID
 * inputs. rho requires exact completion before user reads; rho union M
 * additionally requires the real fields/carrier of the fixed projection.
 * Both constructors retain those inputs, so their same completion adds
 * equal work. We decline the certificate for unequal order or other
 * nonmonotone parent inputs, instead of hiding a useful order property.
 */
static List *
guard_sp_paths(PlannerInfo *root, List *paths, RestrictInfo *closed_policy,
			   Node *original_policy, const NativeAfScanRequirement *need, Node *target_filter)
{
	List *survivors = list_copy(paths);
	List *evidence = NIL;
	ListCell *indexed_cell;
	const char *outside = guard_sp_scope(root, paths, closed_policy, original_policy);
	if (outside != NULL)
	{
		foreach(indexed_cell, survivors)
		{
			CustomPath *path = lfirst_node(CustomPath, indexed_cell);
			List *entry = list_make5(makeString("retain"),
				makeString(pstrdup(outside)),
				list_make2(makeInteger(false), makeInteger(false)),
				guard_number(path->path.total_cost), guard_number(path->path.total_cost));
			entry = lappend(entry, copyObject(list_nth(path->custom_private, 6)));
			entry = lappend(entry, copyObject(list_nth(path->custom_private, 4)));
			entry = lappend(entry, makeString(pstrdup(outside)));
			path->custom_private = lappend(path->custom_private, list_make1(entry));
			guard_retained++;
		}
		return survivors;
	}
	foreach(indexed_cell, paths)
	{
		CustomPath *indexed = lfirst_node(CustomPath, indexed_cell);
		Path *index_child = linitial(indexed->custom_paths);
		ListCell *seq_cell;
		if (!IsA(index_child, IndexPath))
			continue;
		foreach(seq_cell, paths)
		{
			CustomPath *seq = lfirst_node(CustomPath, seq_cell);
			Path *seq_child = linitial(seq->custom_paths);
			const char *reason = "pass";
			const char *decision = "retain";
			bool root_ok;
			bool projection_ok;
			NativeAfScanRule indexed_rule = {
				.input = index_child->pathtarget,
				.output = indexed->path.pathtarget,
				.target_filter = target_filter,
				.before_check = get_actual_clauses(index_child->parent->baserestrictinfo),
				.after_check = lsecond(indexed->custom_private),
				.exact_check = linitial(indexed->custom_private),
				.validated_prefix = lthird(indexed->custom_private),
				.identity = SelfItemPointerAttributeNumber
			};
			NativeAfScanRule seq_rule = {
				.input = seq_child->pathtarget,
				.output = seq->path.pathtarget,
				.target_filter = target_filter,
				.before_check = get_actual_clauses(seq_child->parent->baserestrictinfo),
				.after_check = lsecond(seq->custom_private),
				.exact_check = linitial(seq->custom_private),
				.validated_prefix = lthird(seq->custom_private),
				.identity = SelfItemPointerAttributeNumber
			};
			NativeAfScanDelivery indexed_delivery;
			NativeAfScanDelivery seq_delivery;
			QualCost policy;
			Cost index_root_cost;
			Cost seq_root_cost;
			if (seq_child->pathtype != T_SeqScan ||
				intVal(list_nth(indexed->custom_private, 6)) !=
				intVal(list_nth(seq->custom_private, 6)))
				continue;
			if (intVal(list_nth(indexed->custom_private, 6)))
			{
				List *entry = list_make5(makeString("retain"),
					makeString("diagnostic_rejected_outside_sp"),
					list_make2(makeInteger(false), makeInteger(false)),
					guard_number(indexed->path.total_cost), guard_number(seq->path.total_cost));
				entry = lappend(entry, makeInteger(true));
				entry = lappend(entry, copyObject(list_nth(indexed->custom_private, 4)));
				entry = lappend(entry, makeString("rejected_candidate_no_sp_certificate"));
				evidence = lappend(evidence, entry);
				guard_retained++;
				continue;
			}
			/* Certificate terminates at the exact boundary before original LIKE.
			 * LIKE's fixed authorized-only work is equal, outside this SP slot. */
			cost_qual_eval_node(&policy, linitial(indexed->custom_private), root);
			index_root_cost = index_child->total_cost + policy.startup +
				index_child->rows * (policy.per_tuple + cpu_tuple_cost);
			seq_root_cost = seq_child->total_cost + policy.startup +
				seq_child->rows * (policy.per_tuple + cpu_tuple_cost);
			root_ok = equal(linitial(indexed->custom_private), linitial(seq->custom_private)) &&
				equal(lsecond(indexed->custom_private), lsecond(seq->custom_private)) &&
				equal(lthird(indexed->custom_private), lthird(seq->custom_private)) &&
				equal(get_actual_clauses(index_child->parent->baserestrictinfo),
					get_actual_clauses(seq_child->parent->baserestrictinfo)) &&
				equal(list_nth(indexed->custom_private, 7), list_nth(seq->custom_private, 7));
			projection_ok = equal(index_child->pathtarget->exprs, seq_child->pathtarget->exprs) &&
				index_child->pathtarget->width == seq_child->pathtarget->width;
			root_ok = root_ok &&
				native_af_admit_checked_scan(need, &indexed_rule, &indexed_delivery) == NULL &&
				native_af_admit_checked_scan(need, &seq_rule, &seq_delivery) == NULL &&
				native_af_scan_preserves(&indexed_delivery, &seq_delivery, false) == NULL;
			projection_ok = projection_ok && (!root_ok ||
				native_af_scan_preserves(&indexed_delivery, &seq_delivery, true) == NULL);
			if (!root_ok)
				reason = "completion_or_guard_binding_mismatch";
			else if (!projection_ok)
				reason = "required_policy_inputs_or_carrier_mismatch";
			else if (compare_pathkeys(index_child->pathkeys, seq_child->pathkeys) != PATHKEYS_EQUAL)
				reason = "order_fact_mismatch";
			/* Fixed physical order may be part of starting rho. No Sort is an
			 * SP operator/enforcer here: retain if either root lacks that order. */
			else if (!pathkeys_contained_in(root->sort_pathkeys, index_child->pathkeys) ||
				!pathkeys_contained_in(root->sort_pathkeys, seq_child->pathkeys))
				reason = "starting_order_requirement_not_delivered";
			else if (root->parse->sortClause != NIL)
				reason = "outer_order_operator_outside_fragment";
			else if (index_child->rows != seq_child->rows ||
				!isfinite(indexed->path.total_cost) || !isfinite(seq->path.total_cost))
				reason = "cardinality_or_cost_input_mismatch";
			else
			{
				CustomPath *worse = index_root_cost <= seq_root_cost ? seq : indexed;
				if (list_member_ptr(survivors, worse))
				{
					survivors = list_delete_ptr(survivors, worse);
					guard_pruned++;
					decision = worse == seq ? "drop_seq" : "drop_index";
				}
				else
					decision = "already_discarded";
			}
			if (strcmp(decision, "retain") == 0)
				guard_retained++;
			{
				List *entry = list_make5(makeString(pstrdup(decision)),
					makeString(pstrdup(reason)), list_make2(makeInteger(root_ok), makeInteger(projection_ok)),
					guard_number(index_root_cost), guard_number(seq_root_cost));
				entry = lappend(entry, makeInteger(intVal(list_nth(indexed->custom_private, 6))));
				entry = lappend(entry, copyObject(list_nth(indexed->custom_private, 4)));
				entry = lappend(entry, makeString("fixed_guard_selection_projection"));
				entry = lappend(entry, list_make5(makeInteger(list_length(index_child->pathkeys)),
					makeInteger(list_length(seq_child->pathkeys)), makeInteger(list_length(root->sort_pathkeys)),
					makeInteger(pathkeys_contained_in(root->sort_pathkeys, index_child->pathkeys)),
					makeInteger(pathkeys_contained_in(root->sort_pathkeys, seq_child->pathkeys))));
				evidence = lappend(evidence, entry);
			}
		}
	}
	foreach(indexed_cell, survivors)
	{
		CustomPath *path = lfirst_node(CustomPath, indexed_cell);
		path->custom_private = lappend(path->custom_private, evidence);
	}
	return survivors;
}

/* Passive evidence is independent of SP. Rejected production candidates have
 * no cost fields at all; only an isolated diagnostic build costs late policy. */
static List *
guard_cost_evidence(List *paths, List *uncosted)
{
	List *evidence = list_copy(uncosted);
	ListCell *cell;
	foreach(cell, paths)
	{
		CustomPath *path = lfirst_node(CustomPath, cell);
		bool late = intVal(list_nth(path->custom_private, 6));
		List *entry = list_make5(copyObject(list_nth(path->custom_private, 4)),
			makeInteger(late), makeString(late ? "diagnostic_bypass_costed" : "admitted_costed"),
			makeString(late ? "protected_read_before_exact_policy" : "pass"),
			guard_number(path->path.startup_cost));
		entry = lappend(entry, guard_number(path->path.total_cost));
		entry = lappend(entry, copyObject(list_nth(path->custom_private, 8)));
		entry = lappend(entry, copyObject(list_nth(path->custom_private, 7)));
		evidence = lappend(evidence, entry);
	}
	return evidence;
}

List *
native_af_guard_paths(PlannerInfo *root, RelOptInfo *rel, RangeTblEntry *rte,
					  RestrictInfo *closed_policy, RestrictInfo *completed_hash_policy)
{
	GuardDescriptor base = {0};
	NativeAfScanRequirement need;
	PathTarget *input = NULL;
	List *accepted = NIL;
	List *uncosted = NIL;
	List *cost_evidence;
	List *variants;
	ListCell *cell;
	bool seq_created = false;

	if (!guard_scope(root, rel, rte) || !guard_find(root, rel, rte, &base) ||
		!native_af_scan_requirement(root, rel, rte, &need))
		return NIL;
	variants = guard_policy_variants(root, &base, closed_policy, completed_hash_policy);
	foreach(cell, rel->indexlist)
	{
		IndexOptInfo *index = lfirst_node(IndexOptInfo, cell);
		SupportRequestIndexCondition request = {0};
		GuardDescriptor safe = base;
		RelOptInfo *raw = NULL;
		int indexed;

		if (!guard_index(index, rel, base.title))
			continue;
		NodeSetTag(&request, T_SupportRequestIndexCondition);
		request.root = root;
		request.funcid = F_TEXTLIKE;
		request.node = (Node *) base.like->clause;
		request.indexarg = 0;
		request.index = index;
		request.indexcol = 0;
		request.opfamily = index->opfamily[0];
		request.indexcollation = index->indexcollations[0];
		request.lossy = true;
		safe.bounds = (List *) DatumGetPointer(OidFunctionCall1(F_TEXTLIKE_SUPPORT,
			PointerGetDatum(&request)));
		if (safe.bounds == NIL)
			continue;
		if (input == NULL)
			input = guard_target(rel, rte->relid);
		safe.index = index;
		for (indexed = 1; indexed >= 0; indexed--)
		{
			Path *child = NULL;
			ListCell *variant_cell;
			if ((indexed && !enable_indexscan) || (!indexed && (!enable_seqscan || seq_created)))
				continue;
			foreach(variant_cell, variants)
			{
				GuardDescriptor admitted = *(GuardDescriptor *) lfirst(variant_cell);
				GuardDescriptor unsafe;
				CustomPath *path;
				bool safe_ok;
				bool unsafe_ok;
				admitted.index = index;
				admitted.bounds = safe.bounds;
				unsafe = admitted;
				unsafe.late_policy = true;
				/* Every actual provider/completion/order is admitted before cost. */
				safe_ok = guard_admit(root, rel, rte, &need, input, &admitted);
				unsafe_ok = guard_admit(root, rel, rte, &need, input, &unsafe);
#ifndef NATIVE_AF_GUARD_DIAGNOSTIC_UNSAFE
				if (!unsafe_ok)
				{
					List *rejection = list_make4(guard_oid(indexed ? index->indexoid : InvalidOid),
						makeInteger(true), makeString("rejected_uncosted"), makeString(pstrdup(unsafe.rejection)));
					if (unsafe.policy_binding != NIL)
					{
						rejection = lappend(rejection, copyObject(linitial(unsafe.policy_binding)));
						rejection = lappend(rejection, copyObject(lsecond(unsafe.policy_binding)));
					}
					uncosted = lappend(uncosted, rejection);
				}
#endif
				if (!safe_ok)
					continue;
				if (raw == NULL)
					raw = guard_relation(root, rel, input, safe.bounds);
				if (child == NULL)
					child = guard_child(root, raw, &admitted, indexed);
				path = guard_wrap(root, rel, rte, &admitted, child, indexed);
				accepted = lappend(accepted, path);
#ifdef NATIVE_AF_GUARD_DIAGNOSTIC_UNSAFE
				if (!unsafe_ok && strcmp(unsafe.rejection, "protected_read_before_exact_policy") == 0)
				{
					path = guard_wrap(root, rel, rte, &unsafe, child, indexed);
					accepted = lappend(accepted, path);
				}
#else
				(void) unsafe_ok;
#endif
			}
			if (!indexed && child != NULL)
				seq_created = true;
		}
	}
	cost_evidence = guard_cost_evidence(accepted, uncosted);
	accepted = guard_sp_paths(root, accepted, closed_policy, (Node *) base.original_policy->clause,
							  &need, (Node *) base.like->clause);
	foreach(cell, accepted)
	{
		CustomPath *path = lfirst_node(CustomPath, cell);
		path->custom_private = lappend(path->custom_private, cost_evidence);
	}
	guard_published += list_length(accepted);
	return accepted;
}

static Plan *
guard_plan(PlannerInfo *root, RelOptInfo *rel, CustomPath *path,
			List *target, List *clauses, List *children)
{
	CustomScan *scan = makeNode(CustomScan);
	Plan *child;
	Node *policy = linitial(path->custom_private);
	List *users = lsecond(path->custom_private);
	List *bounds = lthird(path->custom_private);
	bool late = intVal(list_nth(path->custom_private, 6));

	if (list_length(children) != 1)
		elog(ERROR, "AF prefix candidate must have exactly one raw child");
	child = linitial(children);
	if ((!IsA(child, IndexScan) && !IsA(child, SeqScan)) ||
		((Scan *) child)->scanrelid != rel->relid)
		elog(ERROR, "AF prefix raw child binding mismatch");
	/* Scan builder may omit index-implied bounds; it must never add users/RLS. */
	if (list_member(child->qual, policy))
		elog(ERROR, "AF prefix policy unexpectedly executed in raw child");
	scan->scan.scanrelid = rel->relid;
	scan->scan.plan.targetlist = target;
	scan->scan.plan.qual = late ? lappend(list_copy(users), policy) : lcons(policy, list_copy(users));
	scan->custom_plans = children;
	scan->custom_scan_tlist = copyObject(child->targetlist);
	/* These expression copies undergo normal setrefs and SubPlan finalization. */
	scan->custom_exprs = list_make3(policy, users, bounds);
	scan->custom_private = list_copy_tail(path->custom_private, 3);
	scan->methods = &guard_scan_methods;
	return &scan->scan.plan;
}

static Node *
guard_create(CustomScan *scan)
{
	GuardState *state = palloc0(sizeof(*state));
	NodeSetTag(&state->css, T_CustomScanState);
	state->css.methods = &guard_exec_methods;
	return (Node *) state;
}

/* setrefs maps the upper bounds to INDEX_VAR slots; recover their real source. */
static List *
guard_source_bounds(List *bounds, List *target)
{
	List *result = NIL;
	ListCell *cell;
	foreach(cell, bounds)
	{
		OpExpr *op;
		Var *column;
		TargetEntry *entry;
		if (!IsA(lfirst(cell), OpExpr))
			elog(ERROR, "AF prefix upper bound is not an operator");
		op = copyObject(lfirst_node(OpExpr, cell));
		if (list_length(op->args) != 2 || !IsA(linitial(op->args), Var))
			elog(ERROR, "AF prefix upper bound has unexpected inputs");
		column = linitial_node(Var, op->args);
		if (column->varno != INDEX_VAR || column->varattno <= 0 ||
			column->varattno > list_length(target))
			elog(ERROR, "AF prefix upper bound slot mismatch");
		entry = list_nth_node(TargetEntry, target, column->varattno - 1);
		if (!IsA(entry->expr, Var))
			elog(ERROR, "AF prefix bound has no plain source column");
		op->args = list_make2(copyObject(entry->expr), lsecond(op->args));
		result = lappend(result, op);
	}
	return result;
}

static bool
guard_only_bounds(List *actual, List *bounds, bool complete)
{
	ListCell *cell;
	if (complete && list_length(actual) != list_length(bounds))
		return false;
	foreach(cell, actual)
		if (!list_member(bounds, lfirst(cell)))
			return false;
	return true;
}

static bool
guard_runtime_index(Oid oid, Oid heap, AttrNumber attribute)
{
	Relation index = index_open(oid, AccessShareLock);
	bool valid = IndexGetRelation(oid, true) == heap &&
		index->rd_rel->relam == BTREE_AM_OID && index->rd_amhandler == F_BTHANDLER && guard_am() &&
		index->rd_index->indisvalid && index->rd_index->indisready && index->rd_index->indislive &&
		index->rd_index->indnkeyatts == 1 && index->rd_index->indkey.values[0] == attribute &&
		RelationGetIndexExpressions(index) == NIL && RelationGetIndexPredicate(index) == NIL &&
		index->rd_opfamily[0] == TEXT_PATTERN_BTREE_FAM_OID &&
		get_index_column_opclass(oid, 1) == TEXT_BTREE_PATTERN_OPS_OID &&
		index->rd_indcollation[0] == C_COLLATION_OID &&
		index_getprocid(index, 1, BTORDER_PROC) == F_BTTEXT_PATTERN_CMP &&
		guard_function(F_BTTEXT_PATTERN_CMP);
	index_close(index, AccessShareLock);
	return valid;
}

static bool
guard_policy_key(Node *node, CustomScan *scan, AttrNumber attribute)
{
	Var *key;
	if (!IsA(node, Var))
		return false;
	key = castNode(Var, node);
	if (key->vartype != INT8OID || key->varlevelsup != 0 ||
		!bms_is_empty(key->varnullingrels))
		return false;
	if (key->varno == scan->scan.scanrelid && key->varattno == attribute)
		return true;
	if (key->varno == INDEX_VAR && key->varattno > 0 &&
		key->varattno <= list_length(scan->custom_scan_tlist))
	{
		TargetEntry *entry = list_nth_node(TargetEntry, scan->custom_scan_tlist, key->varattno - 1);
		return guard_policy_key((Node *) entry->expr, scan, attribute);
	}
	return false;
}

static void
guard_policy_execution(GuardState *state)
{
	CustomScan *scan = castNode(CustomScan, state->css.ss.ps.plan);
	EState *estate = state->css.ss.ps.state;
	List *costs = list_nth(scan->custom_private, 4);
	List *binding = list_nth(costs, 7);
	Oid heap = DatumGetObjectId(linitial_node(Const, scan->custom_private)->constvalue);
	Node *actual;
	SubPlan *subplan;
	SubPlanState *source = NULL;
	PlanState *expected_state;
	Plan *expected_plan;
	int source_id;
	int input_param;
	ListCell *cell;
	if (binding == NIL)
		return;                 /* Original PG expression was not rewritten. */
	source_id = intVal(lsecond(binding));
	if (strcmp(strVal(linitial(binding)), "native_pg_hash_arm") == 0)
	{
		if (!native_af_hash_policy_binding(estate, &state->css.ss.ps,
			scan->scan.scanrelid, heap, intVal(lthird(binding)), source_id, lfourth(binding)))
			elog(ERROR, "AF prefix exact hash policy binding failed");
		return;
	}
	if (strcmp(strVal(linitial(binding)), "native_pg_correlated_arm") != 0)
		elog(ERROR, "AF prefix unknown exact policy implementation");
	/* Bind the executable qual and its actual SubPlanState, not proof copies. */
	actual = intVal(lfourth(scan->custom_private)) ? llast(scan->scan.plan.qual) : linitial(scan->scan.plan.qual);
	if (!IsA(actual, SubPlan) || source_id < 1 ||
		source_id > list_length(estate->es_plannedstmt->subplans) ||
		source_id > list_length(estate->es_subplanstates))
		elog(ERROR, "AF prefix correlated policy source identity failed");
	subplan = castNode(SubPlan, actual);
	if (subplan->plan_id != source_id || subplan->subLinkType != EXISTS_SUBLINK ||
		subplan->useHashTable || subplan->testexpr || subplan->setParam != NIL ||
		list_length(subplan->args) != 1 || list_length(subplan->parParam) != 1 ||
		!guard_policy_key(linitial(subplan->args), scan, intVal(lthird(binding))))
		elog(ERROR, "AF prefix correlated policy input binding failed");
	input_param = linitial_int(subplan->parParam);
	if (input_param < 0 || input_param >= list_length(estate->es_plannedstmt->paramExecTypes) ||
		list_nth_oid(estate->es_plannedstmt->paramExecTypes, input_param) != INT8OID)
		elog(ERROR, "AF prefix correlated policy parameter type failed");
	foreach(cell, state->css.ss.ps.subPlan)
		if (lfirst_node(SubPlanState, cell)->subplan == subplan)
		{
			if (source != NULL)
				elog(ERROR, "AF prefix correlated policy has duplicate executor state");
			source = lfirst_node(SubPlanState, cell);
		}
	expected_state = list_nth(estate->es_subplanstates, source_id - 1);
	expected_plan = list_nth(estate->es_plannedstmt->subplans, source_id - 1);
	if (source == NULL || expected_state == NULL || expected_plan == NULL ||
		source->parent != &state->css.ss.ps || source->planstate != expected_state ||
		expected_state->plan != expected_plan ||
		!native_af_policy_source_binding(estate, expected_state, lfourth(binding)))
		elog(ERROR, "AF prefix correlated policy executor/source binding failed");
}

static void
guard_binding(GuardState *state)
{
	CustomScan *scan = castNode(CustomScan, state->css.ss.ps.plan);
	EState *estate = state->css.ss.ps.state;
	Plan *child = linitial(scan->custom_plans);
	Oid heap = DatumGetObjectId(linitial_node(Const, scan->custom_private)->constvalue);
	Oid index = DatumGetObjectId(lsecond_node(Const, scan->custom_private)->constvalue);
	AttrNumber attribute = intVal(lthird(scan->custom_private));
	bool late = intVal(lfourth(scan->custom_private));
	Node *policy = linitial(scan->custom_exprs);
	List *users = lsecond(scan->custom_exprs);
	List *bounds = lthird(scan->custom_exprs);
	List *source_bounds = guard_source_bounds(bounds, scan->custom_scan_tlist);
	List *expected = late ? lappend(list_copy(users), policy) : lcons(policy, list_copy(users));
	RangeTblEntry *rte;
	RTEPermissionInfo *permission;
	ListCell *cell;
	int position = 0;
	bool title_retained = false;
	bool tid_retained = false;
	Var *source_title = NULL;
	TupleDesc heap_desc = RelationGetDescr(state->css.ss.ss_currentRelation);
	int heap_columns = 0;
	int attribute_number;
	Bitmapset *seen_attributes = NULL;

#ifndef NATIVE_AF_GUARD_DIAGNOSTIC_UNSAFE
	if (late)
		elog(ERROR, "AF production executor rejects late exact policy");
#endif
	if (estate->es_epq_active != NULL || estate->es_rowmarks != NULL ||
		estate->es_plannedstmt->commandType != CMD_SELECT ||
		estate->es_plannedstmt->hasModifyingCTE ||
		estate->es_snapshot != state->snapshot || !IsMVCCSnapshot(estate->es_snapshot) ||
		scan->scan.scanrelid == 0 ||
		scan->scan.scanrelid > (Index) list_length(estate->es_plannedstmt->rtable) ||
		RelationGetRelid(state->css.ss.ss_currentRelation) != heap ||
		!equal(scan->scan.plan.qual, expected) || !equal(child->targetlist, scan->custom_scan_tlist))
		elog(ERROR, "AF prefix execution binding failed");
	rte = list_nth_node(RangeTblEntry, estate->es_plannedstmt->rtable, scan->scan.scanrelid - 1);
	if (rte->rtekind != RTE_RELATION || rte->relid != heap)
		elog(ERROR, "AF prefix source occurrence changed");
	permission = getRTEPermissionInfo(estate->es_rteperminfos, rte);
	if (permission->relid != heap || OidIsValid(permission->checkAsUser) ||
		(permission->requiredPerms & ACL_SELECT) == 0 || !guard_heap(heap))
		elog(ERROR, "AF prefix permission identity changed");
	foreach(cell, scan->custom_scan_tlist)
	{
		TargetEntry *entry = lfirst_node(TargetEntry, cell);
		Var *var;
		position++;
		if (!IsA(entry->expr, Var) || entry->resno != position)
			elog(ERROR, "AF prefix raw child computed an expression");
		var = castNode(Var, entry->expr);
		if (var->varno != scan->scan.scanrelid || var->varlevelsup != 0)
			elog(ERROR, "AF prefix raw tuple origin mismatch");
		if (var->varattno == attribute && var->vartype == TEXTOID && var->varcollid == C_COLLATION_OID)
		{
			title_retained = true;
			source_title = var;
		}
		if (var->varattno == SelfItemPointerAttributeNumber && var->vartype == TIDOID)
		{
			if (tid_retained)
				elog(ERROR, "AF prefix duplicates its origin carrier");
			tid_retained = true;
		}
		if (var->varattno > 0)
		{
			Form_pg_attribute column;
			if (var->varattno > heap_desc->natts)
				elog(ERROR, "AF prefix raw attribute outside relation descriptor");
			column = TupleDescAttr(heap_desc, var->varattno - 1);
			if (bms_is_member(var->varattno, seen_attributes) ||
				column->attisdropped || column->atttypid != var->vartype ||
				column->atttypmod != var->vartypmod || column->attcollation != var->varcollid)
				elog(ERROR, "AF prefix raw attribute type changed");
			seen_attributes = bms_add_member(seen_attributes, var->varattno);
			heap_columns++;
		}
	}
	for (attribute_number = 0; attribute_number < heap_desc->natts; attribute_number++)
		if (!TupleDescAttr(heap_desc, attribute_number)->attisdropped)
		{
			if (!bms_is_member(attribute_number + 1, seen_attributes))
				elog(ERROR, "AF prefix loses an actual policy input field");
			heap_columns--;
		}
	bms_free(seen_attributes);
	if (!title_retained || !tid_retained ||
		heap_columns != 0 || !guard_bounds(source_bounds, source_title) ||
		((Scan *) child)->scanrelid != scan->scan.scanrelid ||
		(!IsA(child, IndexScan) && !IsA(child, SeqScan)) ||
		(IsA(child, IndexScan) && (castNode(IndexScan, child)->indexid != index ||
			!guard_runtime_index(index, heap, attribute))) ||
		(IsA(child, SeqScan) && OidIsValid(index)))
		elog(ERROR, "AF prefix index or carrier binding failed");
	if (!guard_only_bounds(child->qual, source_bounds, IsA(child, SeqScan)))
		elog(ERROR, "AF prefix raw child contains an unchecked expression");
	if (IsA(child, IndexScan))
	{
		IndexScan *index_scan = castNode(IndexScan, child);
		if (!guard_only_bounds(index_scan->indexqualorig, source_bounds, true) ||
			index_scan->indexorderby != NIL || index_scan->indexorderbyorig != NIL ||
			index_scan->indexorderdir != ForwardScanDirection ||
			list_length(index_scan->indexqual) != list_length(source_bounds))
			elog(ERROR, "AF prefix physical index condition changed");
		foreach(cell, index_scan->indexqual)
		{
			OpExpr *op;
			Var *key;
			if (!IsA(lfirst(cell), OpExpr))
				elog(ERROR, "AF prefix physical condition is not an operator");
			op = lfirst_node(OpExpr, cell);
			if (list_length(op->args) != 2 || !IsA(linitial(op->args), Var) ||
				!IsA(lsecond(op->args), Const) || !guard_function(get_opcode(op->opno)))
				elog(ERROR, "AF prefix physical condition is not leakproof");
			key = linitial_node(Var, op->args);
			if (key->varno != INDEX_VAR || key->varattno != 1 ||
				key->vartype != TEXTOID || key->varlevelsup != 0)
				elog(ERROR, "AF prefix physical key input changed");
		}
	}
	if (state->child != NULL &&
		!equalTupleDescs(ExecGetResultType(state->child), state->css.ss.ss_ScanTupleSlot->tts_tupleDescriptor))
		elog(ERROR, "AF prefix executor tuple descriptor mismatch");
	guard_policy_execution(state);
}

static void
guard_begin(CustomScanState *node, EState *estate, int eflags)
{
	GuardState *state = (GuardState *) node;
	CustomScan *scan = castNode(CustomScan, node->ss.ps.plan);
	if (eflags & (EXEC_FLAG_MARK | EXEC_FLAG_BACKWARD))
		elog(ERROR, "AF prefix does not support mark/backward execution");
	native_af_check_serial_scan(scan, estate);
	state->snapshot = estate->es_snapshot;
	state->first_fetch = true;
	/* Source/tuple/qual binding is checked before initializing/fetching raw data. */
	guard_binding(state);
	state->child = ExecInitNode(linitial(scan->custom_plans), estate, eflags);
	node->custom_ps = list_make1(state->child);
}

static TupleTableSlot *
guard_access(ScanState *node)
{
	GuardState *state = (GuardState *) node;
	if (state->first_fetch)
	{
		guard_binding(state);
		state->first_fetch = false;
	}
	if (!state->counted)
	{
		CustomScan *scan = castNode(CustomScan, node->ps.plan);
		if (intVal(lfourth(scan->custom_private)))
			guard_unsafe_executed++;
		else
			guard_executed++;
		state->counted = true;
	}
	return ExecProcNode(state->child);
}

static bool
guard_recheck(ScanState *node, TupleTableSlot *slot)
{
	elog(ERROR, "AF prefix EvalPlanQual is unsupported");
	return false;
}

static TupleTableSlot *
guard_exec(CustomScanState *node)
{
	/* ExecQual preserves the actual list order installed by guard_plan. */
	return ExecScan(&node->ss, guard_access, guard_recheck);
}

static void
guard_end(CustomScanState *node)
{
	GuardState *state = (GuardState *) node;
	if (state->child)
		ExecEndNode(state->child);
}

static void
guard_rescan(CustomScanState *node)
{
	GuardState *state = (GuardState *) node;
	state->first_fetch = true;
	ExecScanReScan(&node->ss);
	if (node->ss.ps.chgParam != NULL)
		UpdateChangedParamSet(state->child, node->ss.ps.chgParam);
	if (state->child->chgParam == NULL)
		ExecReScan(state->child);
}

static void
guard_explain(CustomScanState *node, List *ancestors, ExplainState *es)
{
	CustomScan *scan = castNode(CustomScan, node->ss.ps.plan);
	GuardState *state = (GuardState *) node;
	Oid index = DatumGetObjectId(lsecond_node(Const, scan->custom_private)->constvalue);
	bool late = intVal(lfourth(scan->custom_private));
	List *costs = list_nth(scan->custom_private, 4);
	List *sp = list_nth(scan->custom_private, 6);
	List *candidate_costs = list_nth(scan->custom_private, 7);
	List *policy_binding = list_nth(costs, 7);
	ListCell *cell;
	ExplainPropertyText("AF Path", OidIsValid(index) ? "prefix_pending_index" : "prefix_pending_seq", es);
	ExplainPropertyText("AF Authorization", "pending_original_exact_policy", es);
	ExplainPropertyText("AF Execution Order", late ? "guard,user,policy,projection" : "guard,policy,user,projection", es);
	ExplainPropertyText("AF Actual Branch", state->counted ? "prefix_guard" : "not_executed", es);
	ExplainPropertyBool("AF Diagnostic Unsafe", late, es);
	ExplainPropertyInteger("AF Guard Attribute", NULL, intVal(lthird(scan->custom_private)), es);
	ExplainPropertyText("AF Carrier", "full_policy_inputs_and_ctid", es);
	ExplainPropertyText("AF Policy Implementation", policy_binding == NIL ?
		"original_pg_policy" : strVal(linitial(policy_binding)), es);
	if (policy_binding != NIL)
		ExplainPropertyInteger("AF Policy Source Plan", NULL, intVal(lsecond(policy_binding)), es);
	ExplainPropertyFloat("AF Guard Candidate Rows", NULL, floatVal(linitial(costs)), 2, es);
	ExplainPropertyFloat("AF Policy Estimated Calls", NULL, floatVal(lsecond(costs)), 2, es);
	ExplainPropertyFloat("AF User Estimated Calls", NULL, floatVal(lthird(costs)), 2, es);
	ExplainPropertyFloat("AF Policy Per Tuple Cost", NULL, floatVal(lfourth(costs)), 6, es);
	ExplainPropertyFloat("AF User Per Tuple Cost", NULL, floatVal(list_nth(costs, 4)), 6, es);
	ExplainPropertyFloat("AF Completion Cost", NULL, floatVal(list_nth(costs, 5)), 2, es);
	ExplainPropertyFloat("AF Guard Child Cost", NULL, floatVal(list_nth(scan->custom_private, 5)), 2, es);
    if (list_length(costs) > 8)
    {
        List *repeat = list_nth(costs, 8);
        ExplainOpenGroup("AF Repeated Policy Cost", "AF Repeated Policy Cost", true, es);
        ExplainPropertyText("Source", "pg_selected_exists_path_and_cost_index", es);
        ExplainPropertyText("Status", strVal(linitial(repeat)), es);
        ExplainPropertyInteger("SubPlan", NULL, intVal(lsecond(repeat)), es);
        ExplainPropertyFloat("Estimated Calls", NULL, floatVal(lthird(repeat)), 6, es);
        ExplainPropertyFloat("Original Per Call", NULL, floatVal(lfourth(repeat)), 9, es);
        ExplainPropertyFloat("Repeated Per Call", NULL, floatVal(list_nth(repeat, 4)), 9, es);
        ExplainPropertyFloat("Source IO Reduction", NULL, floatVal(list_nth(repeat, 5)), 9, es);
        ExplainPropertyFloat("Source Startup", NULL, floatVal(list_nth(repeat, 6)), 9, es);
        ExplainPropertyFloat("Source Total", NULL, floatVal(list_nth(repeat, 7)), 9, es);
        ExplainOpenGroup("Indexes", "Indexes", false, es);
        foreach(cell, list_nth(repeat, 8))
        {
            List *entry = lfirst(cell);
            ExplainOpenGroup("Index", NULL, true, es);
            ExplainPropertyInteger("Index OID", NULL, DatumGetObjectId(linitial_node(Const, entry)->constvalue), es);
            ExplainPropertyFloat("Original Loops", NULL, floatVal(lsecond(entry)), 6, es);
            ExplainPropertyFloat("Repeated Loops", NULL, floatVal(lthird(entry)), 6, es);
            ExplainPropertyFloat("Per Policy Loops", NULL, floatVal(lfourth(entry)), 6, es);
            ExplainPropertyFloat("Original Total", NULL, floatVal(list_nth(entry, 4)), 9, es);
            ExplainPropertyFloat("Repeated Total", NULL, floatVal(list_nth(entry, 5)), 9, es);
            ExplainPropertyFloat("Unchanged Startup", NULL, floatVal(list_nth(entry, 6)), 9, es);
            ExplainPropertyFloat("Raw IO Delta Times Invocations", NULL, floatVal(list_nth(entry, 7)), 9, es);
            ExplainCloseGroup("Index", NULL, true, es);
        }
        ExplainCloseGroup("Indexes", "Indexes", false, es);
        ExplainCloseGroup("AF Repeated Policy Cost", "AF Repeated Policy Cost", true, es);
    }
	ExplainOpenGroup("AF User Cost Stages", "AF User Cost Stages", false, es);
	foreach(cell, list_nth(costs, 6))
	{
		List *stage = lfirst(cell);
		ExplainOpenGroup("Stage", NULL, true, es);
		ExplainPropertyInteger("Ordinal", NULL, foreach_current_index(cell) + 1, es);
		ExplainPropertyFloat("Estimated Calls", NULL, floatVal(linitial(stage)), 6, es);
		ExplainPropertyFloat("Per Tuple Cost", NULL, floatVal(lsecond(stage)), 6, es);
		ExplainPropertyFloat("Conditional Selectivity", NULL, floatVal(lthird(stage)), 6, es);
		ExplainCloseGroup("Stage", NULL, true, es);
	}
	ExplainCloseGroup("AF User Cost Stages", "AF User Cost Stages", false, es);
	ExplainOpenGroup("AF SP Pending Comparisons", "AF SP Pending Comparisons", false, es);
	foreach(cell, sp)
	{
		List *entry = lfirst(cell);
		List *requirements = lthird(entry);
		ExplainOpenGroup("Comparison", NULL, true, es);
		ExplainPropertyText("AF SP Pending Decision", strVal(linitial(entry)), es);
		ExplainPropertyText("AF SP Pending Reason", strVal(lsecond(entry)), es);
		ExplainPropertyBool("AF SP Root Requirement", intVal(linitial(requirements)), es);
		ExplainPropertyBool("AF SP Projection Requirement", intVal(lsecond(requirements)), es);
		if (list_length(entry) >= 8 &&
			strcmp(strVal(list_nth(entry, 7)), "fixed_guard_selection_projection") == 0)
		{
			ExplainPropertyFloat("AF SP Index Boundary Cost", NULL, floatVal(lfourth(entry)), 8, es);
			ExplainPropertyFloat("AF SP Seq Boundary Cost", NULL, floatVal(list_nth(entry, 4)), 8, es);
			ExplainPropertyText("AF SP Cost Scope", "raw_guard_plus_exact_policy_before_original_like", es);
		}
		else
		{
			ExplainPropertyFloat("AF SP Uncertified Candidate Cost One", NULL, floatVal(lfourth(entry)), 8, es);
			ExplainPropertyFloat("AF SP Uncertified Candidate Cost Two", NULL, floatVal(list_nth(entry, 4)), 8, es);
			ExplainPropertyText("AF SP Cost Scope", "full_candidate_no_sp_certificate", es);
		}
		ExplainPropertyBool("AF SP Includes Order Enforcer", false, es);
		if (list_length(entry) >= 7)
		{
			Const *index_oid = list_nth_node(Const, entry, 6);
			ExplainPropertyBool("Diagnostic Late Policy", intVal(list_nth(entry, 5)), es);
			ExplainPropertyInteger("Index OID", NULL, DatumGetObjectId(index_oid->constvalue), es);
		}
		if (list_length(entry) >= 8)
			ExplainPropertyText("AF SP Fragment Scope", strVal(list_nth(entry, 7)), es);
		ExplainPropertyBool("AF SP Certificate Issued",
			strcmp(strVal(linitial(entry)), "drop_seq") == 0 ||
			strcmp(strVal(linitial(entry)), "drop_index") == 0, es);
		if (list_length(entry) >= 9)
		{
			List *facts = list_nth(entry, 8);
			ExplainPropertyInteger("AF SP Index Order Keys", NULL, intVal(linitial(facts)), es);
			ExplainPropertyInteger("AF SP Seq Order Keys", NULL, intVal(lsecond(facts)), es);
			ExplainPropertyInteger("AF SP Starting Order Keys", NULL, intVal(lthird(facts)), es);
			ExplainPropertyBool("AF SP Index Delivers Starting Order", intVal(lfourth(facts)), es);
			ExplainPropertyBool("AF SP Seq Delivers Starting Order", intVal(list_nth(facts, 4)), es);
		}
		ExplainPropertyBool("AF SP Covers Outer Sort Operator", false, es);
		ExplainCloseGroup("Comparison", NULL, true, es);
	}
	ExplainCloseGroup("AF SP Pending Comparisons", "AF SP Pending Comparisons", false, es);
	ExplainOpenGroup("AF Guard Costed Candidates", "AF Guard Costed Candidates", false, es);
	foreach(cell, candidate_costs)
	{
		List *entry = lfirst(cell);
		Const *oid = linitial_node(Const, entry);
		ExplainOpenGroup("Candidate", NULL, true, es);
		ExplainPropertyInteger("Index OID", NULL, DatumGetObjectId(oid->constvalue), es);
		ExplainPropertyBool("Late Policy", intVal(lsecond(entry)), es);
		ExplainPropertyText("Admission Status", strVal(lthird(entry)), es);
		ExplainPropertyText("Admission Reason", strVal(lfourth(entry)), es);
		ExplainPropertyBool("Cost Available", list_length(entry) >= 8, es);
		if (list_length(entry) >= 8)
		{
			List *stages = list_nth(entry, 7);
			List *implementation = list_nth(stages, 7);
			ExplainPropertyFloat("Startup Cost", NULL, floatVal(list_nth(entry, 4)), 8, es);
			ExplainPropertyFloat("Total Cost", NULL, floatVal(list_nth(entry, 5)), 8, es);
			ExplainPropertyFloat("Child Cost", NULL, floatVal(list_nth(entry, 6)), 8, es);
			ExplainPropertyFloat("Exact Policy Calls", NULL, floatVal(lsecond(stages)), 8, es);
			ExplainPropertyFloat("Completion Cost", NULL, floatVal(list_nth(stages, 5)), 8, es);
			ExplainPropertyText("Policy Implementation", implementation == NIL ?
				"original_pg_policy" : strVal(linitial(implementation)), es);
			if (implementation != NIL)
				ExplainPropertyInteger("Policy Source Plan", NULL, intVal(lsecond(implementation)), es);
		}
		else if (list_length(entry) >= 6)
		{
			ExplainPropertyText("Policy Implementation", strVal(list_nth(entry, 4)), es);
			ExplainPropertyInteger("Policy Source Plan", NULL, intVal(list_nth(entry, 5)), es);
		}
		ExplainCloseGroup("Candidate", NULL, true, es);
	}
	ExplainCloseGroup("AF Guard Costed Candidates", "AF Guard Costed Candidates", false, es);
}
