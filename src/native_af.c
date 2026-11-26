/*-------------------------------------------------------------------------
 *
 * native_af.c
 *	  AdmissionFirst (AF): checked access alternatives for tables protected
 *	  by row-level security, integrated into the PostgreSQL 16 planner.
 *
 * PostgreSQL applies a row-level-security policy as written: the policy
 * expression becomes a qualification of the protected table.  AF offers
 * additional, equivalent ways to evaluate a supported policy.  Every
 * candidate is checked against the admission conditions before PostgreSQL
 * compares its cost with the ordinary paths (native_af_admission.c); only
 * admitted candidates take part in the normal cost-based search.
 *
 * The access alternatives are custom scans:
 *
 *   AF Membership Keys        start from the keys the current user may read.
 *                             An InitPlan evaluates the policy's ACL subquery
 *                             at the executor's snapshot and returns a fresh
 *                             key array that drives the protected scan.
 *                             Duplicate keys cannot duplicate protected rows.
 *   AF Completed Hash Policy  check each row against a hash table of the
 *                             permitted keys, built once per execution.
 *   AF Policy Index           read a partial index whose predicate is exactly
 *                             the policy (native_af_partial.c).
 *   AF Exact Policy           complete the original policy check inside the
 *                             ordinary scan.
 *   AF Prefix Guard           bound a LIKE search by a leakproof prefix before
 *                             the exact policy check (native_af_guard.c).
 *
 * This file is organized in the following sections:
 *   - configuration parameters (native_af.*) and execution counters;
 *   - statement and policy-source checks shared by all candidates;
 *   - recognition of membership policies and their permitted-key sets;
 *   - row estimates, tracing and the join-path hook;
 *   - candidate paths: membership keys, policy indexes, completed hash;
 *   - experiment controls used for the component ablations;
 *   - native_af_add_paths(), which offers the admitted candidates;
 *   - plan creation, execution and EXPLAIN output of the custom scans;
 *   - the cost scope and the cache-aware cost adjustment;
 *   - shared checked inputs across joins (the "batch" functions);
 *   - bulk-read buffer rings for key-driven join inputs ("stream");
 *   - the run-time join-input filter ("AF Join Input Authorization
 *     Filter"), which drops ordinary join-input rows whose key cannot
 *     match a permitted row.
 *
 * native_af.mode selects the behavior per session: "native" leaves
 * PostgreSQL unchanged, "af" enables AdmissionFirst, and "index_priority"
 * is the fixed-rule baseline used in the evaluation.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/parallel.h"
#include "access/relation.h"
#include "access/htup_details.h"
#include "access/sysattr.h"
#include "access/table.h"
#include "catalog/index.h"
#include "common/relpath.h"
#include "catalog/pg_am_d.h"
#include "catalog/pg_class.h"
#include "catalog/pg_inherits.h"
#include "catalog/pg_namespace_d.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_opclass.h"
#include "catalog/pg_opfamily_d.h"
#include "catalog/pg_type_d.h"
#include "commands/explain.h"
#include "executor/executor.h"
#include "executor/instrument.h"
#include "executor/nodeSubplan.h"
#include "nodes/extensible.h"
#include "nodes/makefuncs.h"
#include "nodes/nodeFuncs.h"
#include "nodes/tidbitmap.h"
#include "miscadmin.h"
#include "optimizer/cost.h"
#include "optimizer/pathnode.h"
#include "optimizer/paths.h"
#include "optimizer/planner.h"
#include "optimizer/planmain.h"
#include "optimizer/optimizer.h"
#include "optimizer/restrictinfo.h"
#include "optimizer/subselect.h"
#include "optimizer/tlist.h"
#include "optimizer/native_af.h"
#include "optimizer/native_af_os_cache.h"
#include "optimizer/native_af_keyed.h"
#include "optimizer/native_af_binding.h"
#include "optimizer/native_af_partial.h"
#include "optimizer/native_af_sp.h"
#include "optimizer/native_af_guard.h"
#include "parser/parse_relation.h"
#include "parser/parsetree.h"
#include "rewrite/rewriteManip.h"
#include "storage/buf_internals.h"
#include "storage/fd.h"
#include "utils/array.h"
#include "utils/fmgroids.h"
#include "utils/fmgrtab.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/json.h"
#include "lib/stringinfo.h"
#include "utils/plancache.h"
#include "utils/rel.h"
#include "utils/selfuncs.h"
#include "utils/snapshot.h"
#include "utils/snapmgr.h"
#include "utils/syscache.h"

typedef enum NativeAfMode
{
	AF_NATIVE,
	AF_ADMISSION_FIRST,
	AF_INDEX_PRIORITY
} NativeAfMode;

typedef struct MembershipAccess
{
	RestrictInfo *key_filter;
	SubPlan    *initplan;
	/* Witness rows control the physical cap; distinct keys control probes. */
	double		acl_rows;
	double		distinct_keys;
	Cost		array_build_cost;
	Cost		array_dedup_cost;
} MembershipAccess;

typedef struct MembershipCandidate
{
	Index		rti;
	Var		   *key;
	Oid			equality;
	SubLink    *keys;
	RestrictInfo *policy;
	List	   *indexes;
	List	   *other_restrictions;
	MembershipAccess enumerated;
	MembershipAccess keyed;
	double		native_rows;
	bool		uses_current_user;
} MembershipCandidate;

typedef enum NativeAfExecution
{
	AF_EXEC_MEMBER_KEY,
	AF_EXEC_MEMBER_ENUM,
	AF_EXEC_POLICY_KEY,
	AF_EXEC_POLICY_ENUM,
	AF_EXEC_POLICY_CHECK,
	AF_EXEC_COMPLETED_HASH,
	AF_EXEC_FALLBACK,
	AF_EXEC_COUNT
} NativeAfExecution;

typedef struct AfScanState
{
	CustomScanState css;
	PlanState  *child;
	PlanState  *fast_child;
	PlanState  *fallback_child;
	bool		member_guard_pending;
	const char *fallback_reason;
	NativeAfExecution execution_family;
	bool		execution_counted;
} AfScanState;

static const CustomScanMethods af_prefilter_scan_methods;

static int	native_af_mode = AF_NATIVE;
static int	af_batch_depth;
static struct AfCostScope *af_cost_scope;
static struct AfCostScope *af_cost_share_target;
static void stream_membership_ready(PlannerInfo *root, Index rti,
									RangeTblEntry *rte,
									MembershipCandidate *candidate);
static bool native_af_cache_aware_cost = true;
static bool native_af_os_cache_cost = true;
static set_join_pathlist_hook_type native_af_previous_join_hook = NULL;
static void native_af_choice_join_paths(PlannerInfo *root, RelOptInfo *joinrel,
										RelOptInfo *outerrel, RelOptInfo *innerrel,
										JoinType jointype, JoinPathExtraData *extra);
static bool native_af_authorization_indexes = false;
static bool native_af_trace = false;

bool
native_af_planner_trace_enabled(void)
{
	return native_af_trace;
}

static int	native_af_max_authorized_keys = 1048576;

/*
 * Experiment controls (native_af.experiment_*), used for the component
 * ablations.  They restrict which admitted candidates are offered; they never
 * change what admission accepts.
 */
typedef enum AfExperimentForce
{
	AF_EXP_AUTO, AF_EXP_ORDINARY, AF_EXP_KEYS, AF_EXP_HASH,
	AF_EXP_GUARD_INDEX_ORIGINAL, AF_EXP_GUARD_SEQ_ORIGINAL,
	AF_EXP_GUARD_INDEX_HASH, AF_EXP_GUARD_SEQ_HASH,
	AF_EXP_HASH_SEQ, AF_EXP_HASH_INDEX, AF_EXP_HASH_BITMAP
} AfExperimentForce;
static int	native_af_experiment_force = AF_EXP_AUTO;
static bool native_af_experiment_publish_guard = true;
static bool native_af_experiment_publish_keys = true;
static bool native_af_experiment_publish_hash = true;
static bool native_af_experiment_publish_shared = true;
static const struct config_enum_entry af_experiment_forces[] = {
	{"auto", AF_EXP_AUTO, false},
	{"ordinary", AF_EXP_ORDINARY, false},
	{"keys", AF_EXP_KEYS, false},
	{"hash", AF_EXP_HASH, false},
	{"guard_index_original", AF_EXP_GUARD_INDEX_ORIGINAL, false},
	{"guard_seq_original", AF_EXP_GUARD_SEQ_ORIGINAL, false},
	{"guard_index_hash", AF_EXP_GUARD_INDEX_HASH, false},
	{"guard_seq_hash", AF_EXP_GUARD_SEQ_HASH, false},
	{"hash_seq", AF_EXP_HASH_SEQ, false},
	{"hash_index", AF_EXP_HASH_INDEX, false},
	{"hash_bitmap", AF_EXP_HASH_BITMAP, false},
	{NULL, 0, false}
};
static uint64 native_af_stream_index_executions = 0;
static uint64 native_af_stream_index_read_calls = 0;
static char *native_af_stream_index_setting = NULL;
static char *native_af_stream_index_reads_setting = NULL;
static uint64 native_af_stream_heap_executions = 0;
static char *native_af_stream_heap_setting = NULL;
static uint64 native_af_plans_built = 0;
static char *native_af_plans_setting = NULL;
static char *native_af_executions_setting = NULL;
static uint64 native_af_executions[AF_EXEC_COUNT];
static const struct config_enum_entry af_modes[] = {
	{"native", AF_NATIVE, false},
	{"af", AF_ADMISSION_FIRST, false},
	{"index_priority", AF_INDEX_PRIORITY, false},
	{NULL, 0, false}
};

static Plan *plan_membership_path(PlannerInfo *root, RelOptInfo *rel,
								  CustomPath *path, List *target, List *clauses,
								  List *children);
static Plan *plan_exact_path(PlannerInfo *root, RelOptInfo *rel,
							 CustomPath *path, List *target, List *clauses,
							 List *children);
static Node *create_membership_scan(CustomScan *scan);
static Node *create_exact_scan(CustomScan *scan);
static Plan *plan_partial_path(PlannerInfo *root, RelOptInfo *rel,
							   CustomPath *path, List *target, List *clauses,
							   List *children);
static Node *create_partial_scan(CustomScan *scan);
static void begin_partial_scan(CustomScanState *node, EState *estate, int eflags);
static void explain_partial_scan(CustomScanState *node, List *ancestors, ExplainState *es);
static void begin_exact_scan(CustomScanState *node, EState *estate, int eflags);
static void explain_exact_scan(CustomScanState *node, List *ancestors, ExplainState *es);
static Plan *plan_completed_hash_path(PlannerInfo *root, RelOptInfo *rel,
									  CustomPath *path, List *target, List *clauses,
									  List *children);
static Node *create_completed_hash_scan(CustomScan *scan);
static void begin_completed_hash_scan(CustomScanState *node, EState *estate, int eflags);
static void explain_completed_hash_scan(CustomScanState *node, List *ancestors, ExplainState *es);
static void begin_membership_scan(CustomScanState *node, EState *estate,
								  int eflags);
static TupleTableSlot *exec_membership_scan(CustomScanState *node);
static void end_membership_scan(CustomScanState *node);
static void rescan_membership_scan(CustomScanState *node);
static void explain_membership_scan(CustomScanState *node, List *ancestors,
									ExplainState *es);

static const CustomPathMethods membership_path_methods = {
	.CustomName = "AF Membership Keys",
	.PlanCustomPath = plan_membership_path,
};
static const CustomScanMethods membership_scan_methods = {
	.CustomName = "AF Membership Keys",
	.CreateCustomScanState = create_membership_scan,
};
static const CustomExecMethods membership_exec_methods = {
	.CustomName = "AF Membership Keys",
	.BeginCustomScan = begin_membership_scan,
	.ExecCustomScan = exec_membership_scan,
	.EndCustomScan = end_membership_scan,
	.ReScanCustomScan = rescan_membership_scan,
	.ExplainCustomScan = explain_membership_scan,
};

static const CustomPathMethods exact_path_methods = {
	.CustomName = "AF Exact Policy",
	.PlanCustomPath = plan_exact_path,
};
static const CustomScanMethods exact_scan_methods = {
	.CustomName = "AF Exact Policy",
	.CreateCustomScanState = create_exact_scan,
};
static const CustomExecMethods exact_exec_methods = {
	.CustomName = "AF Exact Policy",
	.BeginCustomScan = begin_exact_scan,
	.ExecCustomScan = exec_membership_scan,
	.EndCustomScan = end_membership_scan,
	.ReScanCustomScan = rescan_membership_scan,
	.ExplainCustomScan = explain_exact_scan,
};

/* This path completes the original RLS policy inside the ordinary scan. */
static const CustomPathMethods completed_hash_path_methods = {
	.CustomName = "AF Completed Hash Policy",
	.PlanCustomPath = plan_completed_hash_path,
};
static const CustomScanMethods completed_hash_scan_methods = {
	.CustomName = "AF Completed Hash Policy",
	.CreateCustomScanState = create_completed_hash_scan,
};
static const CustomExecMethods completed_hash_exec_methods = {
	.CustomName = "AF Completed Hash Policy",
	.BeginCustomScan = begin_completed_hash_scan,
	.ExecCustomScan = exec_membership_scan,
	.EndCustomScan = end_membership_scan,
	.ReScanCustomScan = rescan_membership_scan,
	.ExplainCustomScan = explain_completed_hash_scan,
};

static const CustomPathMethods partial_path_methods = {
	.CustomName = "AF Policy Index",
	.PlanCustomPath = plan_partial_path,
};
static const CustomScanMethods partial_scan_methods = {
	.CustomName = "AF Policy Index",
	.CreateCustomScanState = create_partial_scan,
};
static const CustomExecMethods partial_exec_methods = {
	.CustomName = "AF Policy Index",
	.BeginCustomScan = begin_partial_scan,
	.ExecCustomScan = exec_membership_scan,
	.EndCustomScan = end_membership_scan,
	.ReScanCustomScan = rescan_membership_scan,
	.ExplainCustomScan = explain_partial_scan,
};

/* -------------------------------------------------------------------------
 * Configuration parameters and per-backend counters
 *
 * Assign hooks invalidate cached plans when a setting changes what may be
 * planned; the show hooks expose the counters used by the tests.
 * -------------------------------------------------------------------------
 */

static void
assign_af_mode(int new_mode, void *extra)
{
	if (native_af_mode != new_mode)
		ResetPlanCache();
}

static void
assign_max_authorized_keys(int maximum, void *extra)
{
	if (native_af_max_authorized_keys != maximum)
		ResetPlanCache();
}

static void
assign_authorization_indexes(bool enabled, void *extra)
{
	if (native_af_authorization_indexes != enabled)
		ResetPlanCache();
}

/* A changed experimental policy must not reuse an earlier prepared choice. */
static void
assign_experiment_force(int force, void *extra)
{
	if (native_af_experiment_force != force)
		ResetPlanCache();
}

static void
assign_experiment_guard(bool enabled, void *extra)
{
	if (native_af_experiment_publish_guard != enabled)
		ResetPlanCache();
}

static void
assign_experiment_keys(bool enabled, void *extra)
{
	if (native_af_experiment_publish_keys != enabled)
		ResetPlanCache();
}

static void
assign_experiment_hash(bool enabled, void *extra)
{
	if (native_af_experiment_publish_hash != enabled)
		ResetPlanCache();
}

static void
assign_experiment_shared(bool enabled, void *extra)
{
	if (native_af_experiment_publish_shared != enabled)
		ResetPlanCache();
}

static void
assign_os_cache_cost(bool enabled, void *extra)
{
	if (native_af_os_cache_cost != enabled)
		ResetPlanCache();
}

static void
assign_cache_aware_cost(bool enabled, void *extra)
{
	if (native_af_cache_aware_cost != enabled)
		ResetPlanCache();
}

/* Count actual lazy heap-ring allocations, once per executed IndexScan. */
static const char *
show_af_stream_index_executions(void)
{
	return psprintf(UINT64_FORMAT, native_af_stream_index_executions);
}

static const char *
show_af_stream_index_read_calls(void)
{
	return psprintf(UINT64_FORMAT, native_af_stream_index_read_calls);
}

void
native_af_note_stream_index_execution(void)
{
	native_af_stream_index_executions++;
}

void
native_af_note_stream_index_read(void)
{
	native_af_stream_index_read_calls++;
}

static const char *
show_af_stream_heap_executions(void)
{
	return psprintf(UINT64_FORMAT, native_af_stream_heap_executions);
}

bool
native_af_stream_execution_allowed(void)
{
	return native_af_mode == AF_ADMISSION_FIRST;
}

void
native_af_note_stream_heap_execution(void)
{
	native_af_stream_heap_executions++;
}

static const char *
show_af_plans(void)
{
	return psprintf(UINT64_FORMAT, native_af_plans_built);
}

static const char *
show_af_executions(void)
{
	return psprintf("{\"lookup_authorized_key\":" UINT64_FORMAT
					",\"enumerate_authorized_keys\":" UINT64_FORMAT
					",\"lookup_policy_index\":" UINT64_FORMAT
					",\"enumerate_policy_index\":" UINT64_FORMAT
					",\"exact_policy_check\":" UINT64_FORMAT
					",\"completed_hash_policy\":" UINT64_FORMAT
					",\"native_fallback\":" UINT64_FORMAT "}",
					native_af_executions[AF_EXEC_MEMBER_KEY],
					native_af_executions[AF_EXEC_MEMBER_ENUM],
					native_af_executions[AF_EXEC_POLICY_KEY],
					native_af_executions[AF_EXEC_POLICY_ENUM],
					native_af_executions[AF_EXEC_POLICY_CHECK],
					native_af_executions[AF_EXEC_COMPLETED_HASH],
					native_af_executions[AF_EXEC_FALLBACK]);
}

void
native_af_note_planning(void)
{
	native_af_plans_built++;

}

void
native_af_initialize(void)
{
	native_af_guard_initialize();
	native_af_previous_join_hook = set_join_pathlist_hook;
	set_join_pathlist_hook = native_af_choice_join_paths;
	DefineCustomBoolVariable("native_af.os_cache_cost",
							 "Uses operating-system page-cache residency of large relations in AF costs.",
							 NULL, &native_af_os_cache_cost, true, PGC_USERSET, 0,
							 NULL, assign_os_cache_cost, NULL);
	DefineCustomBoolVariable("native_af.cache_aware_cost",
							 "Accounts for sampled resident pages when costing AF alternatives.",
							 NULL, &native_af_cache_aware_cost, true, PGC_USERSET, 0,
							 NULL, assign_cache_aware_cost, NULL);
	DefineCustomEnumVariable("native_af.mode",
							 "Selects the native row-security optimization strategy.",
							 NULL, &native_af_mode, AF_NATIVE, af_modes,
							 PGC_USERSET, 0, NULL, assign_af_mode, NULL);
	DefineCustomBoolVariable("native_af.authorization_indexes",
							 "Enables explicit AF and IndexPriority paths for matching partial indexes.",
							 NULL, &native_af_authorization_indexes, false,
							 PGC_SUSET, 0, NULL, assign_authorization_indexes, NULL);
	DefineCustomEnumVariable("native_af.experiment_force",
							 "Experiment control: offers only one admitted candidate family at the protected table.",
							 NULL, &native_af_experiment_force, AF_EXP_AUTO, af_experiment_forces,
							 PGC_USERSET, 0, NULL, assign_experiment_force, NULL);
	DefineCustomBoolVariable("native_af.experiment_publish_guard",
							 "Experiment control: offers admitted prefix-guard candidates.", NULL,
							 &native_af_experiment_publish_guard, true, PGC_USERSET, 0,
							 NULL, assign_experiment_guard, NULL);
	DefineCustomBoolVariable("native_af.experiment_publish_keys",
							 "Experiment control: offers admitted membership and policy-index key paths.", NULL,
							 &native_af_experiment_publish_keys, true, PGC_USERSET, 0,
							 NULL, assign_experiment_keys, NULL);
	DefineCustomBoolVariable("native_af.experiment_publish_hash",
							 "Experiment control: offers independent completed-hash paths; guard candidates keep their checks.", NULL,
							 &native_af_experiment_publish_hash, true, PGC_USERSET, 0,
							 NULL, assign_experiment_hash, NULL);
	DefineCustomBoolVariable("native_af.experiment_publish_shared",
							 "Experiment control: compares the separately planned shared-input alternative.", NULL,
							 &native_af_experiment_publish_shared, true, PGC_USERSET, 0,
							 NULL, assign_experiment_shared, NULL);
	DefineCustomBoolVariable("native_af.trace",
							 "Reports admitted path families during optimization.",
							 NULL, &native_af_trace, false, PGC_USERSET, 0,
							 NULL, NULL, NULL);
	DefineCustomStringVariable("native_af.plans_built",
							   "Number of standard planner invocations in this backend.",
							   NULL, &native_af_plans_setting, "0", PGC_INTERNAL,
							   GUC_NOT_IN_SAMPLE | GUC_DISALLOW_IN_FILE,
							   NULL, NULL, show_af_plans);
	DefineCustomStringVariable("native_af.stream_index_executions",
							   "Number of actual AF scan-owned B-tree ring allocations in this backend.",
							   NULL, &native_af_stream_index_setting, "0", PGC_INTERNAL,
							   GUC_NOT_IN_SAMPLE | GUC_DISALLOW_IN_FILE,
							   NULL, NULL, show_af_stream_index_executions);
	DefineCustomStringVariable("native_af.stream_index_read_calls",
							   "Number of successful explicit AF B-tree strategy read calls in this backend.",
							   NULL, &native_af_stream_index_reads_setting, "0", PGC_INTERNAL,
							   GUC_NOT_IN_SAMPLE | GUC_DISALLOW_IN_FILE,
							   NULL, NULL, show_af_stream_index_read_calls);
	DefineCustomStringVariable("native_af.stream_heap_executions",
							   "Number of actual AF ordinary-source heap-ring allocations in this backend.",
							   NULL, &native_af_stream_heap_setting, "0", PGC_INTERNAL,
							   GUC_NOT_IN_SAMPLE | GUC_DISALLOW_IN_FILE,
							   NULL, NULL, show_af_stream_heap_executions);
	DefineCustomStringVariable("native_af.path_executions",
							   "First actual executions of AF nodes, grouped by path family.",
							   NULL, &native_af_executions_setting, "", PGC_INTERNAL,
							   GUC_NOT_IN_SAMPLE | GUC_DISALLOW_IN_FILE,
							   NULL, NULL, show_af_executions);
	DefineCustomIntVariable("native_af.max_authorized_keys",
							"Bounds a fresh authorization-key array before exact fallback.",
							NULL, &native_af_max_authorized_keys, 1048576, 1, 16777216,
							PGC_USERSET, 0, NULL, assign_max_authorized_keys, NULL);
	RegisterCustomScanMethods(&membership_scan_methods);
	RegisterCustomScanMethods(&af_prefilter_scan_methods);
	RegisterCustomScanMethods(&exact_scan_methods);
	RegisterCustomScanMethods(&partial_scan_methods);
}

/* -------------------------------------------------------------------------
 * Statement and policy-source checks shared by all candidates
 *
 * AF candidates are serial and read-only.  The helpers below validate the
 * statement, the protected relation, the principal and the ACL expressions
 * before any candidate is generated.
 * -------------------------------------------------------------------------
 */

bool
native_af_readonly_statement(PlannerInfo *root)
{
	for (; root != NULL; root = root->parent_root)
	{
		Query	   *parse = root->parse;

		if (parse->commandType != CMD_SELECT || parse->resultRelation != 0 ||
			parse->rowMarks != NIL || parse->hasModifyingCTE)
			return false;
	}
	return true;
}

/* A query may consider parallel PG paths while these AF paths stay serial. */
bool
native_af_allow_serial_candidates(void)
{
	return native_af_mode == AF_ADMISSION_FIRST && !IsParallelWorker();
}

/* Only AF's generated key-array source uses this planner-local scope. */
bool
native_af_serial_acl_source(PlannerInfo *root)
{
	for (; root != NULL; root = root->parent_root)
		if (root->native_af_serial_acl_source)
			return true;
	return false;
}

/* Match the source binder's physical grammar before publishing a variant. */
bool
native_af_serial_plan(Plan *plan)
{
	List	   *children = NIL;
	ListCell   *cell;

	if (plan == NULL)
		return true;
	if (plan->parallel_aware || plan->initPlan != NIL)
		return false;
	switch (nodeTag(plan))
	{
		case T_Append:
			children = castNode(Append, plan)->appendplans;
			break;
		case T_MergeAppend:
			children = castNode(MergeAppend, plan)->mergeplans;
			break;
		case T_BitmapAnd:
			children = castNode(BitmapAnd, plan)->bitmapplans;
			break;
		case T_BitmapOr:
			children = castNode(BitmapOr, plan)->bitmapplans;
			break;
		case T_SeqScan:
		case T_BitmapHeapScan:
		case T_TidScan:
		case T_TidRangeScan:
		case T_IndexScan:
		case T_IndexOnlyScan:
		case T_BitmapIndexScan:
		case T_Result:
		case T_NestLoop:
		case T_MergeJoin:
		case T_HashJoin:
		case T_Material:
		case T_Memoize:
		case T_Sort:
		case T_IncrementalSort:
		case T_Group:
		case T_Agg:
		case T_Unique:
		case T_Hash:
		case T_Limit:
			break;
		default:
			/* In particular, Gather/GatherMerge are not AF source bindings. */
			return false;
	}
	foreach(cell, children)
		if (!native_af_serial_plan((Plan *) lfirst(cell)))
		return false;
	return native_af_serial_plan(outerPlan(plan)) &&
		native_af_serial_plan(innerPlan(plan));
}

static bool
nonserial_policy_source(Node *node, PlannerInfo *root)
{
	if (node == NULL)
		return false;
	if (IsA(node, SubPlan))
	{
		SubPlan    *subplan = castNode(SubPlan, node);

		if (subplan->plan_id <= 0 || subplan->plan_id > list_length(root->glob->subplans) ||
			!native_af_serial_plan(planner_subplan_get_plan(root, subplan)))
			return true;
	}
	return expression_tree_walker(node, nonserial_policy_source, root);
}

bool
native_af_serial_policy(PlannerInfo *root, Node *expression)
{
	return !nonserial_policy_source(expression, root);
}

/* Do not reject leader execution merely because another branch uses Gather. */
void
native_af_check_serial_scan(CustomScan *scan, EState *estate)
{
	ListCell   *cell;

	/* Native/IP retain their prior implementation and configuration boundary. */
	if (native_af_mode != AF_ADMISSION_FIRST)
		return;
	if (IsParallelWorker() || estate == NULL || !IsMVCCSnapshot(estate->es_snapshot) ||
		scan->scan.plan.parallel_aware || scan->scan.plan.parallel_safe)
		elog(ERROR, "AF serial scan cannot execute in a parallel worker");
	foreach(cell, scan->custom_plans)
		if (!native_af_serial_plan((Plan *) lfirst(cell)))
		elog(ERROR, "AF serial scan has a nonserial physical child");
}

static bool
authorization_index_name(const char *name)
{
	const char *prefix = "native_af_auth_";

	return native_af_authorization_indexes &&
		strncmp(name, prefix, strlen(prefix)) == 0;
}

/*
 * Keep each physical index in PostgreSQL's ordinary index list in every
 * mode. AF and IndexPriority may also generate explicit checked paths for
 * a named exact-policy index, after the normal catalog and validity checks.
 */
void
native_af_collect_index(PlannerInfo *root, IndexOptInfo *index, const char *name)
{
	if (native_af_mode == AF_NATIVE ||
		!authorization_index_name(name) || index->indpred == NIL ||
		index->unique || index->relam != BTREE_AM_OID)
		return;

	root->native_af_private_indexes = lcons(index, root->native_af_private_indexes);
}

/* Only built-in heap relations, with no inherited or sampled rows. */
static bool
plain_heap(RangeTblEntry *rte)
{
	HeapTuple	entry;
	bool		is_heap;

	if (rte->rtekind != RTE_RELATION || rte->relkind != RELKIND_RELATION ||
		rte->tablesample != NULL || (rte->inh && has_subclass(rte->relid)))
		return false;

	entry = SearchSysCache1(RELOID, ObjectIdGetDatum(rte->relid));
	if (!HeapTupleIsValid(entry))
		return false;
	is_heap = ((Form_pg_class) GETSTRUCT(entry))->relam == HEAP_TABLE_AM_OID;
	ReleaseSysCache(entry);
	return is_heap;
}

static bool
builtin_equality(OpExpr *expr)
{
	HeapTuple	entry;
	Form_pg_operator op;
	bool		valid;

	if (expr->opretset || expr->opresulttype != BOOLOID ||
		list_length(expr->args) != 2)
		return false;

	entry = SearchSysCache1(OPEROID, ObjectIdGetDatum(expr->opno));
	if (!HeapTupleIsValid(entry))
		return false;
	op = (Form_pg_operator) GETSTRUCT(entry);
	valid = op->oprnamespace == PG_CATALOG_NAMESPACE &&
		(op->oprcode == F_INT8EQ || op->oprcode == F_INT4EQ ||
		 op->oprcode == F_TEXTEQ);
	ReleaseSysCache(entry);
	return valid;
}

/* CURRENT_USER is evaluated by the copied ACL source at execution time. */
static bool
current_user_name(Node *node)
{
	SQLValueFunction *value;

	if (!IsA(node, SQLValueFunction))
		return false;
	value = castNode(SQLValueFunction, node);
	return value->op == SVFOP_CURRENT_USER && value->type == NAMEOID &&
		value->typmod == -1;
}

static bool
current_user_principal(OpExpr *expression)
{
	Node	   *column;
	Node	   *principal;
	HeapTuple	tuple;
	Form_pg_operator operation;
	bool		valid;

	if (expression->opretset || expression->opresulttype != BOOLOID ||
		list_length(expression->args) != 2)
		return false;
	column = linitial(expression->args);
	principal = lsecond(expression->args);
	if (current_user_name(column))
	{
		column = lsecond(expression->args);
		principal = linitial(expression->args);
	}
	if (!IsA(column, Var) || !current_user_name(principal) ||
		castNode(Var, column)->vartype != NAMEOID ||
		castNode(Var, column)->varlevelsup != 0 ||
		castNode(Var, column)->varattno <= 0 ||
		!bms_is_empty(castNode(Var, column)->varnullingrels))
		return false;
	tuple = SearchSysCache1(OPEROID, ObjectIdGetDatum(expression->opno));
	if (!HeapTupleIsValid(tuple))
		return false;
	operation = (Form_pg_operator) GETSTRUCT(tuple);
	valid = operation->oprnamespace == PG_CATALOG_NAMESPACE &&
		operation->oprcode == F_NAMEEQ && operation->oprleft == NAMEOID &&
		operation->oprright == NAMEOID &&
		(!OidIsValid(expression->opfuncid) || expression->opfuncid == F_NAMEEQ);
	ReleaseSysCache(tuple);
	return valid;
}

static bool
uses_current_user(Node *node, void *context)
{
	if (node == NULL)
		return false;
	if (current_user_name(node))
		return true;
	return expression_tree_walker(node, uses_current_user, context);
}

/* Defer view-owner and other checkAsUser contexts to ordinary RLS. */
static bool
direct_principal_permissions(Query *query, RangeTblEntry *rte)
{
	RTEPermissionInfo *permissions;

	if (rte->perminfoindex == 0 ||
		rte->perminfoindex > list_length(query->rteperminfos))
		return false;
	permissions = getRTEPermissionInfo(query->rteperminfos, rte);
	return permissions->relid == rte->relid &&
		permissions->requiredPerms == ACL_SELECT &&
		!OidIsValid(permissions->checkAsUser);
}

/*
 * Hoisting CURRENT_USER requires a principal stable for this statement.
 * User routines, configuration mutators, overridden permissions and hidden
 * domain/I/O evaluation remain on ordinary RLS. Volatility labels alone are
 * insufficient: user code may label a role-changing function IMMUTABLE.
 */
static bool
principal_preserving_type(Oid type)
{
	return type == INT8OID || type == INT4OID || type == TEXTOID ||
		type == NAMEOID || type == BOOLOID;
}

static bool
principal_preserving_function(Oid function)
{
	/* Closed scalar operations: no array/record/polymorphic callbacks. */
	switch (function)
	{
		case F_INT8EQ:
		case F_INT8NE:
		case F_INT8LT:
		case F_INT8LE:
		case F_INT8GT:
		case F_INT8GE:
		case F_INT4EQ:
		case F_INT4NE:
		case F_INT4LT:
		case F_INT4LE:
		case F_INT4GT:
		case F_INT4GE:
		case F_TEXTEQ:
		case F_TEXTNE:
		case F_NAMEEQ:
		case F_NAMENE:
		case F_NAMELT:
		case F_NAMELE:
		case F_NAMEGT:
		case F_NAMEGE:
		case F_BOOLEQ:
		case F_BOOLNE:
		case F_BOOLLT:
		case F_BOOLLE:
		case F_BOOLGT:
		case F_BOOLGE:
			return true;
		default:
			return false;
	}
}

/* No custom AM/opclass or hidden expression-index evaluation in this scope. */
static bool
principal_preserving_indexes(Oid relation_oid)
{
	Relation	heap = table_open(relation_oid, AccessShareLock);
	List	   *indexes = RelationGetIndexList(heap);
	ListCell   *cell;
	bool		valid = true;

	foreach(cell, indexes)
	{
		Relation	index = index_open(lfirst_oid(cell), AccessShareLock);
		int			column;

		if (index->rd_rel->relam != BTREE_AM_OID ||
			RelationGetIndexExpressions(index) != NIL ||
			RelationGetIndexPredicate(index) != NIL)
			valid = false;
		for (column = 1; valid && column <= index->rd_index->indnkeyatts; column++)
		{
			Oid			class_oid = get_index_column_opclass(RelationGetRelid(index), column);
			HeapTuple	tuple = SearchSysCache1(CLAOID, ObjectIdGetDatum(class_oid));
			Form_pg_opclass operation;
			const char *name;

			if (!HeapTupleIsValid(tuple))
			{
				valid = false;
				break;
			}
			operation = (Form_pg_opclass) GETSTRUCT(tuple);
			name = NameStr(operation->opcname);
			valid = operation->opcnamespace == PG_CATALOG_NAMESPACE &&
				operation->opcmethod == BTREE_AM_OID &&
				((operation->opcintype == INT8OID && strcmp(name, "int8_ops") == 0) ||
				 (operation->opcintype == INT4OID && strcmp(name, "int4_ops") == 0) ||
				 (operation->opcintype == TEXTOID && strcmp(name, "text_ops") == 0) ||
				 (operation->opcintype == NAMEOID && strcmp(name, "name_ops") == 0) ||
				 (operation->opcintype == BOOLOID && strcmp(name, "bool_ops") == 0));
			ReleaseSysCache(tuple);
		}
		index_close(index, AccessShareLock);
		if (!valid)
			break;
	}
	list_free(indexes);
	table_close(heap, AccessShareLock);
	return valid;
}

static bool
principal_changing_expression(Node *node, void *context)
{
	if (node == NULL)
		return false;
	if (IsA(node, Query))
	{
		Query	   *query = castNode(Query, node);
		ListCell   *cell;
		List	   *ordering = list_concat(list_copy(query->sortClause),
										   list_copy(query->groupClause));

		ordering = list_concat(ordering, list_copy(query->distinctClause));
		foreach(cell, ordering)
		{
			SortGroupClause *clause = lfirst_node(SortGroupClause, cell);

			if (!principal_preserving_function(get_opcode(clause->eqop)) ||
				(OidIsValid(clause->sortop) &&
				 !principal_preserving_function(get_opcode(clause->sortop))))
				return true;
		}
		return query_tree_walker(query, principal_changing_expression, context,
								 QTW_EXAMINE_RTES_BEFORE);
	}
	if (IsA(node, RangeTblEntry))
	{
		RangeTblEntry *rte = castNode(RangeTblEntry, node);

		if (rte->rtekind == RTE_RELATION)
			return !plain_heap(rte) || !principal_preserving_indexes(rte->relid);
		return rte->rtekind != RTE_JOIN && rte->rtekind != RTE_SUBQUERY &&
			rte->rtekind != RTE_CTE && rte->rtekind != RTE_VALUES &&
			rte->rtekind != RTE_RESULT;
	}
	if (IsA(node, SQLValueFunction))
		return !current_user_name(node);
	if (IsA(node, Var))
		return !principal_preserving_type(castNode(Var, node)->vartype);
	if (IsA(node, Const))
		return !principal_preserving_type(castNode(Const, node)->consttype);
	if (IsA(node, Param))
	{
		Param	   *parameter = castNode(Param, node);

		return parameter->paramkind != PARAM_EXTERN ||
			!principal_preserving_type(parameter->paramtype);
	}
	if (IsA(node, RelabelType) &&
		!principal_preserving_type(castNode(RelabelType, node)->resulttype))
		return true;
	if (IsA(node, CaseExpr) &&
		!principal_preserving_type(castNode(CaseExpr, node)->casetype))
		return true;
	if (IsA(node, CaseTestExpr) &&
		!principal_preserving_type(castNode(CaseTestExpr, node)->typeId))
		return true;
	if (IsA(node, CoalesceExpr) &&
		!principal_preserving_type(castNode(CoalesceExpr, node)->coalescetype))
		return true;
	if (IsA(node, FuncExpr) &&
		!principal_preserving_function(castNode(FuncExpr, node)->funcid))
		return true;
	if ((IsA(node, OpExpr) || IsA(node, DistinctExpr) || IsA(node, NullIfExpr)) &&
		!principal_preserving_function(get_opcode(((OpExpr *) node)->opno)))
		return true;
	if (IsA(node, ScalarArrayOpExpr))
	{
		ScalarArrayOpExpr *operation = castNode(ScalarArrayOpExpr, node);

		if (!principal_preserving_function(get_opcode(operation->opno)) ||
			(OidIsValid(operation->hashfuncid) &&
			 !principal_preserving_function(operation->hashfuncid)))
			return true;
	}
	if (IsA(node, Aggref) || IsA(node, WindowFunc) || IsA(node, RowCompareExpr) ||
		IsA(node, CoerceViaIO) || IsA(node, CoerceToDomain) || IsA(node, MinMaxExpr) ||
		IsA(node, NextValueExpr) || IsA(node, SubscriptingRef) || IsA(node, XmlExpr) ||
		IsA(node, SubPlan) || IsA(node, AlternativeSubPlan) || IsA(node, ArrayExpr) ||
		IsA(node, RowExpr) || IsA(node, ArrayCoerceExpr) || IsA(node, ConvertRowtypeExpr))
		return true;
	return expression_tree_walker(node, principal_changing_expression, context);
}

/*
 * Keep the ACL side in a small read-only grammar.  In particular, there is
 * no user code whose evaluation count or order could change when the ACL
 * is scanned once instead of being probed for each protected row.
 */
static bool
safe_acl_expression(Node *node)
{
	if (node == NULL || IsA(node, Const))
		return true;
	if (IsA(node, Var))
	{
		Var		   *var = castNode(Var, node);

		return var->varlevelsup == 0 && var->varattno > 0;
	}
	if (IsA(node, RelabelType))
		return safe_acl_expression((Node *) castNode(RelabelType, node)->arg);
	if (IsA(node, OpExpr))
	{
		OpExpr	   *op = castNode(OpExpr, node);

		if (current_user_principal(op))
			return true;
		return builtin_equality(op) &&
			safe_acl_expression(linitial(op->args)) &&
			safe_acl_expression(lsecond(op->args));
	}
	if (IsA(node, BoolExpr))
	{
		BoolExpr   *expr = castNode(BoolExpr, node);
		ListCell   *lc;

		if (expr->boolop != AND_EXPR)
			return false;
		foreach(lc, expr->args)
			if (!safe_acl_expression(lfirst(lc)))
			return false;
		return true;
	}
	return false;
}

static bool
safe_acl_join(Node *node)
{
	JoinExpr   *join;

	if (IsA(node, RangeTblRef))
		return true;
	if (!IsA(node, JoinExpr))
		return false;
	join = castNode(JoinExpr, node);
	return join->jointype == JOIN_INNER &&
		safe_acl_join(join->larg) && safe_acl_join(join->rarg) &&
		safe_acl_expression(join->quals);
}

static Var *
as_key(Node *node, int levelsup)
{
	Var		   *var;

	if (!IsA(node, Var))
		return NULL;
	var = castNode(Var, node);
	if (var->vartype != INT8OID || var->varattno <= 0 ||
		var->varlevelsup != levelsup || !bms_is_empty(var->varnullingrels))
		return NULL;
	return var;
}

/* -------------------------------------------------------------------------
 * Membership policies: recognize the ACL subquery and derive the key set
 * -------------------------------------------------------------------------
 */

/* Derive the key-set query and its binding before any AF cost is computed. */
void
native_af_prepare_membership(PlannerInfo *root, Index rti, RangeTblEntry *rte)
{
	SubLink    *policy;
	Query	   *acl;
	ListCell   *lc;
	List	   *residual = NIL;
	Var		   *key = NULL;
	Var		   *acl_key = NULL;
	Oid			equality = InvalidOid;
	MembershipCandidate *candidate;
	List	   *terms;
	bool		uses_principal;

	if (native_af_mode == AF_NATIVE ||
		(native_af_mode == AF_ADMISSION_FIRST && IsParallelWorker()) ||
		(root->glob->parallelModeOK && !native_af_allow_serial_candidates()) ||
		list_length(rte->securityQuals) != 1 || !native_af_readonly_statement(root) ||
		!plain_heap(rte) || !IsA(linitial(rte->securityQuals), SubLink))
		return;

	policy = castNode(SubLink, linitial(rte->securityQuals));
	if (policy->subLinkType != EXISTS_SUBLINK || policy->testexpr != NULL ||
		!IsA(policy->subselect, Query))
		return;
	acl = castNode(Query, policy->subselect);
	if (acl->commandType != CMD_SELECT || acl->hasAggs || acl->hasSubLinks ||
		acl->hasTargetSRFs || acl->hasWindowFuncs || acl->hasModifyingCTE ||
		acl->setOperations || acl->cteList || acl->distinctClause ||
		acl->groupClause || acl->groupingSets || acl->havingQual ||
		acl->windowClause || acl->sortClause || acl->limitCount ||
		acl->limitOffset || acl->rowMarks || acl->jointree == NULL ||
		acl->jointree->quals == NULL || list_length(acl->targetList) != 1 ||
		!IsA(linitial_node(TargetEntry, acl->targetList)->expr, Const))
		return;
	foreach(lc, acl->rtable)
	{
		RangeTblEntry *source = lfirst_node(RangeTblEntry, lc);

		if (source->rtekind == RTE_JOIN)
			continue;
		if (!plain_heap(source) || source->securityQuals != NIL)
			return;
	}
	foreach(lc, acl->jointree->fromlist)
		if (!safe_acl_join(lfirst(lc)))
		return;

	terms = make_ands_implicit((Expr *) acl->jointree->quals);
	foreach(lc, terms)
	{
		Node	   *term = lfirst(lc);

		if (safe_acl_expression(term))
		{
			residual = lappend(residual, term);
			continue;
		}
		if (key != NULL || !IsA(term, OpExpr))
			return;
		{
			OpExpr	   *op = castNode(OpExpr, term);

			if (!builtin_equality(op) || get_opcode(op->opno) != F_INT8EQ)
				return;
			key = as_key(linitial(op->args), 1);
			acl_key = as_key(lsecond(op->args), 0);
			if (key == NULL || acl_key == NULL)
			{
				key = as_key(lsecond(op->args), 1);
				acl_key = as_key(linitial(op->args), 0);
			}
			if (key == NULL || key->varno != rti || acl_key == NULL ||
				rt_fetch(acl_key->varno, acl->rtable)->rtekind != RTE_RELATION)
				return;
			equality = op->opno;
		}
	}
	if (key == NULL)
		return;
	uses_principal = uses_current_user((Node *) acl->jointree, NULL);
	if (uses_principal)
	{
		PlannerInfo *scope;

		if (!root->parse->hasRowSecurity ||
			!direct_principal_permissions(root->parse, rte))
			return;
		for (scope = root; scope != NULL; scope = scope->parent_root)
			if (principal_changing_expression((Node *) scope->parse, NULL))
				return;
		foreach(lc, acl->rtable)
		{
			RangeTblEntry *source = lfirst_node(RangeTblEntry, lc);

			if (source->rtekind == RTE_RELATION &&
				!direct_principal_permissions(acl, source))
				return;
		}
	}

	candidate = palloc0(sizeof(*candidate));
	candidate->uses_current_user = uses_principal;
	candidate->rti = rti;
	candidate->key = copyObject(key);
	candidate->key->varlevelsup = 0;
	candidate->equality = equality;
	candidate->keys = makeNode(SubLink);
	candidate->keys->subLinkType = ARRAY_SUBLINK;
	candidate->keys->subselect = (Node *) copyObject(acl);
	acl = castNode(Query, candidate->keys->subselect);
	acl->jointree->quals = (Node *) make_ands_explicit(copyObject(residual));
	acl->targetList = list_make1(makeTargetEntry((Expr *) copyObject(acl_key),
												 1, NULL, false));
	root->native_af_membership = lappend(root->native_af_membership, candidate);
	stream_membership_ready(root, rti, rte, candidate);
}

/* Match the primary index before admitting an enumeration candidate. */
static List *
usable_key_indexes(RelOptInfo *rel, AttrNumber attno)
{
	List	   *indexes = NIL;
	ListCell   *lc;

	foreach(lc, rel->indexlist)
	{
		IndexOptInfo *index = lfirst_node(IndexOptInfo, lc);

		if (index->relam == BTREE_AM_OID && index->unique &&
			index->immediate && index->indpred == NIL &&
			index->nkeycolumns == 1 && index->indexkeys[0] == attno &&
			index->opfamily[0] == INTEGER_BTREE_FAM_OID &&
			index->amsearcharray)
			indexes = lappend(indexes, index);
	}
	return indexes;
}

static bool
has_index_clause(IndexPath *path, RestrictInfo *qual)
{
	ListCell   *lc;

	foreach(lc, path->indexclauses)
		if (lfirst_node(IndexClause, lc)->rinfo == qual &&
			!lfirst_node(IndexClause, lc)->lossy)
		return true;
	return false;
}

static MembershipCandidate *
find_membership(PlannerInfo *root, RelOptInfo *rel)
{
	ListCell   *lc;

	if (native_af_mode == AF_NATIVE || rel->reloptkind != RELOPT_BASEREL ||
		rel->lateral_relids != NULL)
		return NULL;
	foreach(lc, root->native_af_membership)
	{
		MembershipCandidate *candidate = lfirst(lc);

		if (candidate->rti == rel->relid)
			return candidate;
	}
	return NULL;
}

/*
 * Charge each admitted key-set plan to its own candidate. The selected
 * path registers its InitPlan at this query level during lowering, as
 * required by PostgreSQL's PARAM_EXEC finalization.
 */
static void
plan_membership_keys(PlannerInfo *root, MembershipCandidate *candidate,
					 SubLink *source, MembershipAccess *access)
{
	List	   *original_initplans = root->init_plans;
	ScalarArrayOpExpr *keys = makeNode(ScalarArrayOpExpr);
	Plan	   *acl_plan;
	Query	   *bounded_source;
	PlannerInfo *source_root;
	Param	   *array_param;
	TargetEntry *source_key;
	EstimationInfo estinfo = {0};
	double		distinct;
	bool		saved_serial_source = root->native_af_serial_acl_source;

	source = copyObject(source);
	bounded_source = castNode(Query, source->subselect);
	bounded_source->limitCount = (Node *) makeConst(INT8OID, -1, InvalidOid,
													sizeof(int64),
													Int64GetDatum((int64) native_af_max_authorized_keys + 1),
													false, true);
	bounded_source->limitOption = LIMIT_OPTION_COUNT;
	root->init_plans = NIL;
	keys->opno = candidate->equality;
	keys->opfuncid = F_INT8EQ;
	keys->useOr = true;
	/* Never change the shared glob: only this AF source and its descendants. */
	if (native_af_mode == AF_ADMISSION_FIRST)
		root->native_af_serial_acl_source = true;
	keys->args = list_make2(candidate->key,
							SS_process_sublinks(root, (Node *) source, false));
	root->native_af_serial_acl_source = saved_serial_source;
	access->initplan = linitial_node(SubPlan, root->init_plans);
	root->init_plans = original_initplans;
	acl_plan = planner_subplan_get_plan(root, access->initplan);
	if (native_af_mode == AF_ADMISSION_FIRST && !native_af_serial_plan(acl_plan))
	{
		/*
		 * Unsupported source shapes cannot become late runtime binding
		 * errors.
		 */
		access->initplan = NULL;
		return;
	}
	access->acl_rows = IsA(acl_plan, Limit) && outerPlan(acl_plan) != NULL ?
		outerPlan(acl_plan)->plan_rows : acl_plan->plan_rows;

	/*
	 * Estimate distinct projected keys with the source query's own
	 * statistics. The input/witness estimate remains separate: ARRAY_SUBLINK
	 * materializes all witnesses, and the execution-time cap counts those
	 * physical entries. With missing NDV statistics, keep the witness
	 * estimate as a conservative probe estimate instead of silently
	 * substituting the generic NDV default.
	 */
	access->distinct_keys = access->acl_rows;
	source_root = list_nth(root->glob->subroots, access->initplan->plan_id - 1);
	source_key = linitial_node(TargetEntry, source_root->processed_tlist);
	distinct = estimate_num_groups(source_root, list_make1(source_key->expr),
								   access->acl_rows, NULL, &estinfo);
	if (!(estinfo.flags & SELFLAG_USED_DEFAULT) && isfinite(distinct))
		access->distinct_keys = Min(access->acl_rows, clamp_row_est(distinct));

	/*
	 * The hint is copied with the generated Param, but has no executor
	 * meaning. PG's ordinary SAOP/B-tree estimators then charge all estimated
	 * probes and heap visits, including their cache/correlation model and
	 * tree descents.
	 */
	array_param = castNode(Param, lsecond(keys->args));
	Assert(array_param->paramkind == PARAM_EXEC &&
		   array_param->paramtype == INT8ARRAYOID);
	array_param->native_af_array_length = access->distinct_keys;

	/*
	 * cost_subplan already charged the complete ACL source plan once.  Add
	 * the work it omits: array accumulation/deconstruction (linear tuple
	 * work), B-tree qsort (the same comparison coefficient as cost_sort), and
	 * the subsequent linear unique pass.  nbtutils performs this even for an
	 * already ordered source, and it processes witness entries before dedup.
	 * These startup costs must be paid before the first protected row
	 * appears.
	 */
	access->array_build_cost = 2.0 * cpu_tuple_cost * access->acl_rows;
	access->array_dedup_cost = cpu_operator_cost * access->acl_rows;
	if (access->acl_rows > 1.0)
		access->array_dedup_cost += 2.0 * cpu_operator_cost * access->acl_rows *
			log(access->acl_rows) / log(2.0);
	access->key_filter = make_restrictinfo(root, (Expr *) keys, true, false,
										   false, false, candidate->policy->security_level,
										   NULL, NULL, NULL);
}

/* -------------------------------------------------------------------------
 * Row estimates, tracing and the join-path hook
 * -------------------------------------------------------------------------
 */

/* Bind the actual RestrictInfo and cost the admitted key-set query. */
void
native_af_size_paths(PlannerInfo *root, RelOptInfo *rel, RangeTblEntry *rte)
{
	MembershipCandidate *candidate = find_membership(root, rel);
	ListCell   *lc;
	List	   *indexes;
	List	   *restrictions = NIL;
	RestrictInfo *policy = NULL;
	Expr	   *policy_expr;
	SubLink    *keyed;

	if (candidate == NULL || list_length(rte->securityQuals) != 1 ||
		list_length(linitial(rte->securityQuals)) != 1)
		return;

	policy_expr = linitial(linitial(rte->securityQuals));
	foreach(lc, rel->baserestrictinfo)
	{
		RestrictInfo *qual = lfirst_node(RestrictInfo, lc);

		if (qual->security_level == 0 && equal(qual->clause, policy_expr))
		{
			if (policy != NULL)
				return;
			policy = qual;
		}
		else
			restrictions = lappend(restrictions, qual);
	}
	indexes = usable_key_indexes(rel, candidate->key->varattno);
	if (policy == NULL || indexes == NIL)
		return;

	candidate->policy = policy;
	candidate->indexes = indexes;
	candidate->other_restrictions = restrictions;
	candidate->native_rows = rel->rows;
	keyed = native_af_keyed_sublink(rel, candidate->key, candidate->equality,
									candidate->keys, policy);
	if (keyed != NULL)
		plan_membership_keys(root, candidate, keyed, &candidate->keyed);
	if (keyed == NULL || native_af_mode == AF_ADMISSION_FIRST)
		plan_membership_keys(root, candidate, candidate->keys, &candidate->enumerated);

	/*
	 * For AF costing, use the estimated authorized key-set cardinality in
	 * place of the generic SubPlan selectivity. This is an engineering
	 * estimate; duplicate ACL witnesses and correlation with user predicates
	 * can make it inaccurate. The original exact policy remains available.
	 */
	if (native_af_mode == AF_ADMISSION_FIRST && candidate->enumerated.initplan != NULL)
	{
		Selectivity residual_selectivity =
			clauselist_selectivity(root, restrictions, rel->relid, JOIN_INNER, NULL);

		rel->rows = clamp_row_est(Min(rel->tuples, candidate->enumerated.distinct_keys) *
								  residual_selectivity);
	}
}

static CustomPath *
wrap_af_path(RelOptInfo *rel, Path *child, const CustomPathMethods * methods)
{
	CustomPath *path = makeNode(CustomPath);

	path->path = *child;
	NodeSetTag(path, T_CustomPath);
	path->path.pathtype = T_CustomScan;
	path->path.parent = rel;
	path->path.pathtarget = rel->reltarget;
	path->path.parallel_aware = false;
	path->path.parallel_safe = false;
	path->path.parallel_workers = 0;
	path->custom_paths = list_make1(child);
	path->methods = methods;
	return path;
}

/* Diagnostic only: base/parameterized paths are not whole-query alternatives. */
static void
trace_af_path(const char *family, Path *path)
{
	char	   *required;

	if (!native_af_trace)
		return;
	required = bmsToString(PATH_REQ_OUTER(path));
	ereport(NOTICE,
			(errmsg("native_af: %s occurrence %u path_tag %d parameterized %s required_outer %s pathkeys %d startup %.6f total %.6f rows %.6f",
					family, path->parent->relid, (int) path->pathtype,
					path->param_info != NULL ? "true" : "false", required,
					list_length(path->pathkeys), path->startup_cost, path->total_cost, path->rows)));
	pfree(required);
}

/* Trace support: describe retained complete join alternatives without changing a cost,
 * a row estimate, an admission decision, or a baseline path.  Each invocation
 * labels its partition because the same join relation is visited repeatedly. */
static void
choice_path_brief(StringInfo out, Path *path, int depth)
{
	ListCell   *cell;
	char	   *relations;

	if (path == NULL || depth > 6)
		return;
	relations = bmsToString(path->parent->relids);
	appendStringInfo(out, "{tag:%d,rels:%s,rows:%.3f,start:%.3f,total:%.3f,param:%d",
					 (int) path->pathtype, relations, path->rows,
					 path->startup_cost, path->total_cost,
					 path->param_info != NULL);
	pfree(relations);
	if (IsA(path, CustomPath))
	{
		CustomPath *custom = castNode(CustomPath, path);

		appendStringInfo(out, ",custom:%s,children:[", custom->methods->CustomName);
		foreach(cell, custom->custom_paths)
			choice_path_brief(out, lfirst(cell), depth + 1);
		appendStringInfoChar(out, ']');
	}
	else if (IsA(path, NestPath) || IsA(path, MergePath) || IsA(path, HashPath))
	{
		JoinPath   *join = (JoinPath *) path;

		appendStringInfoString(out, ",outer:");
		choice_path_brief(out, join->outerjoinpath, depth + 1);
		appendStringInfoString(out, ",inner:");
		choice_path_brief(out, join->innerjoinpath, depth + 1);
	}
	else if (IsA(path, IndexPath))
	{
		IndexPath  *index = castNode(IndexPath, path);

		appendStringInfo(out, ",index:%u,selectivity:%.9f,index_total:%.3f",
						 index->indexinfo->indexoid, index->indexselectivity,
						 index->indextotalcost);
	}
	else if (IsA(path, MaterialPath))
	{
		appendStringInfoString(out, ",material:");
		choice_path_brief(out, castNode(MaterialPath, path)->subpath, depth + 1);
	}
	else if (IsA(path, MemoizePath))
	{
		appendStringInfoString(out, ",memoize:");
		choice_path_brief(out, castNode(MemoizePath, path)->subpath, depth + 1);
	}
	appendStringInfoChar(out, '}');
}

static void
native_af_choice_join_paths(PlannerInfo *root, RelOptInfo *joinrel,
							RelOptInfo *outerrel, RelOptInfo *innerrel,
							JoinType jointype, JoinPathExtraData *extra)
{
	ListCell   *cell;
	char	   *partition_outer;
	char	   *partition_inner;

	if (native_af_previous_join_hook != NULL)
		native_af_previous_join_hook(root, joinrel, outerrel, innerrel, jointype, extra);
	if (native_af_mode != AF_ADMISSION_FIRST || !native_af_trace ||
		root->native_af_membership == NIL || jointype != JOIN_INNER ||
		bms_num_members(joinrel->relids) > 4)
		return;
	partition_outer = bmsToString(outerrel->relids);
	partition_inner = bmsToString(innerrel->relids);
	foreach(cell, joinrel->pathlist)
	{
		StringInfoData details;

		initStringInfo(&details);
		choice_path_brief(&details, lfirst(cell), 0);
		ereport(NOTICE,
				(errmsg("AF_CHOICE join_partition %s/%s retained %s",
						partition_outer, partition_inner, details.data)));
		pfree(details.data);
	}
	pfree(partition_outer);
	pfree(partition_inner);
}

/*
 * The ordinary RelOptInfo owns exact RLS paths. A private shallow copy
 * owns the alternate restriction list for authorization index lowering.
 */
/* -------------------------------------------------------------------------
 * Candidate paths: membership keys, policy indexes and completed hash
 * -------------------------------------------------------------------------
 */

/* Close the generated key test against the actual occurrence and source.
 * The source's SQL was validated before generation. These are the bindings
 * that the physical index test and executor fallback actually consume. */
static bool
membership_access_bound(PlannerInfo *root, RelOptInfo *rel,
						MembershipCandidate *candidate, MembershipAccess *access)
{
	RangeTblEntry *rte = planner_rt_fetch(rel->relid, root);
	SubPlan    *source = access->initplan;
	ScalarArrayOpExpr *test;
	Param	   *array;

	if (candidate->rti != rel->relid || candidate->policy == NULL ||
		!list_member_ptr(rel->baserestrictinfo, candidate->policy) ||
		list_length(rte->securityQuals) != 1 ||
		list_length(linitial(rte->securityQuals)) != 1 ||
		!equal(linitial(linitial(rte->securityQuals)), candidate->policy->clause) ||
		access->key_filter == NULL ||
		!IsA(access->key_filter->clause, ScalarArrayOpExpr) ||
		source->subLinkType != ARRAY_SUBLINK || source->plan_id <= 0 ||
		source->plan_id > list_length(root->glob->subplans) ||
		source->parParam != NIL || source->args != NIL ||
		source->firstColType != INT8OID || list_length(source->setParam) != 1)
		return false;
	test = castNode(ScalarArrayOpExpr, access->key_filter->clause);
	if (!test->useOr || test->opno != candidate->equality || test->opfuncid != F_INT8EQ ||
		list_length(test->args) != 2 || !equal(linitial(test->args), candidate->key) ||
		!IsA(lsecond(test->args), Param))
		return false;
	array = lsecond_node(Param, test->args);
	return array->paramkind == PARAM_EXEC && array->paramtype == INT8ARRAYOID &&
		array->paramid == linitial_int(source->setParam);
}

static List *
membership_index_paths(PlannerInfo *root, RelOptInfo *rel,
					   MembershipCandidate *candidate, MembershipAccess *access,
					   bool keyed, List *sp_evidence)
{
	ListCell   *lc;
	RelOptInfo *alternate;
	List	   *accepted = NIL;

	if (access->initplan == NULL ||
		access->acl_rows > native_af_max_authorized_keys)
		return NIL;
	if (native_af_mode == AF_ADMISSION_FIRST &&
		!membership_access_bound(root, rel, candidate, access))
		return NIL;

	alternate = palloc(sizeof(*alternate));
	memcpy(alternate, rel, sizeof(*alternate));
	alternate->pathlist = NIL;
	alternate->partial_pathlist = NIL;
	alternate->indexlist = NIL;
	alternate->consider_parallel = false;
	alternate->joininfo = NIL;
	alternate->baserestrictinfo = lcons(access->key_filter,
										list_copy(candidate->other_restrictions));
	foreach(lc, candidate->indexes)
	{
		IndexOptInfo *index = palloc(sizeof(*index));

		memcpy(index, lfirst(lc), sizeof(*index));
		index->rel = alternate;
		/* Only tuple-returning index paths are publishable by this provider. */
		index->amhasgetbitmap = false;
		index->indrestrictinfo = alternate->baserestrictinfo;
		alternate->indexlist = lappend(alternate->indexlist, index);
	}
	cost_qual_eval(&alternate->baserestrictcost, alternate->baserestrictinfo, root);
	create_index_paths(root, alternate);

	foreach(lc, alternate->pathlist)
	{
		Path	   *index_path = lfirst(lc);
		CustomPath *path;
		Cost		init_cost;

		if (!IsA(index_path, IndexPath) || index_path->param_info != NULL ||
			!has_index_clause(castNode(IndexPath, index_path), access->key_filter))
			continue;

		path = wrap_af_path(rel, index_path, &membership_path_methods);
		init_cost = access->initplan->startup_cost + access->initplan->per_call_cost;
		init_cost += access->array_build_cost + access->array_dedup_cost;
		path->path.startup_cost += init_cost;
		path->path.total_cost += init_cost;
		trace_af_path(keyed ? "membership-keyed" : "membership-enumerated", &path->path);
		if (native_af_trace)
			ereport(NOTICE,
					(errmsg("native_af: admitted membership %s: witnesses %.0f, distinct %.0f, source %.2f, array %.2f, sort_unique %.2f, index %.2f, startup %.2f, total %.2f, rows %.0f",
							keyed ? "keyed" : "enumerated", access->acl_rows,
							access->distinct_keys,
							access->initplan->startup_cost + access->initplan->per_call_cost,
							access->array_build_cost, access->array_dedup_cost,
							index_path->total_cost, path->path.startup_cost,
							path->path.total_cost, path->path.rows)));
		path->custom_private = list_make5(access->initplan,
										  makeInteger(candidate->key->varattno),
										  makeFloat(psprintf("%.0f", access->acl_rows)),
										  makeInteger(native_af_mode),
										  makeInteger(linitial_int(access->initplan->setParam)));
		path->custom_private = lappend(path->custom_private,
									   makeFloat(psprintf("%.0f", candidate->native_rows)));
		path->custom_private = lappend(path->custom_private, sp_evidence);
		path->custom_private = lappend(path->custom_private, makeInteger(keyed));
		path->custom_private = lappend(path->custom_private,
									   makeConst(OIDOID, -1, InvalidOid, sizeof(Oid),
												 ObjectIdGetDatum(planner_rt_fetch(rel->relid, root)->relid), false, true));
		path->custom_private = lappend(path->custom_private,
									   makeConst(OIDOID, -1, InvalidOid, sizeof(Oid),
												 ObjectIdGetDatum(castNode(IndexPath, index_path)->indexinfo->indexoid), false, true));
		path->custom_private = lappend(path->custom_private, makeInteger(access->initplan->plan_id));
		{
			Query	   *source = castNode(Query, candidate->keys->subselect);
			List	   *relations = NIL;
			ListCell   *rt;

			foreach(rt, source->rtable)
			{
				RangeTblEntry *entry = lfirst_node(RangeTblEntry, rt);

				if (entry->rtekind == RTE_RELATION)
					relations = list_append_unique_oid(relations, entry->relid);
			}
			path->custom_private = lappend(path->custom_private, relations);
		}
		path->custom_private = lappend(path->custom_private,
									   makeInteger(native_af_max_authorized_keys));
		path->custom_private = lappend(path->custom_private,
									   list_make4(makeFloat(psprintf("%.6f", access->distinct_keys)),
												  makeFloat(psprintf("%.6f", access->initplan->startup_cost +
																	 access->initplan->per_call_cost)),
												  makeFloat(psprintf("%.6f", access->array_build_cost)),
												  makeFloat(psprintf("%.6f", access->array_dedup_cost))));
		path->custom_private = lappend(path->custom_private,
									   makeInteger(candidate->uses_current_user));
		{
			Path	   *fallback = create_seqscan_path(root, rel, NULL, 0);

			/* The fallback enforces the same ordering promised by the index. */
			if (index_path->pathkeys != NIL)
				fallback = (Path *) create_sort_path(root, rel, fallback,
													 index_path->pathkeys, -1.0);
			path->custom_paths = lappend(path->custom_paths, fallback);
		}
		accepted = lappend(accepted, path);
	}
	return accepted;
}

/* Match only a plain comparison whose actual built-in function is leakproof. */
static bool
completed_hash_safe_comparison(RestrictInfo *qual, Index relid)
{
	OpExpr	   *expr;
	Node	   *left;
	Node	   *right;
	Var		   *column;
	HeapTuple	entry;
	Oid			function;
	bool		builtin;

	if (qual->pseudoconstant || qual->clause == NULL ||
		!IsA(qual->clause, OpExpr) ||
		contain_volatile_functions((Node *) qual->clause))
		return false;
	expr = castNode(OpExpr, qual->clause);
	if (expr->opretset || expr->opresulttype != BOOLOID ||
		expr->opno >= FirstGenbkiObjectId || list_length(expr->args) != 2)
		return false;
	left = linitial(expr->args);
	right = lsecond(expr->args);
	if (left == NULL || right == NULL)
		return false;
	if (IsA(left, Var) && IsA(right, Const))
		column = castNode(Var, left);
	else if (IsA(left, Const) && IsA(right, Var))
		column = castNode(Var, right);
	else
		return false;
	if (column->varno != relid || column->varattno <= 0 ||
		column->varlevelsup != 0 || !bms_is_empty(column->varnullingrels))
		return false;

	entry = SearchSysCache1(OPEROID, ObjectIdGetDatum(expr->opno));
	if (!HeapTupleIsValid(entry))
		return false;
	builtin = ((Form_pg_operator) GETSTRUCT(entry))->oprnamespace == PG_CATALOG_NAMESPACE;
	function = ((Form_pg_operator) GETSTRUCT(entry))->oprcode;
	ReleaseSysCache(entry);
	return builtin && OidIsValid(function) && function <= fmgr_last_builtin_oid &&
		fmgr_builtin_oid_index[function] != InvalidOidBuiltinMapping &&
		(!OidIsValid(expr->opfuncid) || expr->opfuncid == function) &&
		get_func_namespace(function) == PG_CATALOG_NAMESPACE &&
		get_func_leakproof(function);
}

/* Keep exactly the effective security rule used by PG order_qual_clauses. */
static Index
completed_hash_qual_security(RestrictInfo *qual, Cost per_tuple)
{
	return qual->leakproof && per_tuple < 10 * cpu_operator_cost ?
		0 : qual->security_level;
}

/* Replace the policy; prefer only safe comparisons tied under PG's sorter. */
static List *
completed_hash_restrictions(PlannerInfo *root, Index relid,
							List *restrictions, RestrictInfo *original,
							RestrictInfo *replacement)
{
	List	   *result = NIL;
	List	   *preferred = NIL;
	List	   *ordered = NIL;
	ListCell   *cell;
	QualCost	policy_cost;
	Index		policy_security;
	int			policies = 0;
	bool		known = true;
	bool		after_policy = false;

	foreach(cell, restrictions)
	{
		Node	   *qual = lfirst(cell);

		if (qual == NULL || !IsA(qual, RestrictInfo))
			known = false;
		if (qual == (Node *) original)
			policies++;
		if (qual == (Node *) replacement)
			known = false;
		result = lappend(result, qual == (Node *) original ? (Node *) replacement : qual);
	}
	if (native_af_mode != AF_ADMISSION_FIRST || !known || policies != 1 ||
		original == NULL || replacement == NULL || replacement->pseudoconstant)
		return result;
	cost_qual_eval_node(&policy_cost, (Node *) replacement, root);
	if (!isfinite(policy_cost.per_tuple))
		return result;
	policy_security = completed_hash_qual_security(replacement, policy_cost.per_tuple);
	foreach(cell, result)
	{
		RestrictInfo *qual = lfirst_node(RestrictInfo, cell);
		QualCost	cost;

		if (qual == replacement)
		{
			after_policy = true;
			continue;
		}
		if (!after_policy || !completed_hash_safe_comparison(qual, relid))
			continue;
		cost_qual_eval_node(&cost, (Node *) qual, root);
		if (isfinite(cost.per_tuple) && cost.per_tuple == policy_cost.per_tuple &&
			completed_hash_qual_security(qual, cost.per_tuple) == policy_security)
			preferred = lappend(preferred, qual);
	}
	if (preferred == NIL)
		return result;
	after_policy = false;
	foreach(cell, result)
	{
		RestrictInfo *qual = lfirst_node(RestrictInfo, cell);

		if (qual == replacement)
		{
			ordered = list_concat(ordered, list_copy(preferred));
			ordered = lappend(ordered, qual);
			after_policy = true;
			continue;
		}
		if (!after_policy || !list_member_ptr(preferred, qual))
			ordered = lappend(ordered, qual);
	}
	return ordered;
}

/*
 * The actual RLS expression already owns these PG-generated, equivalent
 * alternatives.  Expose a completed hash choice during AF path costing.
 * Keeping a one-arm AlternativeSubPlan lets upstream setrefs preserve the
 * source plan even when another original occurrence selects the other arm.
 * No source query, hash implementation, permission or runtime value changes.
 */
static List *
completed_hash_paths(PlannerInfo *root, RelOptInfo *rel,
					 MembershipCandidate *candidate, RestrictInfo **completed_policy)
{
	AlternativeSubPlan *original;
	AlternativeSubPlan *chosen;
	SubPlan    *hash = NULL;
	RestrictInfo *policy;
	RelOptInfo *input;
	List	   *accepted = NIL;
	List	   *arms = NIL;
	List	   *relations = NIL;
	ListCell   *cell;

	*completed_policy = NULL;
	if (native_af_mode != AF_ADMISSION_FIRST || candidate == NULL ||
		candidate->policy == NULL || rel->reloptkind != RELOPT_BASEREL ||
		rel->lateral_relids != NULL ||
		!IsA(candidate->policy->clause, AlternativeSubPlan) ||
		!root->hasAlternativeSubPlans ||
		!direct_principal_permissions(root->parse, planner_rt_fetch(rel->relid, root)))
		return NIL;
	original = castNode(AlternativeSubPlan, candidate->policy->clause);
	foreach(cell, original->subplans)
	{
		SubPlan    *arm;

		if (!IsA(lfirst(cell), SubPlan))
			return NIL;
		arm = lfirst_node(SubPlan, cell);
		if (arm->plan_id <= 0 || arm->plan_id > list_length(root->glob->subplans))
			return NIL;
		arms = lappend(arms, list_make4(makeInteger(arm->plan_id),
										makeInteger(arm->useHashTable), makeFloat(psprintf("%.17g", arm->startup_cost)),
										makeFloat(psprintf("%.17g", arm->per_call_cost))));
		if (native_af_trace)
			ereport(NOTICE,
					(errmsg("native_af: completed hash occurrence %u original arm %d hash %d startup %.6f per_call %.9f",
							rel->relid, arm->plan_id, arm->useHashTable,
							arm->startup_cost, arm->per_call_cost)));
		if (!arm->useHashTable)
			continue;
		if (hash != NULL || arm->subLinkType != ANY_SUBLINK ||
			arm->parParam != NIL || arm->args != NIL || arm->setParam != NIL ||
			arm->firstColType != INT8OID || list_length(arm->paramIds) != 1 ||
			!IsA(arm->testexpr, OpExpr) ||
			get_opcode(castNode(OpExpr, arm->testexpr)->opno) != F_INT8EQ)
			return NIL;
		hash = arm;
	}
	if (hash == NULL)
		return NIL;
	{
		OpExpr	   *test = castNode(OpExpr, hash->testexpr);
		Node	   *key;
		Node	   *parameter;
		Plan	   *source_plan = planner_subplan_get_plan(root, hash);

		if (!builtin_equality(test) || list_length(test->args) != 2 ||
			source_plan->targetlist == NIL ||
			linitial_node(TargetEntry, source_plan->targetlist)->resjunk ||
			exprType((Node *) linitial_node(TargetEntry, source_plan->targetlist)->expr) != INT8OID)
			return NIL;
		key = linitial(test->args);
		parameter = lsecond(test->args);
		if (IsA(key, Param))
		{
			key = lsecond(test->args);
			parameter = linitial(test->args);
		}
		if (!equal(key, candidate->key) || !IsA(parameter, Param) ||
			castNode(Param, parameter)->paramkind != PARAM_EXEC ||
			castNode(Param, parameter)->paramtype != INT8OID ||
			castNode(Param, parameter)->paramid != linitial_int(hash->paramIds))
			return NIL;
	}
	foreach(cell, castNode(Query, candidate->keys->subselect)->rtable)
	{
		RangeTblEntry *source = lfirst_node(RangeTblEntry, cell);

		if (source->rtekind == RTE_RELATION)
		{
			if (!direct_principal_permissions(castNode(Query, candidate->keys->subselect), source))
				return NIL;
			relations = list_append_unique_oid(relations, source->relid);
		}
	}
	if (relations == NIL)
		return NIL;
	chosen = makeNode(AlternativeSubPlan);
	chosen->subplans = list_make1(copyObject(hash));
	policy = make_restrictinfo(root, (Expr *) chosen,
							   candidate->policy->is_pushed_down, candidate->policy->has_clone,
							   candidate->policy->is_clone, candidate->policy->pseudoconstant,
							   candidate->policy->security_level, candidate->policy->required_relids,
							   candidate->policy->incompatible_relids, candidate->policy->outer_relids);
	/* Only the independently validated, actual RLS arm can be reused below. */
	*completed_policy = policy;
	/* The ordinary PG arm remains available even when AF cannot bind it. */
	if (!native_af_serial_policy(root, (Node *) chosen))
		return NIL;
	input = palloc(sizeof(*input));
	memcpy(input, rel, sizeof(*input));
	input->pathlist = NIL;
	input->partial_pathlist = NIL;
	input->indexlist = NIL;
	input->joininfo = NIL;
	input->consider_parallel = false;
	input->baserestrictinfo = completed_hash_restrictions(root, rel->relid,
														  rel->baserestrictinfo, candidate->policy, policy);
	foreach(cell, rel->indexlist)
	{
		IndexOptInfo *index = palloc(sizeof(*index));

		memcpy(index, lfirst(cell), sizeof(*index));
		index->rel = input;
		index->indrestrictinfo = completed_hash_restrictions(root, rel->relid,
															 index->indrestrictinfo, candidate->policy, policy);
		input->indexlist = lappend(input->indexlist, index);
	}
	cost_qual_eval(&input->baserestrictcost, input->baserestrictinfo, root);
	add_path(input, create_seqscan_path(root, input, NULL, 0));
	create_index_paths(root, input);
	foreach(cell, input->pathlist)
	{
		Path	   *child = lfirst(cell);
		CustomPath *path;
		double		probes = rel->tuples;

		if (child->param_info != NULL ||
			(!IsA(child, IndexPath) && !IsA(child, BitmapHeapPath) &&
			 child->pathtype != T_SeqScan))
			continue;
		if (IsA(child, IndexPath))
			probes *= castNode(IndexPath, child)->indexselectivity;
		else if (IsA(child, BitmapHeapPath))
		{
			Cost		bitmap_cost;
			Selectivity bitmap_selectivity;

			cost_bitmap_tree_node(castNode(BitmapHeapPath, child)->bitmapqual,
								  &bitmap_cost, &bitmap_selectivity);
			probes *= bitmap_selectivity;
		}
		if (native_af_trace)
			ereport(NOTICE,
					(errmsg("native_af: completed hash occurrence %u candidate type %d input_rows %.0f output_rows %.0f startup %.6f total %.6f hash_evaluations_upper_estimate %.0f",
							rel->relid, child->pathtype, probes, child->rows,
							child->startup_cost, child->total_cost, probes)));
		path = wrap_af_path(rel, child, &completed_hash_path_methods);
		trace_af_path("completed-hash", &path->path);
		path->custom_private = list_make5(chosen, candidate->key, relations,
										  arms, makeFloat(psprintf("%.17g", probes)));
		accepted = lappend(accepted, path);
	}
	return accepted;
}

/* -------------------------------------------------------------------------
 * Experiment controls used for the component ablations
 * -------------------------------------------------------------------------
 */

/*
 * Experiment selectors inspect immutable structural properties of already admitted
 * paths.  They do not change costs, policies, proof records or executor code.
 * Broad hash/keys selectors let normal costing choose among retained physical
 * variants; the more specific hash selectors name the retained child type.
 */
static const char *
experiment_path_kind(Path *path)
{
	if (IsA(path, CustomPath) && castNode(CustomPath, path)->custom_paths != NIL)
		path = linitial(castNode(CustomPath, path)->custom_paths);
	if (IsA(path, IndexPath))
		return "index";
	if (IsA(path, BitmapHeapPath))
		return "bitmap";
	if (path->pathtype == T_SeqScan)
		return "seq";
	return "other";
}

static const char *
experiment_path_selector(Path *path)
{
	CustomPath *custom;
	const char *name;

	if (!IsA(path, CustomPath))
		return "ordinary";
	custom = castNode(CustomPath, path);
	name = custom->methods->CustomName;
	if (strcmp(name, "AF Prefix Guard") == 0)
	{
		Node	   *policy;
		bool		hash = false;
		bool		index = strcmp(experiment_path_kind(path), "index") == 0;

		/* No late diagnostic path is eligible for experiment forcing. */
		if (list_length(custom->custom_private) < 9 ||
			intVal(list_nth(custom->custom_private, 6)))
			return "unsafe_or_unknown";
		policy = linitial(custom->custom_private);
		if (IsA(policy, AlternativeSubPlan))
		{
			List	   *arms = castNode(AlternativeSubPlan, policy)->subplans;

			if (list_length(arms) == 1 && IsA(linitial(arms), SubPlan))
				hash = linitial_node(SubPlan, arms)->useHashTable;
		}
		return index ? (hash ? "guard_index_hash" : "guard_index_original") :
			(hash ? "guard_seq_hash" : "guard_seq_original");
	}
	if (custom->methods == &completed_hash_path_methods)
	{
		const char *kind = experiment_path_kind(path);

		if (strcmp(kind, "seq") == 0)
			return "hash_seq";
		if (strcmp(kind, "index") == 0)
			return "hash_index";
		if (strcmp(kind, "bitmap") == 0)
			return "hash_bitmap";
		return "hash_other";
	}
	if (custom->methods == &membership_path_methods ||
		custom->methods == &partial_path_methods)
		return "keys";
	if (custom->methods == &exact_path_methods)
		return "exact_sp";
	return "ordinary";
}

static bool
experiment_all_families_off(void)
{
	return !native_af_experiment_publish_guard &&
		!native_af_experiment_publish_keys &&
		!native_af_experiment_publish_hash &&
		!native_af_experiment_publish_shared;
}

static bool
experiment_path_enabled(Path *path)
{
	const char *selector = experiment_path_selector(path);

	if (experiment_all_families_off())
		return false;			/* includes exact-SP; row estimation still ran */
#ifdef NATIVE_AF_GUARD_DIAGNOSTIC_UNSAFE

	/*
	 * Only the isolated diagnostic build may naturally publish the precise
	 * late Guard generated by the same provider. A1 forcing stays safe-only.
	 */
	if (native_af_experiment_force == AF_EXP_AUTO &&
		native_af_experiment_publish_guard && IsA(path, CustomPath))
	{
		CustomPath *guard = castNode(CustomPath, path);

		if (guard->methods != NULL &&
			strcmp(guard->methods->CustomName, "AF Prefix Guard") == 0 &&
			list_length(guard->custom_private) >= 9 &&
			IsA(list_nth(guard->custom_private, 6), Integer) &&
			intVal(list_nth(guard->custom_private, 6)) == 1)
			return true;
	}
#endif
	if (strncmp(selector, "guard_", 6) == 0)
		return native_af_experiment_publish_guard;
	if (strncmp(selector, "hash_", 5) == 0)
		return native_af_experiment_publish_hash;
	if (strcmp(selector, "keys") == 0)
		return native_af_experiment_publish_keys;
	return strcmp(selector, "unsafe_or_unknown") != 0;
}

static bool
experiment_force_matches(Path *path)
{
	const char *selector = experiment_path_selector(path);

	if (native_af_experiment_force == AF_EXP_KEYS)
		return strcmp(selector, "keys") == 0;
	if (native_af_experiment_force == AF_EXP_HASH)
		return strncmp(selector, "hash_", 5) == 0;
	return strcmp(selector,
				  af_experiment_forces[native_af_experiment_force].name) == 0;
}

static void
experiment_candidate_json(StringInfo output, Path *path, bool enabled,
						  bool *first)
{
	Path	   *child = path;
	Oid			index_oid = InvalidOid;
	const char *selector = experiment_path_selector(path);
	const char *family = strncmp(selector, "guard_", 6) == 0 ? "guard" :
		strncmp(selector, "hash_", 5) == 0 ? "hash" : selector;

	if (IsA(path, CustomPath) && castNode(CustomPath, path)->custom_paths != NIL)
		child = linitial(castNode(CustomPath, path)->custom_paths);
	if (IsA(child, IndexPath))
		index_oid = castNode(IndexPath, child)->indexinfo->indexoid;
	appendStringInfo(output,
					 "%s{\"selector\":\"%s\",\"family\":\"%s\",\"path_type\":\"%s\","
					 "\"startup_cost\":%.17g,\"total_cost\":%.17g,\"rows\":%.17g,"
					 "\"index_oid\":%u,\"enabled\":%s}",
					 *first ? "" : ",", selector, family, experiment_path_kind(path),
					 path->startup_cost, path->total_cost, path->rows, index_oid,
					 enabled ? "true" : "false");
	*first = false;
}

static void
experiment_trace_candidates(RelOptInfo *rel, List *accepted, Path *forced,
							const char *status)
{
	StringInfoData json;
	ListCell   *cell;
	bool		first = true;

	if (!native_af_trace)
		return;
	initStringInfo(&json);
	appendStringInfo(&json,
					 "{\"event\":\"candidates\",\"rti\":%u,\"force\":\"%s\","
					 "\"status\":\"%s\",\"selected\":",
					 rel->relid, af_experiment_forces[native_af_experiment_force].name, status);
	if (forced != NULL)
		escape_json(&json, experiment_path_selector(forced));
	else if (native_af_experiment_force == AF_EXP_ORDINARY)
		appendStringInfoString(&json, "\"ordinary\"");
	else
		appendStringInfoString(&json, "null");
	appendStringInfoString(&json, ",\"candidates\":[");
	foreach(cell, rel->pathlist)
		experiment_candidate_json(&json, lfirst(cell), true, &first);
	foreach(cell, accepted)
		experiment_candidate_json(&json, lfirst(cell),
								  experiment_path_enabled(lfirst(cell)), &first);
	appendStringInfoString(&json, "]}");
	ereport(NOTICE, (errmsg("AF_EXPERIMENT %s", json.data)));
	pfree(json.data);
}

/* -------------------------------------------------------------------------
 * Entry point: offer the admitted AF alternatives for a protected relation
 *
 * Called by set_base_rel_pathlist() for a base relation with row-level
 * security.  Candidates that fail admission are discarded before costing;
 * the survivors are added with add_path() next to the ordinary paths.
 * -------------------------------------------------------------------------
 */

void
native_af_add_paths(PlannerInfo *root, RelOptInfo *rel, RangeTblEntry *rte)
{
	MembershipCandidate *candidate = find_membership(root, rel);
	ListCell   *lc;
	List	   *accepted;
	List	   *keyed = NIL;
	List	   *enumerated = NIL;
	List	   *sp_paths = NIL;
	List	   *sp_evidence = NIL;
	List	   *private_paths;
	List	   *hash_paths = NIL;
	RestrictInfo *completed_policy = NULL;

	if (native_af_mode == AF_NATIVE ||
		(native_af_mode == AF_ADMISSION_FIRST && IsParallelWorker()))
		return;
	private_paths = native_af_partial_paths(root, rel, rte,
											root->native_af_private_indexes,
											native_af_mode == AF_INDEX_PRIORITY);
	foreach(lc, private_paths)
	{
		NativeAfPartialPath *artifact = lfirst(lc);
		CustomPath *path = wrap_af_path(rel, &artifact->path->path,
										&partial_path_methods);
		Const	   *index_oid = makeConst(OIDOID, -1, InvalidOid, sizeof(Oid),
										  ObjectIdGetDatum(artifact->index_oid), false, true);

		path->custom_private = list_make3(index_oid, makeInteger(artifact->keyed),
										  makeInteger(native_af_mode));
		if (artifact->keyed)
			keyed = lappend(keyed, path);
		else
			enumerated = lappend(enumerated, path);
	}

	if (candidate != NULL && candidate->policy != NULL)
	{
		hash_paths = completed_hash_paths(root, rel, candidate, &completed_policy);
		if (native_af_mode == AF_ADMISSION_FIRST)
			sp_paths = native_af_sp_exact_paths(root, rel, rte, candidate->policy,
												candidate->key, &sp_evidence);

		keyed = list_concat(keyed, membership_index_paths(root, rel, candidate,
														  &candidate->keyed, true, sp_evidence));
		if (native_af_mode == AF_ADMISSION_FIRST || keyed == NIL)
		{
			/*
			 * IP only plans membership enumeration when no valid keyed path
			 * is available. AF admits both families before comparing.
			 */
			if (candidate->enumerated.initplan == NULL)
				plan_membership_keys(root, candidate, candidate->keys, &candidate->enumerated);
			enumerated = list_concat(enumerated,
									 membership_index_paths(root, rel, candidate,
															&candidate->enumerated,
															false, sp_evidence));
		}
	}

	if (native_af_trace && rte->securityQuals != NIL)
		ereport(NOTICE,
				(errmsg("native_af: occurrence %u: keyed %d, enumerated %d, exact SP %d%s",
						rel->relid, list_length(keyed), list_length(enumerated),
						list_length(sp_paths),
						keyed == NIL && enumerated == NIL && sp_paths == NIL ?
						", no applicable AF path" : "")));

	if (native_af_trace && candidate != NULL && candidate->policy != NULL)
		foreach(lc, rel->pathlist)
	{
		trace_af_path("ordinary-exact-policy", lfirst(lc));
	}

	accepted = native_af_mode == AF_ADMISSION_FIRST ?
		list_concat(keyed, enumerated) : (keyed != NIL ? keyed : enumerated);
	accepted = list_concat(accepted, hash_paths);
	if (native_af_mode == AF_ADMISSION_FIRST)
		accepted = list_concat(accepted, native_af_guard_paths(root, rel, rte,
															   candidate ? candidate->policy : NULL, completed_policy));
	foreach(lc, sp_paths)
	{
		CustomPath *path = wrap_af_path(rel, lfirst(lc), &exact_path_methods);

		path->custom_private = list_make3(candidate->policy->clause,
										  candidate->key, sp_evidence);
		accepted = lappend(accepted, path);
	}
	if (native_af_mode == AF_ADMISSION_FIRST && rte->securityQuals != NIL)
	{
		List	   *published = NIL;
		Path	   *forced = NULL;
		bool		require = native_af_experiment_force != AF_EXP_AUTO &&
			root->parent_root == NULL;

		foreach(lc, accepted)
		{
			Path	   *path = lfirst(lc);

			if (!experiment_path_enabled(path))
				continue;
			published = lappend(published, path);
			if (require && native_af_experiment_force != AF_EXP_ORDINARY &&
				experiment_force_matches(path) &&
				(forced == NULL || path->total_cost < forced->total_cost))
				forced = path;
		}
		experiment_trace_candidates(rel, accepted, forced,
									!require ? "natural" : native_af_experiment_force == AF_EXP_ORDINARY ?
									"forced_ordinary" : forced != NULL ? "forced" : "unavailable");
		if (require)
		{
			if (native_af_experiment_force == AF_EXP_ORDINARY)
				return;			/* untouched ordinary RLS paths, AF row
								 * estimate retained */
			if (forced == NULL)
				ereport(ERROR,
						(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
						 errmsg("AF experiment target unavailable: %s at occurrence %u",
								af_experiment_forces[native_af_experiment_force].name, rel->relid),
						 errdetail("No matching enabled retained admitted path exists. The family may be inapplicable, disabled, or privately pruned before publication; inspect the candidate trace.")));
			rel->pathlist = NIL;
			rel->partial_pathlist = NIL;
			add_path(rel, forced);
			return;
		}
		accepted = published;
	}
	if (accepted == NIL)
		return;
	if (native_af_mode == AF_INDEX_PRIORITY)
	{
		/*
		 * IP publishes the first applicable path family. AF's finite
		 * replacement proof applies only to the compared private roots.
		 * Ordinary paths still take part in normal complete-plan choice.
		 */
		rel->pathlist = NIL;
		rel->partial_pathlist = NIL;
	}
	foreach(lc, accepted)
	{
		if (native_af_trace)
			trace_af_path("admitted-candidate", lfirst(lc));
		add_path(rel, lfirst(lc));
	}
}

/* -------------------------------------------------------------------------
 * Plan creation, execution and EXPLAIN output of the AF custom scans
 * -------------------------------------------------------------------------
 */

static Plan *
plan_membership_path(PlannerInfo *root, RelOptInfo *rel, CustomPath *path,
					 List *target, List *clauses, List *children)
{
	CustomScan *scan = makeNode(CustomScan);
	Plan	   *child = (Plan *) linitial(children);

	Plan	   *fallback = (Plan *) lsecond(children);
	ListCell   *fast_column;
	ListCell   *fallback_column;

	if (list_length(fallback->targetlist) < list_length(child->targetlist))
		elog(ERROR, "AF membership fallback loses output columns");
	forboth(fast_column, child->targetlist, fallback_column, fallback->targetlist)
	{
		TargetEntry *fast = lfirst_node(TargetEntry, fast_column);
		TargetEntry *exact = lfirst_node(TargetEntry, fallback_column);

		if (fast->resno != exact->resno || fast->resjunk != exact->resjunk ||
			!equal(fast->expr, exact->expr))
			elog(ERROR, "AF membership branches disagree on output binding");
	}

	scan->scan.plan.targetlist = target;
	scan->scan.scanrelid = rel->relid;
	scan->custom_plans = children;
	scan->custom_scan_tlist = copyObject(child->targetlist);
	scan->custom_private = list_copy_tail(path->custom_private, 1);
	scan->methods = &membership_scan_methods;
	root->init_plans = lappend(root->init_plans, linitial(path->custom_private));
	return &scan->scan.plan;
}

static Plan *
plan_partial_path(PlannerInfo *root, RelOptInfo *rel, CustomPath *path,
				  List *target, List *clauses, List *children)
{
	CustomScan *scan = makeNode(CustomScan);
	Plan	   *child = (Plan *) linitial(children);

	scan->scan.plan.targetlist = target;
	scan->scan.scanrelid = rel->relid;
	scan->custom_plans = children;
	scan->custom_scan_tlist = copyObject(child->targetlist);
	scan->custom_private = path->custom_private;
	scan->methods = &partial_scan_methods;
	return &scan->scan.plan;
}

static Node *
create_partial_scan(CustomScan *scan)
{
	AfScanState *state = palloc0(sizeof(*state));

	NodeSetTag(&state->css, T_CustomScanState);
	state->css.methods = &partial_exec_methods;
	return (Node *) &state->css;
}

static void
begin_partial_scan(CustomScanState *node, EState *estate, int eflags)
{
	AfScanState *state = (AfScanState *) node;
	CustomScan *scan = castNode(CustomScan, node->ss.ps.plan);
	Plan	   *child = (Plan *) linitial(scan->custom_plans);
	Oid			expected = DatumGetObjectId(linitial_node(Const, scan->custom_private)->constvalue);
	Oid			actual;

	native_af_check_serial_scan(scan, estate);

	if (IsA(child, IndexScan))
		actual = castNode(IndexScan, child)->indexid;
	else if (IsA(child, IndexOnlyScan))
		actual = castNode(IndexOnlyScan, child)->indexid;
	else
		elog(ERROR, "invalid AF policy index scan child");
	if (((Scan *) child)->scanrelid != scan->scan.scanrelid || actual != expected ||
		IndexGetRelation(actual, true) != RelationGetRelid(node->ss.ss_currentRelation))
		elog(ERROR, "invalid AF policy index binding");

	state->execution_family = intVal(lsecond(scan->custom_private)) ?
		AF_EXEC_POLICY_KEY : AF_EXEC_POLICY_ENUM;
	state->child = ExecInitNode(child, estate, eflags);
	node->custom_ps = list_make1(state->child);
}

static void
explain_partial_scan(CustomScanState *node, List *ancestors, ExplainState *es)
{
	CustomScan *scan = castNode(CustomScan, node->ss.ps.plan);

	ExplainPropertyText("AF Path", intVal(lsecond(scan->custom_private)) ?
						"lookup_policy_index" : "enumerate_policy_index", es);
	ExplainPropertyText("AF Authorization", "exact_transactional_policy_index", es);
	ExplainPropertyText("AF Algorithm", af_modes[intVal(lthird(scan->custom_private))].name, es);
}

static List *
exact_policy_subplans(Node *policy)
{
	List	   *ids = NIL;
	ListCell   *lc;

	if (IsA(policy, SubPlan))
		return list_make1_int(castNode(SubPlan, policy)->plan_id);
	if (!IsA(policy, AlternativeSubPlan))
		return NIL;
	foreach(lc, castNode(AlternativeSubPlan, policy)->subplans)
	{
		if (!IsA(lfirst(lc), SubPlan))
			return NIL;
		ids = lappend_int(ids, lfirst_node(SubPlan, lc)->plan_id);
	}
	return ids;
}

static Plan *
plan_exact_path(PlannerInfo *root, RelOptInfo *rel, CustomPath *path,
				List *target, List *clauses, List *children)
{
	CustomScan *scan = makeNode(CustomScan);
	Plan	   *child = (Plan *) linitial(children);
	Node	   *policy = linitial(path->custom_private);
	Var		   *key = lsecond_node(Var, path->custom_private);
	List	   *subplan_ids = exact_policy_subplans(policy);
	ListCell   *lc;
	bool		key_retained = false;

	foreach(lc, child->targetlist)
		if (equal(lfirst_node(TargetEntry, lc)->expr, key))
		key_retained = true;
	if (!key_retained || !list_member(child->qual, policy) || subplan_ids == NIL)
		elog(ERROR, "invalid AF exact policy lowering");

	scan->scan.plan.targetlist = target;
	scan->scan.scanrelid = rel->relid;
	scan->custom_plans = children;
	scan->custom_scan_tlist = copyObject(child->targetlist);
	scan->custom_private = list_make4(lthird(path->custom_private), subplan_ids,
									  makeInteger(key->varattno),
									  makeConst(OIDOID, -1, InvalidOid, sizeof(Oid),
												ObjectIdGetDatum(planner_rt_fetch(rel->relid, root)->relid),
												false, true));
	scan->methods = &exact_scan_methods;
	return &scan->scan.plan;
}

static Node *
create_exact_scan(CustomScan *scan)
{
	AfScanState *state = palloc0(sizeof(*state));

	NodeSetTag(&state->css, T_CustomScanState);
	state->css.methods = &exact_exec_methods;
	return (Node *) &state->css;
}

static Plan *
plan_completed_hash_path(PlannerInfo *root, RelOptInfo *rel, CustomPath *path,
						 List *target, List *clauses, List *children)
{
	CustomScan *scan = makeNode(CustomScan);
	Plan	   *child = (Plan *) linitial(children);
	AlternativeSubPlan *policy = linitial_node(AlternativeSubPlan, path->custom_private);
	SubPlan    *hash = linitial_node(SubPlan, policy->subplans);
	Var		   *key = lsecond_node(Var, path->custom_private);

	if (list_length(children) != 1 || list_length(policy->subplans) != 1 ||
		!list_member(child->qual, policy) || !hash->useHashTable)
		elog(ERROR, "invalid AF completed hash policy lowering");
	scan->scan.plan.targetlist = target;
	scan->scan.scanrelid = rel->relid;
	scan->custom_plans = children;
	scan->custom_scan_tlist = copyObject(child->targetlist);
	scan->custom_private = list_make5(makeInteger(hash->plan_id),
									  makeInteger(key->varattno),
									  makeConst(OIDOID, -1, InvalidOid, sizeof(Oid),
												ObjectIdGetDatum(planner_rt_fetch(rel->relid, root)->relid), false, true),
									  lthird(path->custom_private), lfourth(path->custom_private));
	scan->custom_private = lappend(scan->custom_private,
								   list_nth(path->custom_private, 4));
	scan->methods = &completed_hash_scan_methods;
	return &scan->scan.plan;
}

static Node *
create_completed_hash_scan(CustomScan *scan)
{
	AfScanState *state = palloc0(sizeof(*state));

	NodeSetTag(&state->css, T_CustomScanState);
	state->css.methods = &completed_hash_exec_methods;
	return (Node *) &state->css;
}

static void
begin_completed_hash_scan(CustomScanState *node, EState *estate, int eflags)
{
	AfScanState *state = (AfScanState *) node;
	CustomScan *scan = castNode(CustomScan, node->ss.ps.plan);
	Plan	   *child;
	Oid			heap;

	native_af_check_serial_scan(scan, estate);

	if (list_length(scan->custom_plans) != 1)
		elog(ERROR, "invalid AF completed hash child count");
	child = (Plan *) linitial(scan->custom_plans);
	heap = DatumGetObjectId(lthird_node(Const, scan->custom_private)->constvalue);
	if (RelationGetRelid(node->ss.ss_currentRelation) != heap)
		elog(ERROR, "invalid AF completed hash heap binding");
	state->child = ExecInitNode(child, estate, eflags);
	if (!native_af_hash_policy_binding(estate, state->child,
									   scan->scan.scanrelid, heap, intVal(lsecond(scan->custom_private)),
									   intVal(linitial(scan->custom_private)), lfourth(scan->custom_private)))
		elog(ERROR, "invalid AF completed hash policy binding");
	state->execution_family = AF_EXEC_COMPLETED_HASH;
	node->custom_ps = list_make1(state->child);
}

static void
explain_completed_hash_scan(CustomScanState *node, List *ancestors, ExplainState *es)
{
	CustomScan *scan = castNode(CustomScan, node->ss.ps.plan);
	ListCell   *cell;

	ExplainPropertyText("AF Path", "completed_hash_policy", es);
	ExplainPropertyText("AF Authorization", "native_exact_policy_hash", es);
	ExplainPropertyText("AF Hash Source", "original_rls_alternative", es);
	ExplainPropertyInteger("AF Hash SubPlan", NULL,
						   intVal(linitial(scan->custom_private)), es);
	ExplainPropertyFloat("AF Hash Evaluations Upper Estimate", NULL,
						 floatVal(list_nth(scan->custom_private, 5)), 0, es);
	ExplainOpenGroup("AF Original Policy Alternatives", "AF Original Policy Alternatives", false, es);
	foreach(cell, (List *) list_nth(scan->custom_private, 4))
	{
		List	   *arm = lfirst(cell);

		ExplainOpenGroup("Alternative", NULL, true, es);
		ExplainPropertyInteger("SubPlan", NULL, intVal(linitial(arm)), es);
		ExplainPropertyBool("Hash", intVal(lsecond(arm)), es);
		ExplainPropertyFloat("Startup Cost", NULL, floatVal(lthird(arm)), 6, es);
		ExplainPropertyFloat("Per Call Cost", NULL, floatVal(lfourth(arm)), 9, es);
		ExplainCloseGroup("Alternative", NULL, true, es);
	}
	ExplainCloseGroup("AF Original Policy Alternatives", "AF Original Policy Alternatives", false, es);
}

static void
begin_exact_scan(CustomScanState *node, EState *estate, int eflags)
{
	AfScanState *state = (AfScanState *) node;
	CustomScan *scan = castNode(CustomScan, node->ss.ps.plan);
	Plan	   *child = (Plan *) linitial(scan->custom_plans);
	ListCell   *lc;
	bool		policy_bound = false;
	bool		key_retained = false;
	List	   *subplan_ids = lsecond(scan->custom_private);
	AttrNumber	key_attribute = intVal(lthird(scan->custom_private));
	Oid			expected_heap = DatumGetObjectId(lfourth_node(Const, scan->custom_private)->constvalue);

	native_af_check_serial_scan(scan, estate);

	if ((!IsA(child, SeqScan) && !IsA(child, BitmapHeapScan) && !IsA(child, IndexScan)) ||
		((Scan *) child)->scanrelid != scan->scan.scanrelid)
		elog(ERROR, "invalid AF exact policy scan child");
	foreach(lc, child->qual)
		if (IsA(lfirst(lc), SubPlan) &&
			list_member_int(subplan_ids, lfirst_node(SubPlan, lc)->plan_id))
		policy_bound = true;
	foreach(lc, child->targetlist)
	{
		TargetEntry *entry = lfirst_node(TargetEntry, lc);

		if (IsA(entry->expr, Var))
		{
			Var		   *key = castNode(Var, entry->expr);

			if (key->varno == scan->scan.scanrelid && key->varattno == key_attribute &&
				key->varlevelsup == 0 && key->vartype == INT8OID)
				key_retained = true;
		}
	}
	if (!policy_bound || !key_retained ||
		RelationGetRelid(node->ss.ss_currentRelation) != expected_heap)
		elog(ERROR, "invalid AF exact policy binding");
	state->execution_family = AF_EXEC_POLICY_CHECK;
	state->child = ExecInitNode(child, estate, eflags);
	node->custom_ps = list_make1(state->child);
}

static void
explain_exact_scan(CustomScanState *node, List *ancestors, ExplainState *es)
{
	CustomScan *scan = castNode(CustomScan, node->ss.ps.plan);

	ExplainPropertyText("AF Path", "exact_policy_check", es);
	ExplainPropertyText("AF Authorization", "native_exact_policy", es);
	native_af_sp_explain(linitial(scan->custom_private), es);
}

static Node *
create_membership_scan(CustomScan *scan)
{
	AfScanState *state = palloc0(sizeof(*state));

	NodeSetTag(&state->css, T_CustomScanState);
	state->css.methods = &membership_exec_methods;
	return (Node *) &state->css;
}

static void
begin_membership_scan(CustomScanState *node, EState *estate, int eflags)
{
	AfScanState *state = (AfScanState *) node;
	CustomScan *scan = castNode(CustomScan, node->ss.ps.plan);

	native_af_check_serial_scan(scan, estate);

	if (list_length(scan->custom_plans) != 2)
		elog(ERROR, "invalid AF membership branch count");
	state->execution_family = intVal(list_nth(scan->custom_private, 6)) ?
		AF_EXEC_MEMBER_KEY : AF_EXEC_MEMBER_ENUM;
	state->fast_child = ExecInitNode((Plan *) linitial(scan->custom_plans), estate, eflags);
	state->fallback_child = ExecInitNode((Plan *) lsecond(scan->custom_plans), estate, eflags);
	state->child = state->fast_child;
	state->member_guard_pending = true;
	node->custom_ps = list_make2(state->fast_child, state->fallback_child);
}

static void
validate_membership_execution(CustomScanState *node)
{
	AfScanState *state = (AfScanState *) node;
	CustomScan *scan = castNode(CustomScan, node->ss.ps.plan);
	List	   *binding = scan->custom_private;
	EState	   *estate = node->ss.ps.state;
	int			param_id = intVal(list_nth(binding, 3));
	int			maximum = intVal(list_nth(binding, 11));
	bool		valid;

	valid = native_af_member_binding(estate, state->fast_child->plan,
									 scan->scan.scanrelid,
									 DatumGetObjectId(list_nth_node(Const, binding, 7)->constvalue),
									 DatumGetObjectId(list_nth_node(Const, binding, 8)->constvalue),
									 intVal(linitial(binding)), param_id,
									 intVal(list_nth(binding, 9)), list_nth(binding, 10),
									 intVal(list_nth(binding, 13)) != 0);
	if (valid)
	{
		ParamExecData *parameter = &estate->es_param_exec_vals[param_id];

		ExecSetParamPlan(parameter->execPlan, node->ss.ps.ps_ExprContext);
		if (parameter->isnull)
			state->fallback_reason = "runtime_binding";
		else
		{
			ArrayType  *keys = DatumGetArrayTypeP(parameter->value);

			if (ARR_ELEMTYPE(keys) != INT8OID || ARR_NDIM(keys) > 1)
				state->fallback_reason = "runtime_binding";
			else if (ArrayGetNItems(ARR_NDIM(keys), ARR_DIMS(keys)) > maximum)
				state->fallback_reason = "authorization_key_capacity";
		}
	}
	else
		state->fallback_reason = "runtime_binding";

	if (state->fallback_reason != NULL)
	{
		state->child = state->fallback_child;
		state->execution_family = AF_EXEC_FALLBACK;
	}
	state->member_guard_pending = false;
}

static TupleTableSlot *
exec_membership_scan(CustomScanState *node)
{
	AfScanState *state = (AfScanState *) node;
	CustomScan *scan = castNode(CustomScan, node->ss.ps.plan);
	TupleTableSlot *slot;
	TupleTableSlot *scan_slot = node->ss.ss_ScanTupleSlot;
	ProjectionInfo *projection = node->ss.ps.ps_ProjInfo;
	int			columns;
	int			attribute;

	if (state->member_guard_pending)
		validate_membership_execution(node);
	if (!state->execution_counted)
	{
		native_af_executions[state->execution_family]++;
		state->execution_counted = true;
	}
	slot = ExecProcNode(state->child);
	if (TupIsNull(slot))
	{
		ExecClearTuple(scan_slot);
		if (projection != NULL)
			return ExecClearTuple(projection->pi_state.resultslot);
		return scan_slot;
	}

	/*
	 * A NIL logical input uses the heap descriptor in ExecInitCustomScan.
	 * This empty projection reads no input fields, including fallback extras.
	 */
	if (scan->custom_scan_tlist == NIL && scan->scan.plan.targetlist == NIL &&
		scan->scan.plan.qual == NIL && projection != NULL)
	{
		ResetExprContext(node->ss.ps.ps_ExprContext);
		node->ss.ps.ps_ExprContext->ecxt_scantuple = slot;
		return ExecProject(projection);
	}

	/*
	 * CustomScan declares virtual input, even when its child elides
	 * projection. Borrow the validated prefix until the next child fetch,
	 * like ExecProject. A fallback may expose extra columns after the agreed
	 * output prefix.
	 */
	columns = scan_slot->tts_tupleDescriptor->natts;
	if (scan_slot->tts_ops != &TTSOpsVirtual || slot == scan_slot ||
		slot->tts_tupleDescriptor->natts < columns)
		elog(ERROR, "invalid AF custom scan tuple binding");
	slot_getsomeattrs(slot, columns);
	ExecClearTuple(scan_slot);
	for (attribute = 0; attribute < columns; attribute++)
	{
		scan_slot->tts_values[attribute] = slot->tts_values[attribute];
		scan_slot->tts_isnull[attribute] = slot->tts_isnull[attribute];
	}
	ExecStoreVirtualTuple(scan_slot);
	if (projection == NULL)
		return scan_slot;

	ResetExprContext(node->ss.ps.ps_ExprContext);
	node->ss.ps.ps_ExprContext->ecxt_scantuple = scan_slot;
	return ExecProject(projection);
}

static void
end_membership_scan(CustomScanState *node)
{
	AfScanState *state = (AfScanState *) node;

	if (state->fallback_child != NULL)
	{
		ExecEndNode(state->fast_child);
		ExecEndNode(state->fallback_child);
	}
	else
		ExecEndNode(state->child);
}

static void
rescan_membership_scan(CustomScanState *node)
{
	AfScanState *state = (AfScanState *) node;

	if (state->member_guard_pending)
	{
		/*
		 * ExecReScan of an index can evaluate its runtime array key. Preserve
		 * invalidation now, and defer all branch work until the first-fetch
		 * guard has checked the actual source and capacity.
		 */
		if (node->ss.ps.chgParam != NULL)
		{
			UpdateChangedParamSet(state->fast_child, node->ss.ps.chgParam);
			UpdateChangedParamSet(state->fallback_child, node->ss.ps.chgParam);
		}
		return;
	}
	if (node->ss.ps.chgParam != NULL)
		UpdateChangedParamSet(state->child, node->ss.ps.chgParam);
	if (state->child->chgParam == NULL)
		ExecReScan(state->child);
}

static void
explain_membership_scan(CustomScanState *node, List *ancestors, ExplainState *es)
{
	CustomScan *scan = castNode(CustomScan, node->ss.ps.plan);
	AfScanState *state = (AfScanState *) node;

	ExplainPropertyText("AF Actual Branch", state->member_guard_pending ? "not_executed" :
						(state->fallback_reason == NULL ? "authorized_index" : "native_fallback"), es);
	if (state->fallback_reason != NULL)
		ExplainPropertyText("AF Fallback Reason", state->fallback_reason, es);
	ExplainPropertyText("AF Path", intVal(list_nth(scan->custom_private, 6)) ?
						"lookup_authorized_key" : "enumerate_authorized_keys", es);
	ExplainPropertyText("AF Authorization", "fresh_exact_membership", es);
	if (intVal(list_nth(scan->custom_private, 13)))
		ExplainPropertyText("AF Principal Binding", "execution_current_user", es);
	ExplainPropertyText("AF Algorithm", af_modes[intVal(lthird(scan->custom_private))].name, es);
	ExplainPropertyInteger("AF Key Parameter", NULL,
						   intVal(list_nth(scan->custom_private, 3)), es);
	ExplainPropertyInteger("AF Key Attribute", NULL,
						   intVal(linitial(scan->custom_private)), es);
	ExplainPropertyFloat("AF ACL Estimated Rows", NULL,
						 floatVal(lsecond(scan->custom_private)), 0, es);
	ExplainPropertyFloat("AF Original Relation Rows", NULL,
						 floatVal(list_nth(scan->custom_private, 4)), 0, es);
	{
		List	   *costs = list_nth(scan->custom_private, 12);

		ExplainPropertyFloat("AF Estimated Distinct Keys", NULL,
							 floatVal(linitial(costs)), 0, es);
		ExplainPropertyFloat("AF Source Plan Cost", NULL,
							 floatVal(lsecond(costs)), 2, es);
		ExplainPropertyFloat("AF Array Build Cost", NULL,
							 floatVal(lthird(costs)), 2, es);
		ExplainPropertyFloat("AF Array Sort Unique Cost", NULL,
							 floatVal(lfourth(costs)), 2, es);
	}
	if (list_nth(scan->custom_private, 5) != NULL)
		native_af_sp_explain(list_nth(scan->custom_private, 5), es);
}


/* One statement-local, structurally admitted whole-query alternative. */
typedef struct AfBatchContext
{
	Query	   *query;
	SubLink    *keys;
	ScalarArrayOpExpr *filter;
	bool		lowered;
	bool		rejected;
	Index		inner_rti;
	int			param_id;
	Index		outer_rti;
	AttrNumber	outer_key;
	AttrNumber	inner_key;
	int			array_plan_id;
	List	   *producer_carriers;
	Oid			principal;
	Snapshot	planning_snapshot;
	bool		domain_costed;
	Bitmapset  *input_relids;
	bool		pair_first;
} AfBatchContext;

typedef struct AfBatchVars
{
	Query	   *query;
	Index		protected_rti;
	Bitmapset  *needed;
	int		   *mapping;
	bool		valid;
} AfBatchVars;

static AfBatchContext *af_batch_context;

/* -------------------------------------------------------------------------
 * Cost scope and cache-aware cost adjustment
 *
 * native_af.cache_aware_cost samples shared buffers and native_af.os_cache_cost
 * samples the operating-system page cache (native_af_os_cache.c).  Both only
 * lower the I/O part of an AF candidate's estimated cost.
 * -------------------------------------------------------------------------
 */

/* Cost scope: each standard planner invocation owns a metadata scope.  Only the
 * explicit private replan below consumes a one-use sharing ticket.  Ordinary
 * recursive planning obtains its own scope, then restores its parent. */
#define AF_CACHE_SAMPLE_BUFFERS 4096

typedef struct AfCacheSample
{
	int			samples;
	int			valid;
	int			fractions;
	int			os_segment_probes;
	RelFileLocator locators[AF_CACHE_SAMPLE_BUFFERS];
	struct
	{
		Oid			relation;
		double		pages;
		double		resident;
	}			estimates[128];
} AfCacheSample;

/* The join-chain identities of a key-driven input belong to the original main Query only.  They do not
 * participate in costing and never survive as executor pointers. */
typedef struct AfStreamDomain
{
	bool		collected;
	bool		eligible;
	Var		   *protected_key;
	Var		   *source_fk;
	Var		   *source;
	Var		   *target;
	Oid			protected_oid;
	Oid			source_oid;
	Oid			target_oid;
	Oid			first_operator;
	Oid			operator;
} AfStreamDomain;

typedef struct AfStreamMark
{
	IndexScan  *scan;
	Oid			index_oid;
} AfStreamMark;

/* A narrow identity snapshot survives normal expression preprocessing. */
typedef struct AfCostRteIdentity
{
	RTEKind		kind;
	Oid			relation;
	Index		permission;
	bool		security_barrier;
	bool		lateral;
} AfCostRteIdentity;

typedef struct AfCostShapeNode
{
	NodeTag		tag;
	Index		rti;
	JoinType	jointype;
	List	   *children;
} AfCostShapeNode;

typedef struct AfCostShape
{
	int			nrtes;
	AfCostRteIdentity *rtes;
	AfCostShapeNode *tree;
} AfCostShape;

typedef struct AfCostScope
{
	struct AfCostScope *previous;
	struct AfCostScope *owner;
	MemoryContext memory;
	AfCacheSample *sample;
	Query	   *query;
	AfStreamDomain stream;
	List	   *stream_marks;
	AfCostShape shape;
	PlannerInfo *join_root;
	List	   *join_rtable;
	FromExpr   *join_tree;
	Snapshot	join_snapshot;
	Oid			join_role;
	uint64		join_scope_reuses;
	bool		join_scope_ok;
	bool		eligible;
	bool		membership_ready;
	bool		shared;
} AfCostScope;

static bool stream_collect(Query *query, AfStreamDomain *domain);
static void stream_capture_shape(AfCostScope *scope);
static bool stream_cost_scope_matches(PlannerInfo *root);

void *
native_af_cost_enter(Query *parse)
{
	/* Only the existing one-use private batch ticket may share an owner. */
	AfCostScope *shared = af_cost_share_target == af_cost_scope &&
		af_cost_scope != NULL && af_batch_depth > 0 &&
		af_batch_context != NULL && af_batch_context->query == parse ?
		af_cost_scope : NULL;
	AfCostScope *scope = NULL;
	MemoryContext context;
	MemoryContext previous = CurrentMemoryContext;
	volatile bool initialized = false;

	af_cost_share_target = NULL;
	if (native_af_mode != AF_ADMISSION_FIRST)
		return NULL;
	context = AllocSetContextCreate(CurrentMemoryContext,
									"AF planner cost metadata", ALLOCSET_SMALL_SIZES);

	/*
	 * No scope is pushed until all catalog collection and allocation succeed.
	 * ERROR restores the prior context before deleting this unpushed scope.
	 */
	PG_TRY();
	{
		MemoryContextSwitchTo(context);
		scope = palloc0(sizeof(*scope));
		scope->previous = af_cost_scope;
		scope->memory = context;
		scope->query = parse;
		scope->owner = shared != NULL ? shared->owner : scope;
		scope->shared = shared != NULL;
		if (shared != NULL)
			scope->eligible = shared->owner->eligible;
		else
		{
			scope->stream.collected = true;
			scope->stream.eligible = stream_collect(parse, &scope->stream);
			scope->eligible = scope->stream.eligible;
		}
		if (scope->eligible)
			stream_capture_shape(scope);
		initialized = true;
	}
	PG_FINALLY();
	{
		MemoryContextSwitchTo(previous);
		if (!initialized)
			MemoryContextDelete(context);
	}
	PG_END_TRY();
	af_cost_scope = scope;
	return scope;
}

void
native_af_cost_leave(void *token)
{
	AfCostScope *scope = token;

	if (scope == NULL)
		return;
	Assert(af_cost_scope == scope);
	af_cost_scope = scope->previous;
	MemoryContextDelete(scope->memory);
}

/* This observes backing-object metadata only, through the same permanent
 * locator already locked by planning.  No mapped byte is dereferenced.  Small
 * relations use the shared-buffer observation, avoiding extra work on cheap
 * queries.  A statement has at most 16 segment probes / 2048 OS page samples. */
static double
cache_os_resident_share(AfCacheSample *sample, RelFileLocator locator, double pages)
{
	char	   *base;
	uint64		bytes = 0;
	double		weighted = 0;
	uint64		observations = 0;
	int			segment;
	bool		complete = false;
	bool		known = true;
	double		probability;
	double		z = 1.645;
	double		denominator;
	double		center;
	double		uncertainty;

	if (!native_af_os_cache_cost || pages <= NBuffers / 4.0)
		return 0.0;
	base = relpathperm(locator, MAIN_FORKNUM);
	for (segment = 0; segment <= 8; segment++)
	{
		char	   *path = segment == 0 ? pstrdup(base) : psprintf("%s.%d", base, segment);
		int			fd = OpenTransientFile(path, O_RDONLY | PG_BINARY);
		AfOsCacheResult observed;

		if (fd < 0)
		{
			int			error = errno;

			pfree(path);
			if (segment > 0 && error == ENOENT)
				complete = true;
			else
				known = false;
			break;
		}
		if (segment == 8 || sample->os_segment_probes >= 16)
		{
			CloseTransientFile(fd);
			pfree(path);
			known = false;
			break;
		}
		sample->os_segment_probes++;
		af_os_cache_probe_fd(fd, 128, &observed);
		CloseTransientFile(fd);
		pfree(path);
		if (!observed.known)
		{
			known = false;
			break;
		}
		bytes += observed.file_bytes;
		weighted += observed.resident_fraction * observed.file_bytes;
		observations += observed.sampled_pages;
		CHECK_FOR_INTERRUPTS();
	}
	pfree(base);
	if (!known || !complete || bytes == 0 || observations == 0)
		return 0.0;

	/*
	 * Size weighting covers a short final segment.  Wilson-shaped shrinkage
	 * is an estimation heuristic, not a statistical coverage guarantee.
	 */
	probability = weighted / bytes;
	denominator = 1.0 + z * z / observations;
	center = probability + z * z / (2.0 * observations);
	uncertainty = z * sqrt(probability * (1.0 - probability) / observations +
						   z * z / (4.0 * observations * observations));
	return Max(0.0, (center - uncertainty) / denominator);
}

static double
cache_resident_share(Oid relation_oid, double pages)
{
	AfCostScope *owner = af_cost_scope->owner;
	AfCacheSample *sample = owner->sample;
	Relation	relation;
	RelFileLocator locator;
	int			matches = 0;
	int			i;
	double		probability;
	double		lower;
	double		denominator;
	double		center;
	double		uncertainty;
	double		resident;

	if (sample != NULL)
		for (i = 0; i < sample->fractions; i++)
			if (sample->estimates[i].relation == relation_oid &&
				sample->estimates[i].pages == pages)
				return sample->estimates[i].resident;
	relation = relation_open(relation_oid, NoLock);
	if (RELATION_IS_LOCAL(relation))
	{
		relation_close(relation, NoLock);
		return 0.0;
	}
	locator = relation->rd_locator;
	relation_close(relation, NoLock);
	if (sample == NULL)
	{
		sample = MemoryContextAllocZero(owner->memory, sizeof(*sample));
		owner->sample = sample;
		sample->samples = Min(NBuffers, AF_CACHE_SAMPLE_BUFFERS);
		for (i = 0; i < sample->samples; i++)
		{
			int			begin = ((int64) i * NBuffers) / sample->samples;
			int			end = ((int64) (i + 1) * NBuffers) / sample->samples;
			int			offset = ((uint32) i * 2654435761U + 1013904223U) % (end - begin);
			BufferDesc *buffer;
			uint32		state;

			CHECK_FOR_INTERRUPTS();
			buffer = GetBufferDescriptor(begin + offset);
			state = LockBufHdr(buffer);
			if ((state & BM_VALID) && (state & BM_TAG_VALID) &&
				BufTagGetForkNum(&buffer->tag) == MAIN_FORKNUM)
				sample->locators[sample->valid++] = BufTagGetRelFileLocator(&buffer->tag);
			UnlockBufHdr(buffer, state);
		}
	}
	for (i = 0; i < sample->valid; i++)
	{
		RelFileLocator *observed = &sample->locators[i];

		if (observed->spcOid == locator.spcOid && observed->dbOid == locator.dbOid &&
			observed->relNumber == locator.relNumber)
			matches++;
	}
	probability = (double) matches / sample->samples;
	denominator = 1.0 + (1.645 * 1.645) / sample->samples;
	center = probability + (1.645 * 1.645) / (2.0 * sample->samples);
	uncertainty = 1.645 * sqrt(probability * (1.0 - probability) / sample->samples +
							   (1.645 * 1.645) / (4.0 * sample->samples * sample->samples));
	lower = Max(0.0, (center - uncertainty) / denominator);
	resident = Min(1.0, lower * NBuffers / pages);

	/*
	 * Shared and backing-file residency overlap.  max is a conservative union
	 * estimate; never add them or apply two successive discounts. Existing
	 * tuple/qual/index-page/descent CPU costs remain unchanged.
	 */
	resident = Max(resident, cache_os_resident_share(sample, locator, pages));
	if (sample->fractions < lengthof(sample->estimates))
	{
		i = sample->fractions++;
		sample->estimates[i].relation = relation_oid;
		sample->estimates[i].pages = pages;
		sample->estimates[i].resident = resident;
	}
	if (native_af_trace && superuser())
		ereport(NOTICE,
				(errmsg("AF_CACHE relation %u pages %.0f matches %d/%d resident_lower %.6f",
						relation_oid, pages, matches, sample->samples, resident)));
	return resident;
}

double
native_af_cache_io_fraction(PlannerInfo *root, Oid relation_oid, double pages,
							double page_events, double scans)
{
	double		resident;
	double		first_touch_share;

	if (root == NULL || native_af_mode != AF_ADMISSION_FIRST ||
		!native_af_cache_aware_cost || IsParallelWorker() ||
		af_cost_scope == NULL || !af_cost_scope->owner->eligible ||
		!af_cost_scope->owner->membership_ready || !stream_cost_scope_matches(root) ||
		pages <= 0 || !isfinite(pages) || page_events <= 0 || !isfinite(page_events))
		return 1.0;
	resident = cache_resident_share(relation_oid, pages);

	/*
	 * M&L has already charged repeated misses/refetches.  Initial residency
	 * can save at most one relation's unique pages over all these scans.
	 */
	first_touch_share = Min(1.0, pages / (page_events * Max(1.0, scans)));
	return 1.0 - resident * first_touch_share;
}

/* -------------------------------------------------------------------------
 * Shared checked inputs across joins ("batch")
 *
 * native_af_batch_choose() plans a query a second time with the checked
 * protected input shared by the joins that read it, and keeps whichever
 * complete plan has the lower total cost.
 * -------------------------------------------------------------------------
 */

static bool batch_relation(RangeTblEntry *rte, bool *rls);
static RTEPermissionInfo *batch_permission(Query *query, RangeTblEntry *rte);
static bool batch_principal_expression(Node *node, void *unused);

static bool
batch_type(Oid type)
{
	return principal_preserving_type(type) || type == INT2OID || type == OIDOID ||
		type == NUMERICOID || type == FLOAT4OID || type == FLOAT8OID ||
		type == DATEOID || type == TIMESTAMPOID || type == TIMESTAMPTZOID ||
		type == INTERVALOID || type == BPCHAROID || type == VARCHAROID;
}

static bool
batch_function(Oid function)
{
	return OidIsValid(function) && function <= fmgr_last_builtin_oid &&
		fmgr_builtin_oid_index[function] != InvalidOidBuiltinMapping &&
		get_func_namespace(function) == PG_CATALOG_NAMESPACE &&
		func_volatile(function) != PROVOLATILE_VOLATILE;
}

/* Include index expressions/opclasses: immutable user code is not trusted. */
static bool
batch_indexes_safe(Oid heap)
{
	Relation	table = table_open(heap, AccessShareLock);
	List	   *indexes = RelationGetIndexList(table);
	ListCell   *lc;
	bool		valid = true;

	foreach(lc, indexes)
	{
		Relation	index = index_open(lfirst_oid(lc), AccessShareLock);
		int			column;

		if (index->rd_rel->relam != BTREE_AM_OID ||
			index->rd_amhandler != F_BTHANDLER ||
			batch_principal_expression((Node *) RelationGetIndexExpressions(index), NULL) ||
			batch_principal_expression((Node *) RelationGetIndexPredicate(index), NULL))
			valid = false;
		for (column = 1; valid && column <= index->rd_index->indnkeyatts; column++)
		{
			Oid			class_oid = get_index_column_opclass(RelationGetRelid(index), column);
			HeapTuple	tuple = SearchSysCache1(CLAOID, ObjectIdGetDatum(class_oid));

			if (!HeapTupleIsValid(tuple))
				valid = false;
			else
			{
				Form_pg_opclass op = (Form_pg_opclass) GETSTRUCT(tuple);

				valid = class_oid < FirstGenbkiObjectId &&
					op->opcnamespace == PG_CATALOG_NAMESPACE &&
					op->opcmethod == BTREE_AM_OID && batch_type(op->opcintype);
				ReleaseSysCache(tuple);
			}
		}
		index_close(index, NoLock);
		if (!valid)
			break;
	}
	list_free(indexes);
	table_close(table, NoLock);
	return valid;
}

/* The join input filter retains all business expressions. Recognize only
 * the parser's constant string-list forms of a built-in text equality. */
static bool
af_prefilter_literal_array(Node *node, Oid array_type, Oid element_type)
{
	ArrayExpr  *array;
	ListCell   *lc;

	if (IsA(node, Const))
		return castNode(Const, node)->consttype == array_type;
	if (!IsA(node, ArrayExpr))
		return false;
	array = castNode(ArrayExpr, node);
	if (array->multidims || array->array_typeid != array_type ||
		array->element_typeid != element_type)
		return false;
	foreach(lc, array->elements)
	{
		Node	   *element = lfirst(lc);

		if (!IsA(element, Const) || castNode(Const, element)->consttype != element_type)
			return false;
	}
	return true;
}

static bool
af_prefilter_text_list(ScalarArrayOpExpr *operation)
{
	Node	   *array;

	if (operation->opno != TextEqualOperator || !operation->useOr ||
		(OidIsValid(operation->opfuncid) && operation->opfuncid != F_TEXTEQ) ||
		OidIsValid(operation->hashfuncid) || OidIsValid(operation->negfuncid) ||
		list_length(operation->args) != 2 ||
		exprType(linitial(operation->args)) != TEXTOID)
		return false;
	array = lsecond(operation->args);
	if (af_prefilter_literal_array(array, TEXTARRAYOID, TEXTOID))
		return true;
	if (IsA(array, ArrayCoerceExpr))
	{
		ArrayCoerceExpr *cast = castNode(ArrayCoerceExpr, array);
		RelabelType *relabel;

		if (cast->resulttype != TEXTARRAYOID || cast->resulttypmod != -1 ||
			!IsA(cast->elemexpr, RelabelType))
			return false;
		relabel = castNode(RelabelType, cast->elemexpr);
		return relabel->resulttype == TEXTOID && relabel->resulttypmod == -1 &&
			IsA(relabel->arg, CaseTestExpr) &&
			castNode(CaseTestExpr, relabel->arg)->typeId == VARCHAROID &&
			af_prefilter_literal_array((Node *) cast->arg, VARCHARARRAYOID, VARCHAROID);
	}
	return false;
}

static bool
batch_principal_expression(Node *node, void *unused)
{
	if (node == NULL)
		return false;
	if (IsA(node, Query))
	{
		Query	   *query = castNode(Query, node);
		ListCell   *lc;

		if (query->commandType != CMD_SELECT || query->resultRelation != 0 ||
			query->rowMarks != NIL || query->cteList != NIL || query->hasRecursive ||
			query->hasModifyingCTE || query->setOperations != NULL ||
			query->hasTargetSRFs || query->utilityStmt != NULL)
			return true;
		foreach(lc, query->rtable)
		{
			RangeTblEntry *rte = lfirst_node(RangeTblEntry, lc);

			if (rte->rtekind == RTE_RELATION && batch_permission(query, rte) == NULL)
				return true;
		}
		return query_tree_walker(query, batch_principal_expression, unused,
								 QTW_EXAMINE_RTES_BEFORE | QTW_EXAMINE_SORTGROUP);
	}
	if (IsA(node, RangeTblEntry))
	{
		RangeTblEntry *rte = castNode(RangeTblEntry, node);
		bool		rls;

		if (rte->rtekind == RTE_JOIN)
			return rte->jointype != JOIN_INNER || rte->joinmergedcols != 0;
		return !batch_relation(rte, &rls) || !batch_indexes_safe(rte->relid);
	}
	if (IsA(node, Var))
		return !batch_type(castNode(Var, node)->vartype);
	if (IsA(node, Const))
		return !batch_type(castNode(Const, node)->consttype);
	if (IsA(node, SQLValueFunction))
		return !current_user_name(node);
	if (IsA(node, FuncExpr) &&
		(!batch_function(castNode(FuncExpr, node)->funcid) ||
		 !batch_type(castNode(FuncExpr, node)->funcresulttype)))
		return true;
	if ((IsA(node, OpExpr) || IsA(node, DistinctExpr) || IsA(node, NullIfExpr)) &&
		!batch_function(get_opcode(((OpExpr *) node)->opno)))
		return true;
	if (IsA(node, Aggref))
	{
		Aggref	   *agg = castNode(Aggref, node);

		if (agg->aggfnoid >= FirstGenbkiObjectId ||
			get_func_namespace(agg->aggfnoid) != PG_CATALOG_NAMESPACE ||
			!batch_type(agg->aggtype))
			return true;
	}
	if (IsA(node, SortGroupClause))
	{
		SortGroupClause *clause = castNode(SortGroupClause, node);

		return !batch_function(get_opcode(clause->eqop)) ||
			(OidIsValid(clause->sortop) && !batch_function(get_opcode(clause->sortop)));
	}
	if (unused != NULL && IsA(node, ScalarArrayOpExpr) &&
		af_prefilter_text_list(castNode(ScalarArrayOpExpr, node)))
		return batch_principal_expression(linitial(castNode(ScalarArrayOpExpr, node)->args),
										  unused);
	if (IsA(node, Param) || IsA(node, WindowFunc) || IsA(node, CoerceViaIO) ||
		IsA(node, CoerceToDomain) || IsA(node, NextValueExpr) ||
		IsA(node, SubscriptingRef) || IsA(node, RowCompareExpr) ||
		IsA(node, RowExpr) || IsA(node, ArrayExpr) || IsA(node, ArrayCoerceExpr) ||
		IsA(node, ConvertRowtypeExpr) || IsA(node, XmlExpr))
		return true;
	if (IsA(node, RelabelType) && !batch_type(castNode(RelabelType, node)->resulttype))
		return true;
	if (IsA(node, ScalarArrayOpExpr) &&
		!batch_function(get_opcode(castNode(ScalarArrayOpExpr, node)->opno)))
		return true;
	return expression_tree_walker(node, batch_principal_expression, unused);
}

static bool
batch_jointree(Node *node, Query *query, Bitmapset **seen, List **quals)
{
	ListCell   *lc;

	if (node == NULL)
		return false;
	if (IsA(node, RangeTblRef))
	{
		Index		rti = castNode(RangeTblRef, node)->rtindex;

		if (rti == 0 || rti > list_length(query->rtable) ||
			rt_fetch(rti, query->rtable)->rtekind != RTE_RELATION ||
			bms_is_member(rti, *seen))
			return false;
		*seen = bms_add_member(*seen, rti);
		return true;
	}
	if (IsA(node, FromExpr))
	{
		FromExpr   *from = castNode(FromExpr, node);

		foreach(lc, from->fromlist)
			if (!batch_jointree(lfirst(lc), query, seen, quals))
			return false;
		*quals = list_concat(*quals, make_ands_implicit((Expr *) from->quals));
		return from->fromlist != NIL;
	}
	if (IsA(node, JoinExpr))
	{
		JoinExpr   *join = castNode(JoinExpr, node);
		RangeTblEntry *rte;

		if (join->jointype != JOIN_INNER || join->isNatural ||
			join->usingClause != NIL || join->alias != NULL ||
			join->rtindex <= 0 || join->rtindex > list_length(query->rtable))
			return false;
		rte = rt_fetch(join->rtindex, query->rtable);
		if (rte->rtekind != RTE_JOIN || rte->jointype != JOIN_INNER ||
			rte->joinmergedcols != 0 || rte->join_using_alias != NULL)
			return false;
		if (!batch_jointree(join->larg, query, seen, quals) ||
			!batch_jointree(join->rarg, query, seen, quals))
			return false;
		*quals = list_concat(*quals, make_ands_implicit((Expr *) join->quals));
		return true;
	}
	return false;
}

/* Only user expressions, never policy-internal Vars or unused JOIN aliases. */
static bool
batch_user_vars(Node *node, AfBatchVars *context)
{
	if (node == NULL)
		return false;
	if (IsA(node, Query) || IsA(node, SubLink) || IsA(node, SubPlan) ||
		IsA(node, Param) || IsA(node, CurrentOfExpr))
		return true;
	if (IsA(node, Var))
	{
		Var		   *var = castNode(Var, node);

		if (var->varlevelsup != 0 || var->varno <= 0 ||
			var->varno > list_length(context->query->rtable) ||
			var->varattno <= 0 || !bms_is_empty(var->varnullingrels) ||
			rt_fetch(var->varno, context->query->rtable)->rtekind != RTE_RELATION ||
			(var->varnosyn != 0 && var->varnosyn != var->varno) ||
			(var->varnosyn != 0 && var->varattnosyn != var->varattno))
			return true;
		if (var->varno == context->protected_rti)
			context->needed = bms_add_member(context->needed, var->varattno);
		return false;
	}
	return expression_tree_walker(node, batch_user_vars, context);
}

static Node *
batch_map_vars(Node *node, AfBatchVars *context)
{
	if (node == NULL)
		return NULL;
	if (IsA(node, Var))
	{
		Var		   *var = copyObject(castNode(Var, node));

		if (var->varno == context->protected_rti)
		{
			Assert(var->varattno > 0 && context->mapping[var->varattno] > 0);
			var->varattno = context->mapping[var->varattno];
			if (var->varnosyn == context->protected_rti)
				var->varattnosyn = context->mapping[var->varattnosyn];
		}
		return (Node *) var;
	}
	return expression_tree_mutator(node, batch_map_vars, context);
}

static RTEPermissionInfo *
batch_permission(Query *query, RangeTblEntry *rte)
{
	RTEPermissionInfo *info;

	if (rte->perminfoindex == 0 ||
		rte->perminfoindex > list_length(query->rteperminfos))
		return NULL;
	info = list_nth_node(RTEPermissionInfo, query->rteperminfos,
						 rte->perminfoindex - 1);
	if (info->relid != rte->relid || info->requiredPerms != ACL_SELECT ||
		OidIsValid(info->checkAsUser) || info->insertedCols != NULL ||
		info->updatedCols != NULL)
		return NULL;
	return info;
}

/* Catalog guards; ordinary structures remain visible to every mode. */
static bool
batch_relation(RangeTblEntry *rte, bool *rls)
{
	HeapTuple	tuple;
	Form_pg_class form;
	bool		valid;

	if (rte->rtekind != RTE_RELATION || rte->relkind != RELKIND_RELATION ||
		rte->lateral || rte->tablesample != NULL ||
		(rte->inh && has_subclass(rte->relid)))
		return false;
	tuple = SearchSysCache1(RELOID, ObjectIdGetDatum(rte->relid));
	if (!HeapTupleIsValid(tuple))
		return false;
	form = (Form_pg_class) GETSTRUCT(tuple);
	valid = form->relkind == RELKIND_RELATION && form->relam == HEAP_TABLE_AM_OID;
	*rls = form->relrowsecurity;
	ReleaseSysCache(tuple);
	return valid;
}

static bool
batch_index(Oid heap, AttrNumber key, bool unique)
{
	Relation	table = table_open(heap, AccessShareLock);
	List	   *indexes = RelationGetIndexList(table);
	ListCell   *lc;
	bool		found = false;

	foreach(lc, indexes)
	{
		Relation	index = index_open(lfirst_oid(lc), AccessShareLock);

		if (index->rd_rel->relam == BTREE_AM_OID &&
			index->rd_amhandler == F_BTHANDLER &&
			index->rd_index->indisvalid && index->rd_index->indisready &&
			index->rd_index->indislive && index->rd_index->indnkeyatts >= 1 &&
			index->rd_index->indkey.values[0] == key &&
			index->rd_opfamily[0] == INTEGER_BTREE_FAM_OID &&
			RelationGetIndexExpressions(index) == NIL &&
			RelationGetIndexPredicate(index) == NIL &&
			(!unique || (index->rd_index->indisunique &&
						 index->rd_index->indimmediate &&
						 index->rd_index->indnkeyatts == 1)))
			found = true;
		index_close(index, NoLock);
		if (found)
			break;
	}
	list_free(indexes);
	table_close(table, NoLock);
	return found;
}

static double
batch_seq_cost(Plan *plan, Index rti)
{
	double		cost = -1;
	ListCell   *lc;

	if (plan == NULL)
		return cost;
	if (IsA(plan, SeqScan) && castNode(SeqScan, plan)->scan.scanrelid == rti)
		cost = plan->total_cost;
	cost = Max(cost, batch_seq_cost(outerPlan(plan), rti));
	cost = Max(cost, batch_seq_cost(innerPlan(plan), rti));
	if (IsA(plan, CustomScan))
		foreach(lc, castNode(CustomScan, plan)->custom_plans)
			cost = Max(cost, batch_seq_cost(lfirst(lc), rti));
	return cost;
}

/* -------------------------------------------------------------------------
 * Bulk-read buffer rings for key-driven join inputs ("stream")
 *
 * When permitted keys drive a nested-loop chain into a large ordinary
 * table, the index scan of that table may use a BAS_BULKREAD buffer ring
 * so that it does not evict the shared buffers of other relations.
 * -------------------------------------------------------------------------
 */

/* Eligibility reads catalog metadata only: the original all-INNER key chain
 * R.unique (NOT NULL) -> S.fk, S.unique (NOT NULL) -> T.fk.  No statistics, expression evaluation or rewrite. */
static bool
stream_int8_equality(Oid operator)
{
	HeapTuple	tuple = SearchSysCache1(OPEROID, ObjectIdGetDatum(operator));
	Form_pg_operator op;
	bool		valid;

	if (!HeapTupleIsValid(tuple))
		return false;
	op = (Form_pg_operator) GETSTRUCT(tuple);
	valid = op->oprnamespace == PG_CATALOG_NAMESPACE &&
		strcmp(NameStr(op->oprname), "=") == 0 && op->oprkind == 'b' &&
		op->oprleft == INT8OID && op->oprright == INT8OID &&
		op->oprresult == BOOLOID && op->oprcode == F_INT8EQ &&
		op->oprrest == F_EQSEL && op->oprjoin == F_EQJOINSEL;
	ReleaseSysCache(tuple);
	return valid && get_opcode(operator) == F_INT8EQ && func_strict(F_INT8EQ);
}

static bool
stream_plain_var(Node *node, Query *query)
{
	Var		   *var;

	if (node == NULL || !IsA(node, Var))
		return false;
	var = castNode(Var, node);
	return var->vartype == INT8OID && var->varlevelsup == 0 &&
		var->varno > 0 && var->varno <= list_length(query->rtable) &&
		var->varattno > 0 && bms_is_empty(var->varnullingrels) &&
		(var->varnosyn == 0 || (var->varnosyn == var->varno &&
								var->varattnosyn == var->varattno)) &&
		rt_fetch(var->varno, query->rtable)->rtekind == RTE_RELATION;
}

static bool
stream_same_var(Var *left, Var *right)
{
	return left->varno == right->varno && left->varattno == right->varattno &&
		left->vartype == right->vartype && left->vartypmod == right->vartypmod &&
		left->varcollid == right->varcollid;
}

/* preprocess_expression converts ANDs to Lists; explicit INNER JOIN trees can
 * still have nested ANDs.  Flatten only these two conjunctive representations. */
static void
stream_conjuncts(Node *node, List **quals)
{
	ListCell   *lc;

	if (node == NULL)
		return;
	if (IsA(node, List))
	{
		foreach(lc, (List *) node)
			stream_conjuncts(lfirst(lc), quals);
	}
	else if (is_andclause(node))
	{
		foreach(lc, castNode(BoolExpr, node)->args)
			stream_conjuncts(lfirst(lc), quals);
	}
	else
		*quals = lappend(*quals, node);
}

static bool
stream_jointree(Node *node, Query *query, Bitmapset **seen, List **quals)
{
	ListCell   *lc;

	if (node == NULL)
		return false;
	if (IsA(node, RangeTblRef))
	{
		Index		rti = castNode(RangeTblRef, node)->rtindex;

		if (rti == 0 || rti > list_length(query->rtable) ||
			rt_fetch(rti, query->rtable)->rtekind != RTE_RELATION ||
			bms_is_member(rti, *seen))
			return false;
		*seen = bms_add_member(*seen, rti);
		return true;
	}
	if (IsA(node, FromExpr))
	{
		FromExpr   *from = castNode(FromExpr, node);

		foreach(lc, from->fromlist)
			if (!stream_jointree(lfirst(lc), query, seen, quals))
			return false;
		stream_conjuncts(from->quals, quals);
		return from->fromlist != NIL;
	}
	if (IsA(node, JoinExpr))
	{
		JoinExpr   *join = castNode(JoinExpr, node);
		RangeTblEntry *rte;

		if (join->jointype != JOIN_INNER || join->isNatural ||
			join->usingClause != NIL || join->alias != NULL ||
			join->rtindex <= 0 || join->rtindex > list_length(query->rtable))
			return false;
		rte = rt_fetch(join->rtindex, query->rtable);
		if (rte->rtekind != RTE_JOIN || rte->jointype != JOIN_INNER ||
			rte->joinmergedcols != 0 || rte->join_using_alias != NULL)
			return false;
		if (!stream_jointree(join->larg, query, seen, quals) ||
			!stream_jointree(join->rarg, query, seen, quals))
			return false;
		stream_conjuncts(join->quals, quals);
		return true;
	}
	return false;
}

static bool
stream_column(Query *query, Var *var, bool notnull)
{
	Oid			relation = rt_fetch(var->varno, query->rtable)->relid;
	HeapTuple	tuple = SearchSysCache2(ATTNUM, ObjectIdGetDatum(relation),
										Int16GetDatum(var->varattno));
	Form_pg_attribute att;
	bool		valid;

	if (!HeapTupleIsValid(tuple))
		return false;
	att = (Form_pg_attribute) GETSTRUCT(tuple);
	valid = !att->attisdropped && att->atttypid == INT8OID &&
		att->atttypmod == var->vartypmod && att->attcollation == var->varcollid &&
		(!notnull || att->attnotnull);
	ReleaseSysCache(tuple);
	return valid;
}

static bool
stream_edge(Node *node, Query *query)
{
	OpExpr	   *op;

	if (node == NULL || !IsA(node, OpExpr))
		return false;
	op = castNode(OpExpr, node);
	return !op->opretset && op->opresulttype == BOOLOID &&
		list_length(op->args) == 2 && stream_int8_equality(op->opno) &&
		stream_plain_var(linitial(op->args), query) &&
		stream_plain_var(lsecond(op->args), query) &&
		linitial_node(Var, op->args)->varno != lsecond_node(Var, op->args)->varno;
}

static bool
stream_collect(Query *query, AfStreamDomain *domain)
{
	Bitmapset  *seen = NULL;
	List	   *quals = NIL;
	ListCell   *lc;
	ListCell   *edge;
	Index		protected_rti = 0;
	Index		rti = 0;

	if (query == NULL || query->commandType != CMD_SELECT || !query->hasRowSecurity ||
		query->resultRelation != 0 || query->hasModifyingCTE || query->cteList != NIL ||
		query->rowMarks != NIL || query->setOperations != NULL ||
		query->hasTargetSRFs || query->hasRecursive || query->utilityStmt != NULL ||
		!stream_jointree((Node *) query->jointree, query, &seen, &quals) ||
		bms_num_members(seen) != 3)
		return false;
	/* Validate every RTI before looking up any column or uniqueness proof. */
	foreach(lc, query->rtable)
	{
		RangeTblEntry *rte = lfirst_node(RangeTblEntry, lc);
		bool		rls = false;

		rti++;
		if (rte->rtekind == RTE_JOIN)
		{
			if (rte->jointype != JOIN_INNER || rte->joinmergedcols != 0 ||
				rte->alias != NULL || rte->join_using_alias != NULL ||
				rte->securityQuals != NIL || rte->security_barrier ||
				rte->lateral || rte->perminfoindex != 0)
				return false;
			continue;
		}
		if (!bms_is_member(rti, seen) || !batch_relation(rte, &rls) ||
			batch_permission(query, rte) == NULL || rte->security_barrier ||
			has_subclass(rte->relid) || has_superclass(rte->relid))
			return false;
		if (rls)
		{
			if (protected_rti != 0 || rte->securityQuals == NIL)
				return false;
			protected_rti = rti;
		}
		else if (rte->securityQuals != NIL)
			return false;
	}
	if (protected_rti == 0)
		return false;
	foreach(lc, quals)
	{
		OpExpr	   *first;
		Var		   *r;
		Var		   *s_fk;

		if (!stream_edge(lfirst(lc), query))
			continue;
		first = lfirst_node(OpExpr, lc);
		r = linitial_node(Var, first->args);
		s_fk = lsecond_node(Var, first->args);
		if (s_fk->varno == protected_rti)
		{
			Var		   *swap = r;

			r = s_fk;
			s_fk = swap;
		}
		if (r->varno != protected_rti || !stream_column(query, r, true) ||
			!stream_column(query, s_fk, false) ||
			!batch_index(rt_fetch(r->varno, query->rtable)->relid, r->varattno, true))
			continue;
		foreach(edge, quals)
		{
			OpExpr	   *second;
			Var		   *s;
			Var		   *t;

			if (!stream_edge(lfirst(edge), query))
				continue;
			second = lfirst_node(OpExpr, edge);
			s = linitial_node(Var, second->args);
			t = lsecond_node(Var, second->args);
			if (t->varno == s_fk->varno)
			{
				Var		   *swap = s;

				s = t;
				t = swap;
			}
			if (s->varno != s_fk->varno || t->varno == protected_rti ||
				!stream_column(query, s, true) || !stream_column(query, t, false) ||
				!batch_index(rt_fetch(s->varno, query->rtable)->relid, s->varattno, true))
				continue;
			/* Ambiguous source roles keep the original buffer policy. */
			if (domain->source != NULL &&
				(!stream_same_var(domain->source, s) ||
				 !stream_same_var(domain->target, t) ||
				 !stream_same_var(domain->protected_key, r) ||
				 !stream_same_var(domain->source_fk, s_fk)))
				return false;
			if (domain->source == NULL)
			{
				domain->source = copyObject(s);
				domain->target = copyObject(t);
				domain->protected_key = copyObject(r);
				domain->source_fk = copyObject(s_fk);
				domain->protected_oid = rt_fetch(r->varno, query->rtable)->relid;
				domain->source_oid = rt_fetch(s->varno, query->rtable)->relid;
				domain->target_oid = rt_fetch(t->varno, query->rtable)->relid;
				domain->first_operator = first->opno;
				domain->operator = second->opno;
			}
		}
	}
	return domain->source != NULL;
}


/* quals/securityQuals/joinaliasvars and rte.inh legitimately change during
 * preprocessing.  Capture only relation/permission identities and topology. */
static AfCostShapeNode *
stream_capture_shape_node(Node *node)
{
	AfCostShapeNode *saved;
	ListCell   *cell;

	if (node == NULL ||
		(!IsA(node, RangeTblRef) && !IsA(node, FromExpr) && !IsA(node, JoinExpr)))
		return NULL;
	saved = palloc0(sizeof(*saved));
	saved->tag = nodeTag(node);
	if (IsA(node, RangeTblRef))
		saved->rti = castNode(RangeTblRef, node)->rtindex;
	else if (IsA(node, FromExpr))
	{
		foreach(cell, castNode(FromExpr, node)->fromlist)
		{
			AfCostShapeNode *child = stream_capture_shape_node(lfirst(cell));

			if (child == NULL)
				return NULL;
			saved->children = lappend(saved->children, child);
		}
	}
	else
	{
		JoinExpr   *join = castNode(JoinExpr, node);
		AfCostShapeNode *left = stream_capture_shape_node(join->larg);
		AfCostShapeNode *right = stream_capture_shape_node(join->rarg);

		if (left == NULL || right == NULL)
			return NULL;
		saved->rti = join->rtindex;
		saved->jointype = join->jointype;
		saved->children = list_make2(left, right);
	}
	return saved;
}

static void
stream_capture_shape(AfCostScope *scope)
{
	ListCell   *cell;
	int			i = 0;

	if (scope->query == NULL || scope->query->jointree == NULL)
		return;
	scope->shape.nrtes = list_length(scope->query->rtable);
	scope->shape.rtes = palloc0(sizeof(AfCostRteIdentity) * scope->shape.nrtes);
	foreach(cell, scope->query->rtable)
	{
		RangeTblEntry *rte = lfirst_node(RangeTblEntry, cell);
		AfCostRteIdentity *saved = &scope->shape.rtes[i++];

		saved->kind = rte->rtekind;
		saved->relation = rte->rtekind == RTE_RELATION ? rte->relid : InvalidOid;
		saved->permission = rte->perminfoindex;
		saved->security_barrier = rte->security_barrier;
		saved->lateral = rte->lateral;
	}
	scope->shape.tree = stream_capture_shape_node((Node *) scope->query->jointree);
}

static bool
stream_shape_node_matches(AfCostShapeNode *saved, Node *node)
{
	ListCell   *before;
	ListCell   *now;

	if (saved == NULL || node == NULL || saved->tag != nodeTag(node))
		return false;
	if (IsA(node, RangeTblRef))
		return saved->rti == castNode(RangeTblRef, node)->rtindex;
	if (IsA(node, FromExpr))
	{
		List	   *children = castNode(FromExpr, node)->fromlist;

		if (list_length(saved->children) != list_length(children))
			return false;
		forboth(before, saved->children, now, children)
			if (!stream_shape_node_matches(lfirst(before), lfirst(now)))
			return false;
		return true;
	}
	if (IsA(node, JoinExpr))
	{
		JoinExpr   *join = castNode(JoinExpr, node);

		return saved->rti == join->rtindex && saved->jointype == join->jointype &&
			stream_shape_node_matches(linitial(saved->children), join->larg) &&
			stream_shape_node_matches(lsecond(saved->children), join->rarg);
	}
	return false;
}

static bool
stream_cost_scope_recheck(PlannerInfo *root)
{
	AfCostScope *scope = af_cost_scope;
	ListCell   *cell;
	int			i = 0;

	if (root == NULL || root->parent_root != NULL || scope == NULL ||
		scope->query != root->parse || !scope->eligible ||
		(scope->owner != scope && !scope->shared) ||
		scope->shape.tree == NULL ||
		scope->shape.nrtes != list_length(root->parse->rtable))
		return false;
	foreach(cell, root->parse->rtable)
	{
		RangeTblEntry *rte = lfirst_node(RangeTblEntry, cell);
		AfCostRteIdentity *saved = &scope->shape.rtes[i++];

		if (saved->kind != rte->rtekind ||
			saved->relation != (rte->rtekind == RTE_RELATION ? rte->relid : InvalidOid) ||
			saved->permission != rte->perminfoindex ||
			saved->security_barrier != rte->security_barrier || saved->lateral != rte->lateral)
			return false;
	}
	return stream_shape_node_matches(scope->shape.tree, (Node *) root->parse->jointree);
}

/* After base sizing, the supported direct INNER graph and RTE identities
 * are read-only during base/parameterized path and join search. Hooks that
 * can extend this interval keep per-use validation. A private replan or
 * subquery uses its own PlannerInfo and cost scope. */
void
native_af_begin_join_enumeration(PlannerInfo *root)
{
	AfCostScope *scope = af_cost_scope;

	if (native_af_mode != AF_ADMISSION_FIRST || scope == NULL ||
		root->parent_root != NULL || scope->query != root->parse ||
		!scope->owner->eligible || !scope->owner->membership_ready ||
		set_rel_pathlist_hook != NULL || join_search_hook != NULL || native_af_previous_join_hook != NULL ||
		set_join_pathlist_hook != native_af_choice_join_paths)
		return;
	scope->join_root = root;
	scope->join_rtable = root->parse->rtable;
	scope->join_tree = root->parse->jointree;
	scope->join_role = GetUserId();
	scope->join_snapshot = ActiveSnapshotSet() ? GetActiveSnapshot() : NULL;
	scope->join_scope_ok = stream_cost_scope_recheck(root);
	scope->join_scope_reuses = 0;
}

void
native_af_end_join_enumeration(PlannerInfo *root)
{
	AfCostScope *scope = af_cost_scope;

	if (scope == NULL || scope->join_root != root)
		return;
	if (native_af_trace)
		ereport(NOTICE, (errmsg("native_af: join scope reuse " UINT64_FORMAT " validated %d",
								scope->join_scope_reuses, scope->join_scope_ok)));
	scope->join_root = NULL;
}

static bool
stream_cost_scope_matches(PlannerInfo *root)
{
	AfCostScope *scope = af_cost_scope;

	if (root != NULL && scope != NULL && scope->join_root == root)
	{
		if (root->parse == scope->query &&
			root->parse->rtable == scope->join_rtable &&
			root->parse->jointree == scope->join_tree &&
			GetUserId() == scope->join_role &&
			(ActiveSnapshotSet() ? GetActiveSnapshot() : NULL) == scope->join_snapshot)
		{
			if (native_af_trace)
				scope->join_scope_reuses++;
			return scope->join_scope_ok;
		}
		scope->join_root = NULL;
	}
	return stream_cost_scope_recheck(root);
}

static bool
stream_main_scope(PlannerInfo *root)
{
	return native_af_mode == AF_ADMISSION_FIRST && root != NULL &&
		root->parent_root == NULL && af_batch_depth == 0 &&
		af_cost_scope != NULL && af_cost_scope->owner == af_cost_scope &&
		stream_cost_scope_matches(root);
}

/* This is called only after prepare_membership has appended its validated
 * descriptor.  hasRowSecurity alone never enables cache-aware costing. */
static void
stream_membership_ready(PlannerInfo *root, Index rti, RangeTblEntry *rte,
						MembershipCandidate *candidate)
{
	AfStreamDomain *domain;

	if (!stream_main_scope(root))
		return;
	domain = &af_cost_scope->stream;
	if (!domain->collected || !domain->eligible || candidate == NULL ||
		rti != domain->protected_key->varno || candidate->rti != rti ||
		candidate->key == NULL || candidate->key->varlevelsup != 0 ||
		!stream_same_var(candidate->key, domain->protected_key) ||
		candidate->equality != domain->first_operator ||
		rt_fetch(rti, root->parse->rtable) != rte ||
		rte->rtekind != RTE_RELATION || rte->relid != domain->protected_oid ||
		!list_member_ptr(root->native_af_membership, candidate))
		return;
	af_cost_scope->membership_ready = true;
}

static bool
stream_exact_edge(Node *node, Query *query, Var *a, Var *b, Oid operator)
{
	OpExpr	   *op;

	if (!stream_edge(node, query))
		return false;
	op = castNode(OpExpr, node);
	return op->opno == operator &&
		((stream_same_var(linitial_node(Var, op->args), a) &&
		  stream_same_var(lsecond_node(Var, op->args), b)) ||
		 (stream_same_var(linitial_node(Var, op->args), b) &&
		  stream_same_var(lsecond_node(Var, op->args), a)));
}

/* Validate the chosen physical index too; an unrelated index on the same
 * occurrence must not inherit the source role. */
static bool
stream_index_binding(Oid index_oid, Oid heap_oid, AttrNumber key)
{
	Relation	index = index_open(index_oid, AccessShareLock);
	bool		valid = index->rd_index->indrelid == heap_oid &&
		index->rd_rel->relam == BTREE_AM_OID && index->rd_amhandler == F_BTHANDLER &&
		index->rd_index->indisvalid && index->rd_index->indisready &&
		index->rd_index->indislive && index->rd_index->indnkeyatts >= 1 &&
		index->rd_index->indkey.values[0] == key &&
		index->rd_opfamily[0] == INTEGER_BTREE_FAM_OID &&
		RelationGetIndexExpressions(index) == NIL &&
		RelationGetIndexPredicate(index) == NIL;

	index_close(index, NoLock);
	return valid;
}

void
native_af_stream_mark_index(PlannerInfo *root, IndexPath *path, IndexScan *scan)
{
	AfStreamDomain *domain;
	IndexOptInfo *index;
	ParamPathInfo *ppi;
	ListCell   *cell;
	bool		leading = false;
	AfStreamMark *mark;
	MemoryContext previous;

	if (!stream_main_scope(root))
		return;
	domain = &af_cost_scope->stream;
	if (!domain->eligible || root->glob->parallelModeNeeded ||
		path->path.pathtype != T_IndexScan || path->path.parallel_aware ||
		path->path.parallel_workers != 0 || path->indexorderbys != NIL ||
		path->path.parent->reloptkind != RELOPT_BASEREL ||
		path->path.parent->relid != domain->source->varno ||
		planner_rt_fetch(path->path.parent->relid, root)->relid != domain->source_oid ||
		scan->scan.scanrelid != domain->source->varno)
		return;
	ppi = path->path.param_info;
	index = path->indexinfo;
	if (ppi == NULL || bms_num_members(ppi->ppi_req_outer) != 1 ||
		!bms_is_member(domain->protected_key->varno, ppi->ppi_req_outer) ||
		list_length(ppi->ppi_clauses) != 1 ||
		!stream_exact_edge((Node *) linitial_node(RestrictInfo, ppi->ppi_clauses)->clause,
						   root->parse, domain->protected_key, domain->source_fk, domain->first_operator) ||
		index->rel != path->path.parent || index->relam != BTREE_AM_OID ||
		index->nkeycolumns < 1 || index->indexkeys[0] != domain->source_fk->varattno ||
		index->opfamily[0] != INTEGER_BTREE_FAM_OID || index->indexprs != NIL ||
		index->indpred != NIL || scan->indexid != index->indexoid ||
		!stream_index_binding(scan->indexid, domain->source_oid, domain->source_fk->varattno))
		return;
	foreach(cell, path->indexclauses)
	{
		IndexClause *clause = lfirst_node(IndexClause, cell);

		if (clause->indexcol == 0 && !clause->lossy && clause->indexcols == NIL &&
			list_length(clause->indexquals) == 1 &&
			stream_exact_edge((Node *) clause->rinfo->clause, root->parse,
							  domain->protected_key, domain->source_fk, domain->first_operator) &&
			stream_exact_edge((Node *) linitial_node(RestrictInfo, clause->indexquals)->clause,
							  root->parse, domain->protected_key, domain->source_fk, domain->first_operator))
			leading = true;
	}
	if (!leading)
		return;
	previous = MemoryContextSwitchTo(af_cost_scope->memory);
	PG_TRY();
	{
		mark = palloc(sizeof(*mark));
		mark->scan = scan;
		mark->index_oid = scan->indexid;
		af_cost_scope->stream_marks = lappend(af_cost_scope->stream_marks, mark);
	}
	PG_FINALLY();
	{
		MemoryContextSwitchTo(previous);
	}
	PG_END_TRY();
	scan->af_stream_heap = true;
}

static bool
stream_target_has(Plan *plan, Var *key)
{
	ListCell   *cell;

	foreach(cell, plan->targetlist)
	{
		TargetEntry *target = lfirst_node(TargetEntry, cell);

		if (IsA(target->expr, Var) &&
			stream_same_var(castNode(Var, target->expr), key))
			return true;
	}
	return false;
}

/* Called before set_plan_references: paramval and targetlists still contain
 * the original RTI/attnum Vars, not OUTER_VAR result-column positions. */
static int
stream_nest_parameter(NestLoop *join, Var *source)
{
	NestLoopParam *parameter;

	if (join->join.jointype != JOIN_INNER || list_length(join->nestParams) != 1 ||
		!stream_target_has(outerPlan(join), source))
		return -1;
	parameter = linitial_node(NestLoopParam, join->nestParams);
	if (!IsA(parameter->paramval, Var) ||
		!stream_same_var(parameter->paramval, source))
		return -1;
	return parameter->paramno;
}

static bool
stream_parameter_edge(IndexScan *scan, Query *query, Var *target,
					  Oid operator, int parameter_id)
{
	ListCell   *cell;

	foreach(cell, scan->indexqualorig)
	{
		OpExpr	   *op;
		Node	   *left;
		Node	   *right;
		Param	   *parameter;

		if (!IsA(lfirst(cell), OpExpr))
			continue;
		op = lfirst_node(OpExpr, cell);
		if (op->opno != operator || op->opretset ||
			op->opresulttype != BOOLOID || list_length(op->args) != 2)
			continue;
		left = linitial(op->args);
		right = lsecond(op->args);
		if (IsA(left, Param))
		{
			Node	   *swap = left;

			left = right;
			right = swap;
		}
		if (!stream_plain_var(left, query) || !IsA(right, Param) ||
			!stream_same_var(castNode(Var, left), target))
			continue;
		parameter = castNode(Param, right);
		if (parameter->paramkind == PARAM_EXEC && parameter->paramtype == INT8OID &&
			parameter->paramid == parameter_id)
			return true;
	}
	return false;
}

static bool
stream_serial(Plan *plan)
{
	return plan != NULL && !plan->parallel_aware &&
		!IsA(plan, Gather) && !IsA(plan, GatherMerge);
}

static bool
stream_protected_scan(Plan *plan, AfStreamDomain *domain)
{
	CustomScan *scan;
	Const	   *heap;

	if (!stream_serial(plan) || !IsA(plan, CustomScan))
		return false;
	scan = castNode(CustomScan, plan);
	if (scan->scan.scanrelid != domain->protected_key->varno ||
		!stream_target_has(plan, domain->protected_key))
		return false;

	/*
	 * Known exact method identity, never a provider-name or leaf-count guess.
	 * Membership's two children are its mandatory fast/fallback branches.
	 */
	if (scan->methods == &membership_scan_methods)
	{
		if (list_length(scan->custom_plans) != 2 ||
			list_length(scan->custom_private) < 14 ||
			!IsA(list_nth(scan->custom_private, 7), Const) ||
			intVal(linitial(scan->custom_private)) != domain->protected_key->varattno ||
			intVal(lthird(scan->custom_private)) != AF_ADMISSION_FIRST)
			return false;
		heap = list_nth_node(Const, scan->custom_private, 7);
	}
	else if (scan->methods == &completed_hash_scan_methods)
	{
		if (list_length(scan->custom_plans) != 1 ||
			list_length(scan->custom_private) != 6 ||
			!IsA(lthird(scan->custom_private), Const) ||
			intVal(lsecond(scan->custom_private)) != domain->protected_key->varattno)
			return false;
		heap = lthird_node(Const, scan->custom_private);
	}
	else
		return false;
	return heap->consttype == OIDOID && !heap->constisnull &&
		DatumGetObjectId(heap->constvalue) == domain->protected_oid;
}

static bool
stream_was_marked(IndexScan *scan)
{
	ListCell   *cell;

	foreach(cell, af_cost_scope->stream_marks)
	{
		AfStreamMark *mark = lfirst(cell);

		if (mark->scan == scan && mark->index_oid == scan->indexid)
			return true;
	}
	return false;
}

/* Capacity affects only the already-proved S Plan tag, never path cost or
 * candidate choice.  Unknown metadata/work keeps the original ring policy. */
static bool
stream_capacity_result(bool estimated, bool fits, const char *reason,
					   double heap_pages, double index_pages, double total_pages)
{
	if (native_af_trace)
		ereport(NOTICE, (errmsg("native_af: stream heap capacity estimated %s decision %s reason %s",
								estimated ? "true" : "false", fits ? "clear_ring" : "keep_ring", reason)));
	if (native_af_trace && superuser() && estimated)
		ereport(NOTICE, (errmsg("AF_STREAM_CAPACITY heap_pages %.0f index_pages %.0f total_pages %.0f buffers %d",
								heap_pages, index_pages, total_pages, NBuffers)));
	return estimated && fits;
}

static RelOptInfo *
stream_capacity_relation(PlannerInfo *root, Index rti, Oid relation_oid)
{
	RelOptInfo *rel;

	if (rti == 0 || rti >= root->simple_rel_array_size ||
		root->simple_rel_array == NULL || rti > list_length(root->parse->rtable) ||
		rt_fetch(rti, root->parse->rtable)->rtekind != RTE_RELATION ||
		rt_fetch(rti, root->parse->rtable)->relid != relation_oid)
		return NULL;
	rel = root->simple_rel_array[rti];
	if (rel == NULL || rel->reloptkind != RELOPT_BASEREL ||
		rel->rtekind != RTE_RELATION || rel->relid != rti)
		return NULL;
	return rel;
}

static IndexOptInfo *
stream_capacity_index(RelOptInfo *rel, Oid index_oid, AttrNumber key)
{
	ListCell   *cell;

	foreach(cell, rel->indexlist)
	{
		IndexOptInfo *index = lfirst_node(IndexOptInfo, cell);

		if (index->indexoid == index_oid)
		{
			if (index->rel != rel || index->relam != BTREE_AM_OID ||
				index->nkeycolumns < 1 || index->indexkeys[0] != key ||
				index->opfamily[0] != INTEGER_BTREE_FAM_OID ||
				index->indexprs != NIL || index->indpred != NIL || index->tree_height < 0)
				return NULL;
			return index;
		}
	}
	return NULL;
}

/* With no residual business quals, these complete NL outputs represent the
 * matched heap work.  Never multiply a parameterized inner Plan Rows by loops.
 * R is budgeted at its full heap size; S/T heap pages are bounded by visits.
 * Index probes include internal pages and a conservative range-leaf term. */
static bool
stream_capacity_fits(PlannerInfo *root, NestLoop *lower, NestLoop *upper,
					 IndexScan *source, IndexScan *target, AfStreamDomain *domain)
{
	RelOptInfo *r;
	RelOptInfo *s;
	RelOptInfo *t;
	IndexOptInfo *s_index;
	IndexOptInfo *t_index;
	double		r_pages;
	double		s_pages;
	double		t_pages;
	double		s_probes = outerPlan(lower)->plan_rows;
	double		s_matched = lower->join.plan.plan_rows;
	double		t_probes = lower->join.plan.plan_rows;
	double		t_matched = upper->join.plan.plan_rows;
	double		s_index_visits;
	double		t_index_visits;
	double		heap_pages;
	double		index_pages;
	double		total_pages;

	/*
	 * The original R policy may have filters: full R heap already covers it.
	 * Only the two business joins and ordinary S/T scans constrain this rule.
	 */
	if (source->scan.plan.qual != NIL || target->scan.plan.qual != NIL ||
		lower->join.joinqual != NIL || lower->join.plan.qual != NIL ||
		upper->join.joinqual != NIL || upper->join.plan.qual != NIL)
		return stream_capacity_result(false, false, "residual_quals", 0, 0, 0);
	r = stream_capacity_relation(root, domain->protected_key->varno, domain->protected_oid);
	s = stream_capacity_relation(root, domain->source->varno, domain->source_oid);
	t = stream_capacity_relation(root, domain->target->varno, domain->target_oid);
	if (r == NULL || s == NULL || t == NULL || NBuffers <= 0)
		return stream_capacity_result(false, false, "relation_metadata", 0, 0, 0);
	s_index = stream_capacity_index(s, source->indexid, domain->source_fk->varattno);
	t_index = stream_capacity_index(t, target->indexid, domain->target->varattno);
	if (s_index == NULL || t_index == NULL)
		return stream_capacity_result(false, false, "index_metadata", 0, 0, 0);
	r_pages = (double) r->pages;
	s_pages = (double) s->pages;
	t_pages = (double) t->pages;
	if (!isfinite(r_pages) || r_pages < 0 || !isfinite(s_pages) || s_pages < 0 ||
		!isfinite(t_pages) || t_pages < 0 ||
		!isfinite((double) s_index->pages) || !isfinite((double) t_index->pages) ||
		!isfinite(s_probes) || s_probes < 0 || !isfinite(s_matched) || s_matched < 0 ||
		!isfinite(t_probes) || t_probes < 0 || !isfinite(t_matched) || t_matched < 0)
		return stream_capacity_result(false, false, "nonfinite_work", 0, 0, 0);
	s_index_visits = s_probes * ((double) s_index->tree_height + 1.0) + s_matched;
	t_index_visits = t_probes * ((double) t_index->tree_height + 1.0) + t_matched;
	if (!isfinite(s_index_visits) || !isfinite(t_index_visits))
		return stream_capacity_result(false, false, "nonfinite_work", 0, 0, 0);
	heap_pages = r_pages + Min(s_pages, s_matched) + Min(t_pages, t_matched);
	index_pages = Min((double) s_index->pages, s_index_visits) +
		Min((double) t_index->pages, t_index_visits);
	total_pages = heap_pages + index_pages;
	if (!isfinite(total_pages))
		return stream_capacity_result(false, false, "nonfinite_work", 0, 0, 0);
	return stream_capacity_result(true, total_pages <= (double) NBuffers,
								  total_pages <= (double) NBuffers ? "fits_shared_buffers" : "exceeds_shared_buffers",
								  heap_pages, index_pages, total_pages);
}

/* First version deliberately admits only the direct two-NL chain and plain
 * unary parents.  Memoize, Material between joins, alternate roots and all
 * unknown shapes simply retain the original buffer policy. */
static int
stream_final_chain(PlannerInfo *root, Plan *plan, AfStreamDomain *domain)
{
	NestLoop   *upper;
	NestLoop   *lower;
	IndexScan  *source;
	IndexScan  *target;
	int			first_parameter;
	int			second_parameter;
	Query	   *query = root->parse;

	if (!stream_serial(plan))
		return 0;
	switch (nodeTag(plan))
	{
		case T_Limit:
		case T_Sort:
		case T_IncrementalSort:
		case T_Agg:
		case T_Group:
		case T_Unique:
		case T_Result:
		case T_Material:
			if (innerPlan(plan) != NULL)
				return 0;
			return stream_final_chain(root, outerPlan(plan), domain);
		default:
			break;
	}
	if (!IsA(plan, NestLoop) || !IsA(outerPlan(plan), NestLoop) ||
		!IsA(innerPlan(plan), IndexScan))
		return 0;
	upper = castNode(NestLoop, plan);
	lower = castNode(NestLoop, outerPlan(plan));
	if (!stream_serial((Plan *) lower) || !IsA(innerPlan(lower), IndexScan) ||
		!stream_protected_scan(outerPlan(lower), domain))
		return 0;
	source = castNode(IndexScan, innerPlan(lower));
	target = castNode(IndexScan, innerPlan(upper));
	if (!stream_serial((Plan *) source) || !stream_serial((Plan *) target) ||
		!stream_was_marked(source) || source->scan.scanrelid != domain->source->varno ||
		target->scan.scanrelid != domain->target->varno ||
		rt_fetch(source->scan.scanrelid, query->rtable)->relid != domain->source_oid ||
		rt_fetch(target->scan.scanrelid, query->rtable)->relid != domain->target_oid ||
		!stream_index_binding(source->indexid, domain->source_oid, domain->source_fk->varattno) ||
		!stream_index_binding(target->indexid, domain->target_oid, domain->target->varattno) ||
		!stream_target_has((Plan *) source, domain->source))
		return 0;
	first_parameter = stream_nest_parameter(lower, domain->protected_key);
	second_parameter = stream_nest_parameter(upper, domain->source);
	if (first_parameter < 0 || second_parameter < 0 ||
		first_parameter == second_parameter ||
		!stream_parameter_edge(source, query, domain->source_fk,
							   domain->first_operator, first_parameter) ||
		!stream_parameter_edge(target, query, domain->target,
							   domain->operator, second_parameter))
		return 0;
	source->af_stream_heap = !stream_capacity_fits(root, lower, upper, source, target, domain);
	return source->af_stream_heap ? 1 : 0;
}

void
native_af_stream_finalize(PlannerInfo *root, Plan *plan)
{
	ListCell   *cell;
	int			enabled = 0;

	if (root == NULL || af_cost_scope == NULL ||
		af_cost_scope->owner != af_cost_scope || af_cost_scope->query != root->parse)
		return;
	/* Always clear provisional tags, including a mode change during planning. */
	foreach(cell, af_cost_scope->stream_marks)
		((AfStreamMark *) lfirst(cell))->scan->af_stream_heap = false;
	if (stream_main_scope(root) && af_cost_scope->stream.eligible &&
		!root->glob->parallelModeNeeded)
		enabled = stream_final_chain(root, plan, &af_cost_scope->stream);
	if (native_af_trace && af_cost_scope->stream_marks != NIL)
		ereport(NOTICE, (errmsg("native_af: stream heap marked %d enabled %d main_original true",
								list_length(af_cost_scope->stream_marks), enabled)));
}

Query *
native_af_batch_save(Query *parse)
{
	if (native_af_mode != AF_ADMISSION_FIRST || af_batch_depth != 0 ||
		parse->commandType != CMD_SELECT || !parse->hasRowSecurity ||
		parse->resultRelation != 0 || parse->hasModifyingCTE ||
		parse->cteList != NIL || parse->rowMarks != NIL || parse->setOperations != NULL ||
		parse->hasTargetSRFs || parse->hasRecursive || parse->utilityStmt != NULL)
		return NULL;
	return copyObject(parse);
}

static Query *
batch_query(Query *query, PlannedStmt *original, AfBatchContext *context)
{
	Index		protected_rti = 0;
	Index		selected = 0;
	AttrNumber	protected_key = 0;
	AttrNumber	inner_key = 0;
	Oid			equality = InvalidOid;
	Bitmapset  *seen = NULL;
	List	   *quals = NIL;
	List	   *moved = NIL;
	List	   *remaining = NIL;
	List	   *targets = NIL;
	List	   *names = NIL;
	List	   *types = NIL;
	List	   *typmods = NIL;
	List	   *collations = NIL;
	ListCell   *lc;
	double		best = -1;
	Index		rti = 0;
	AfBatchVars vars = {0};
	RangeTblEntry *physical;
	RTEPermissionInfo *permission;
	Relation	relation;
	TupleDesc	desc;
	Query	   *producer;
	Query	   *array_query;
	Query	   *result;
	RangeTblEntry *reference;
	RangeTblEntry *array_reference;
	CommonTableExpr *cte;
	ScalarArrayOpExpr *filter;
	SubLink    *array;
	RangeTblRef *range;
	int			att;

	if (query->jointree == NULL || contain_volatile_functions((Node *) query) ||
		batch_principal_expression((Node *) query, NULL) ||
		!batch_jointree((Node *) query->jointree, query, &seen, &quals))
		return NULL;
	foreach(lc, query->rtable)
	{
		RangeTblEntry *rte = lfirst_node(RangeTblEntry, lc);
		bool		rls = false;

		rti++;
		if (rte->rtekind == RTE_JOIN)
		{
			if (rte->jointype != JOIN_INNER || rte->joinmergedcols != 0 ||
				rte->alias != NULL || rte->join_using_alias != NULL ||
				rte->securityQuals != NIL || rte->lateral || rte->perminfoindex != 0)
				return NULL;
			continue;
		}
		if (!batch_relation(rte, &rls) || batch_permission(query, rte) == NULL ||
			!bms_is_member(rti, seen))
			return NULL;
		if (rls)
		{
			if (protected_rti != 0 || rte->securityQuals == NIL)
				return NULL;
			protected_rti = rti;
		}
		else if (rte->securityQuals != NIL)
			return NULL;
	}
	if (protected_rti == 0 || bms_num_members(seen) < 2)
		return NULL;
	vars.query = query;
	vars.protected_rti = protected_rti;
	if (query_tree_walker(query, batch_user_vars, &vars, QTW_IGNORE_RANGE_TABLE))
		return NULL;

	/* Only conjunctive, direct equality edges of the existing INNER graph. */
	foreach(lc, quals)
	{
		OpExpr	   *op;
		Var		   *left;
		Var		   *right;
		Var		   *outer;
		Var		   *inner;
		RangeTblEntry *rte;
		double		cost;

		if (!IsA(lfirst(lc), OpExpr))
			continue;
		op = lfirst_node(OpExpr, lc);
		if (!builtin_equality(op) || get_opcode(op->opno) != F_INT8EQ ||
			list_length(op->args) != 2 || !IsA(linitial(op->args), Var) ||
			!IsA(lsecond(op->args), Var))
			continue;
		left = linitial_node(Var, op->args);
		right = lsecond_node(Var, op->args);
		outer = left->varno == protected_rti ? left : right;
		inner = outer == left ? right : left;
		if (outer->varno != protected_rti || inner->varno == protected_rti ||
			outer->vartype != INT8OID || inner->vartype != INT8OID)
			continue;
		rte = rt_fetch(inner->varno, query->rtable);
		if (inner->varno > list_length(original->rtable) ||
			rt_fetch(inner->varno, original->rtable)->relid != rte->relid)
			continue;
		cost = batch_seq_cost(original->planTree, inner->varno);
		if (cost <= best ||
			!batch_index(rt_fetch(protected_rti, query->rtable)->relid,
						 outer->varattno, true) ||
			!batch_index(rte->relid, inner->varattno, false))
			continue;
		selected = inner->varno;
		protected_key = outer->varattno;
		inner_key = inner->varattno;
		equality = op->opno;
		best = cost;
	}
	if (selected == 0 || best < 0)
		return NULL;

	/* Move only safe WHERE conjuncts; original graph edges stay untouched. */
	foreach(lc, make_ands_implicit((Expr *) query->jointree->quals))
	{
		RestrictInfo temp = {0};

		temp.clause = lfirst(lc);
		if (completed_hash_safe_comparison(&temp, protected_rti))
			moved = lappend(moved, lfirst(lc));
		else
			remaining = lappend(remaining, lfirst(lc));
	}
	if (moved == NIL)
		return NULL;
	physical = copyObject(rt_fetch(protected_rti, query->rtable));
	permission = copyObject(batch_permission(query, physical));
	physical->perminfoindex = 1;
	relation = table_open(physical->relid, AccessShareLock);
	desc = RelationGetDescr(relation);
	vars.mapping = palloc0(sizeof(int) * (desc->natts + 1));
	vars.needed = bms_add_member(vars.needed, protected_key);
	att = -1;
	while ((att = bms_next_member(vars.needed, att)) >= 0)
	{
		Form_pg_attribute attribute;
		Var		   *var;

		if (att <= 0 || att > desc->natts ||
			!bms_is_member(att - FirstLowInvalidHeapAttributeNumber,
						   permission->selectedCols))
		{
			table_close(relation, NoLock);
			return NULL;
		}
		attribute = TupleDescAttr(desc, att - 1);
		if (attribute->attisdropped)
		{
			table_close(relation, NoLock);
			return NULL;
		}
		vars.mapping[att] = list_length(targets) + 1;
		var = makeVar(protected_rti, att, attribute->atttypid, attribute->atttypmod,
					  attribute->attcollation, 0);
		targets = lappend(targets, makeTargetEntry((Expr *) var,
												   vars.mapping[att], pstrdup(NameStr(attribute->attname)), false));
		names = lappend(names, makeString(pstrdup(NameStr(attribute->attname))));
		types = lappend_oid(types, attribute->atttypid);
		typmods = lappend_int(typmods, attribute->atttypmod);
		collations = lappend_oid(collations, attribute->attcollation);
	}
	table_close(relation, NoLock);

	producer = makeNode(Query);
	producer->commandType = CMD_SELECT;
	producer->querySource = QSRC_ORIGINAL;
	producer->hasSubLinks = query->hasSubLinks;
	producer->hasRowSecurity = query->hasRowSecurity;
	producer->rtable = list_make1(physical);
	producer->rteperminfos = list_make1(permission);
	producer->targetList = targets;
	range = makeNode(RangeTblRef);
	range->rtindex = protected_rti;
	producer->jointree = makeFromExpr(list_make1(range),
									  (Node *) make_ands_explicit(copyObject(moved)));
	ChangeVarNodes((Node *) producer, protected_rti, 1, 0);
	{
		RangeTblEntry *original_rte = rt_fetch(protected_rti, query->rtable);
		List	   *required_policy = copyObject(original_rte->securityQuals);

		ChangeVarNodes((Node *) required_policy, protected_rti, 1, 0);
		if (!equal(physical->securityQuals, required_policy) ||
			!equal(permission, batch_permission(query, original_rte)))
			return NULL;
	}

	/* Map actual outer expressions before attaching the physical producer. */

	/*
	 * Unlike query_tree_walker, query_tree_mutator does not implement
	 * QTW_IGNORE_RANGE_TABLE.  Detach it so hidden policy/alias Vars cannot
	 * acquire compressed consumer attnos.
	 */
	{
		Query	   *mapping_input = copyObject(query);
		List	   *rtable = mapping_input->rtable;

		mapping_input->rtable = NIL;
		result = query_tree_mutator(mapping_input, batch_map_vars, &vars, 0);
		result->rtable = rtable;
	}
	result->jointree->quals = (Node *) batch_map_vars(
													  (Node *) make_ands_explicit(remaining), &vars);
	foreach(lc, result->rtable)
	{
		RangeTblEntry *rte = lfirst_node(RangeTblEntry, lc);

		if (rte->rtekind == RTE_JOIN)
		{
			/*
			 * ON-only aliases have no actual expression users (checked
			 * above). Like planner setrefs, discard unused expansion/source
			 * metadata.
			 */
			rte->joinaliasvars = NIL;
			rte->joinleftcols = NIL;
			rte->joinrightcols = NIL;
		}
	}
	cte = makeNode(CommonTableExpr);
	cte->ctename = pstrdup("__native_af_authorized_batch");
	cte->ctematerialized = CTEMaterializeAlways;
	cte->ctequery = (Node *) producer;
	cte->cterefcount = 2;
	cte->ctecolnames = names;
	cte->ctecoltypes = types;
	cte->ctecoltypmods = typmods;
	cte->ctecolcollations = collations;
	cte->location = -1;
	result->cteList = list_make1(cte);

	reference = makeNode(RangeTblEntry);
	reference->rtekind = RTE_CTE;
	reference->ctename = pstrdup(cte->ctename);
	reference->ctelevelsup = 0;
	reference->coltypes = copyObject(types);
	reference->coltypmods = copyObject(typmods);
	reference->colcollations = copyObject(collations);
	reference->alias = copyObject(physical->alias);
	reference->eref = makeAlias(pstrdup(physical->eref->aliasname), copyObject(names));
	reference->inFromCl = physical->inFromCl;
	lfirst(list_nth_cell(result->rtable, protected_rti - 1)) = reference;

	array_reference = copyObject(reference);
	array_reference->ctelevelsup = 1;
	array_reference->alias = NULL;
	array_query = makeNode(Query);
	array_query->commandType = CMD_SELECT;
	array_query->querySource = QSRC_ORIGINAL;
	array_query->rtable = list_make1(array_reference);
	array_query->targetList = list_make1(makeTargetEntry((Expr *) makeVar(1,
																		  vars.mapping[protected_key], INT8OID, -1, InvalidOid, 0), 1,
														 pstrdup("authorized_key"), false));
	range = makeNode(RangeTblRef);
	range->rtindex = 1;
	array_query->jointree = makeFromExpr(list_make1(range), NULL);
	array = makeNode(SubLink);
	array->subLinkType = ARRAY_SUBLINK;
	array->subselect = (Node *) array_query;
	array->location = -1;
	filter = makeNode(ScalarArrayOpExpr);
	filter->opno = equality;
	filter->opfuncid = F_INT8EQ;
	filter->useOr = true;
	filter->args = list_make2(makeVar(selected, inner_key, INT8OID, -1,
									  InvalidOid, 0), array);
	result->jointree->quals = (Node *) make_and_qual(
													 result->jointree->quals, (Node *) filter);
	result->hasSubLinks = true;
	context->query = result;
	context->keys = array;
	context->filter = filter;
	context->inner_rti = selected;
	context->outer_rti = protected_rti;
	context->outer_key = vars.mapping[protected_key];
	context->inner_key = inner_key;
	context->input_relids = bms_copy(seen);
	att = -1;
	while ((att = bms_next_member(vars.needed, att)) >= 0)
		context->producer_carriers = lappend_int(context->producer_carriers, att);
	context->principal = GetUserId();
	context->planning_snapshot = ActiveSnapshotSet() ? GetActiveSnapshot() : NULL;
	return result;
}

/* Shared inputs: retain an admitted producer/ordinary-partner continuation until its
 * complete query has been costed.  The old flat alternative remains available.
 * Only reassociate the existing all-INNER graph; retain each original qual. */
static bool
batch_flat_quals(Node *node, List **quals)
{
	ListCell   *cell;

	if (IsA(node, RangeTblRef))
		return true;
	if (IsA(node, FromExpr))
	{
		FromExpr   *from = castNode(FromExpr, node);

		foreach(cell, from->fromlist)
			if (!batch_flat_quals(lfirst(cell), quals))
			return false;
		*quals = list_concat(*quals, make_ands_implicit((Expr *) from->quals));
		return true;
	}
	if (IsA(node, JoinExpr))
	{
		JoinExpr   *join = castNode(JoinExpr, node);

		if (join->jointype != JOIN_INNER || join->isNatural ||
			join->usingClause != NIL || join->alias != NULL ||
			!batch_flat_quals(join->larg, quals) ||
			!batch_flat_quals(join->rarg, quals))
			return false;
		*quals = list_concat(*quals, make_ands_implicit((Expr *) join->quals));
		return true;
	}
	return false;
}

static bool
batch_keep_first_pair(Query *query, AfBatchContext *context)
{
	List	   *quals = NIL;
	List	   *pair_quals = NIL;
	List	   *remaining = NIL;
	List	   *fromlist;
	ListCell   *cell;
	JoinExpr   *pair;
	RangeTblRef *left;
	RangeTblRef *right;
	int			member = -1;

	if (!batch_flat_quals((Node *) query->jointree, &quals) ||
		context->input_relids == NULL || bms_num_members(context->input_relids) <= 2)
		return false;
	foreach(cell, quals)
	{
		Node	   *node = lfirst(cell);
		bool		paired = false;

		if (IsA(node, OpExpr))
		{
			OpExpr	   *op = castNode(OpExpr, node);

			if (builtin_equality(op) && list_length(op->args) == 2 &&
				IsA(linitial(op->args), Var) && IsA(lsecond(op->args), Var))
			{
				Var		   *a = linitial_node(Var, op->args);
				Var		   *b = lsecond_node(Var, op->args);

				if (b->varno == context->outer_rti)
				{
					Var		   *swap = a;

					a = b;
					b = swap;
				}
				paired = get_opcode(op->opno) == F_INT8EQ &&
					a->varno == context->outer_rti && a->varattno == context->outer_key &&
					b->varno == context->inner_rti && b->varattno == context->inner_key &&
					a->varlevelsup == 0 && b->varlevelsup == 0 &&
					bms_is_empty(a->varnullingrels) && bms_is_empty(b->varnullingrels);
			}
		}
		if (paired)
			pair_quals = lappend(pair_quals, node);
		else
			remaining = lappend(remaining, node);
	}
	if (pair_quals == NIL)
		return false;
	left = makeNode(RangeTblRef);
	left->rtindex = context->outer_rti;
	right = makeNode(RangeTblRef);
	right->rtindex = context->inner_rti;
	pair = makeNode(JoinExpr);
	pair->jointype = JOIN_INNER;
	pair->larg = (Node *) left;
	pair->rarg = (Node *) right;
	pair->quals = (Node *) make_ands_explicit(pair_quals);
	/* An INNER join needs no nullable-rel ID and has no alias Var consumers. */
	pair->rtindex = 0;
	fromlist = list_make1(pair);
	while ((member = bms_next_member(context->input_relids, member)) >= 0)
	{
		RangeTblRef *ref;

		if (member == context->outer_rti || member == context->inner_rti)
			continue;
		ref = makeNode(RangeTblRef);
		ref->rtindex = member;
		fromlist = lappend(fromlist, ref);
	}
	query->jointree = makeFromExpr(fromlist, (Node *) make_ands_explicit(remaining));
	context->pair_first = true;
	return true;
}

/* Main business tree only: InitPlans are intentionally not traversed. */
static bool
batch_plan_key(Plan *plan, AfBatchContext *context)
{
	List	   *quals;
	ListCell   *lc;

	if (IsA(plan, BitmapHeapScan))
	{
		if (outerPlan(plan) == NULL || !IsA(outerPlan(plan), BitmapIndexScan))
			return false;
		quals = castNode(BitmapIndexScan, outerPlan(plan))->indexqualorig;
	}
	else if (IsA(plan, IndexScan))
		quals = castNode(IndexScan, plan)->indexqualorig;
	else
		return false;
	foreach(lc, quals)
	{
		ScalarArrayOpExpr *array;
		Var		   *key;
		Param	   *param;

		if (!IsA(lfirst(lc), ScalarArrayOpExpr))
			continue;
		array = lfirst_node(ScalarArrayOpExpr, lc);
		if (list_length(array->args) != 2 || !IsA(linitial(array->args), Var) ||
			!IsA(lsecond(array->args), Param))
			continue;
		key = linitial_node(Var, array->args);
		param = lsecond_node(Param, array->args);
		if (array->useOr && array->opno == context->filter->opno &&
			array->opfuncid == F_INT8EQ && key->varno == context->inner_rti &&
			key->varattno == context->inner_key && param->native_af_batch_keys &&
			param->paramkind == PARAM_EXEC && param->paramtype == INT8ARRAYOID &&
			param->paramid == context->param_id)
			return true;
	}
	return false;
}

static Bitmapset *
batch_plan_scope(Plan *plan, AfBatchContext *context, bool repeated,
				 bool *valid, bool *paired, int *batch_scans, CteScan **producer_use)
{
	Bitmapset  *left;
	Bitmapset  *right;
	Bitmapset  *all;
	bool		join;

	if (plan == NULL)
		return NULL;
	if (IsA(plan, BitmapHeapScan) || IsA(plan, IndexScan) ||
		IsA(plan, IndexOnlyScan) || IsA(plan, SeqScan) || IsA(plan, CteScan))
	{
		Index		rti = ((Scan *) plan)->scanrelid;

		if (rti == context->inner_rti)
		{
			if (repeated || !batch_plan_key(plan, context))
				*valid = false;
			(*batch_scans)++;
		}
		if (rti == context->outer_rti)
		{
			if (!IsA(plan, CteScan) || *producer_use != NULL)
				*valid = false;
			else
				*producer_use = castNode(CteScan, plan);
		}
		return bms_make_singleton(rti);
	}

	/*
	 * Keep the single-preprocessing contract independent of merge
	 * mark/restore and rescan details in this first prototype.
	 */
	left = batch_plan_scope(outerPlan(plan), context,
							repeated || IsA(plan, MergeJoin),
							valid, paired, batch_scans, producer_use);
	right = batch_plan_scope(innerPlan(plan), context,
							 repeated || IsA(plan, NestLoop) || IsA(plan, MergeJoin),
							 valid, paired, batch_scans, producer_use);
	join = IsA(plan, NestLoop) || IsA(plan, MergeJoin) || IsA(plan, HashJoin);
	if (join && bms_num_members(left) == 1 && bms_num_members(right) == 1 &&
		((bms_is_member(context->outer_rti, left) &&
		  bms_is_member(context->inner_rti, right)) ||
		 (bms_is_member(context->inner_rti, left) &&
		  bms_is_member(context->outer_rti, right))))
	{
		if (((Join *) plan)->jointype != JOIN_INNER)
			*valid = false;
		else
			*paired = true;
	}
	if (bms_overlap(left, right))
		*valid = false;
	all = bms_union(left, right);
	bms_free(left);
	bms_free(right);
	return all;
}

/* Resolve projection slots back to the actual scan that produces them.
 * These are planner-only references and never enter the cached plan. */
static Var *
batch_producer_column(Plan *producer, AttrNumber column)
{
	TargetEntry *entry = get_tle_by_resno(producer->targetlist, column);
	Var		   *value;
	List	   *carriers = NIL;

	if (entry == NULL || entry->resjunk || !IsA(entry->expr, Var))
		return NULL;
	value = castNode(Var, entry->expr);
	if (value->varno != INDEX_VAR)
		return value;
	if (IsA(producer, CustomScan))
		carriers = castNode(CustomScan, producer)->custom_scan_tlist;
	else if (IsA(producer, IndexOnlyScan))
		carriers = castNode(IndexOnlyScan, producer)->indextlist;
	entry = get_tle_by_resno(carriers, value->varattno);
	return entry != NULL && IsA(entry->expr, Var) ? castNode(Var, entry->expr) : NULL;
}

/* Reconstruct the effective root range from the physical main tree, then
 * separately resolve the materialized producer and key-set read. The same
 * checked row source must establish the protected occurrence and supply the
 * complete prefilter key set. Other main-tree occurrences retain their
 * original permissions and identities. */
static const char *
batch_root_check(Query *original, PlannedStmt *statement, const AfBatchContext *context,
				 Bitmapset *actual, CteScan *consumer)
{
	Plan	   *array;
	Plan	   *producer;
	CteScan    *key_scan;
	RangeTblEntry *rte;
	const RangeTblEntry *original_rte = rt_fetch(context->outer_rti, original->rtable);
	Index		physical_occurrence;
	int			occurrence = -1;
	int			output = 0;
	int			producer_bindings = 0;
	int			array_bindings = 0;
	ListCell   *cell;
	Var		   *key;

	if (!original->hasRowSecurity)
		return "original_policy_context_missing";
	if (consumer == NULL || !bms_equal(context->input_relids, actual))
		return "root_occurrence_mismatch";
	if (context->principal != GetUserId() ||
		context->planning_snapshot != (ActiveSnapshotSet() ? GetActiveSnapshot() : NULL))
		return "root_binding_mismatch";
	while ((occurrence = bms_next_member(actual, occurrence)) >= 0)
	{
		RangeTblEntry *before = rt_fetch(occurrence, original->rtable);

		if (occurrence > list_length(statement->rtable))
			return "root_occurrence_missing";
		rte = rt_fetch(occurrence, statement->rtable);
		if (occurrence == context->outer_rti)
		{
			if (rte->rtekind != RTE_CTE)
				return "root_producer_use_missing";
		}
		else if (rte->rtekind != RTE_RELATION || rte->relid != before->relid ||
				 rte->perminfoindex == 0 ||
				 !equal(getRTEPermissionInfo(statement->permInfos, rte),
						batch_permission(original, before)))
			return "root_ordinary_occurrence_mismatch";
	}
	if (consumer->ctePlanId <= 0 || consumer->ctePlanId > list_length(statement->subplans) ||
		context->array_plan_id <= 0 || context->array_plan_id > list_length(statement->subplans) ||
		context->param_id < 0 || context->param_id >= list_length(statement->paramExecTypes) ||
		list_nth_oid(statement->paramExecTypes, context->param_id) != INT8ARRAYOID)
		return "root_dependency_missing";
	foreach(cell, statement->planTree->initPlan)
	{
		SubPlan    *source = lfirst_node(SubPlan, cell);

		if (list_member_int(source->setParam, context->param_id))
		{
			if (source->subLinkType != ARRAY_SUBLINK || source->plan_id != context->array_plan_id ||
				source->parParam != NIL || source->args != NIL ||
				list_length(source->setParam) != 1 || source->firstColType != INT8OID)
				return "root_array_binding_mismatch";
			array_bindings++;
		}
		if (list_member_int(source->setParam, consumer->cteParam))
		{
			if (source->subLinkType != CTE_SUBLINK || source->plan_id != consumer->ctePlanId ||
				list_length(source->setParam) != 1)
				return "root_producer_binding_mismatch";
			producer_bindings++;
		}
	}
	if (producer_bindings != 1 || array_bindings != 1)
		return "root_producer_or_array_binding_missing";
	array = list_nth(statement->subplans, context->array_plan_id - 1);
	if (!IsA(array, CteScan))
		return "key_source_is_not_producer_read";
	key_scan = castNode(CteScan, array);
	if (key_scan->ctePlanId != consumer->ctePlanId || key_scan->cteParam != consumer->cteParam ||
		array->qual != NIL || list_length(array->targetlist) != 1)
		return "key_source_not_same_complete_producer";
	key = batch_producer_column(array, 1);
	if (key == NULL || key->varno != key_scan->scan.scanrelid ||
		key->varattno != context->outer_key || key->vartype != INT8OID)
		return "key_source_column_mismatch";
	producer = list_nth(statement->subplans, consumer->ctePlanId - 1);
	if (IsA(producer, CustomScan))
	{
		CustomScan *scan = castNode(CustomScan, producer);

		if (scan->methods != &completed_hash_scan_methods &&
			scan->methods != &membership_scan_methods && scan->methods != &partial_scan_methods)
			return "unknown_producer_exact_rule";
	}
	else if (!IsA(producer, SeqScan) && !IsA(producer, IndexScan) &&
			 !IsA(producer, IndexOnlyScan) && !IsA(producer, BitmapHeapScan))
		return "unknown_producer_leaf";
	physical_occurrence = ((Scan *) producer)->scanrelid;
	if (physical_occurrence <= 0 || physical_occurrence > list_length(statement->rtable))
		return "producer_scan_binding_missing";
	rte = rt_fetch(physical_occurrence, statement->rtable);
	if (rte->rtekind != RTE_RELATION || rte->relid != original_rte->relid ||
		rte->perminfoindex == 0 ||
		!equal(getRTEPermissionInfo(statement->permInfos, rte),
			   batch_permission(original, (RangeTblEntry *) original_rte)))
		return "producer_policy_context_mismatch";
	foreach(cell, context->producer_carriers)
	{
		Var		   *value = batch_producer_column(producer, ++output);

		if (value == NULL || value->varno != physical_occurrence || value->varattno != lfirst_int(cell))
			return "producer_carrier_mismatch";
	}
	return NULL;
}

static void
batch_summary(AfBatchContext *context, bool generated, bool scope,
			  bool paired, int scans, PlannedStmt *original,
			  PlannedStmt *alternative, bool chosen)
{
	if (!native_af_trace || native_af_mode != AF_ADMISSION_FIRST || af_batch_depth != 0)
		return;
	ereport(NOTICE,
			(errmsg("native_af: batch summary generated %d lowered %d rejected %d domain %d scope %d paired %d scans %d original_total %.6f alternative_total %.6f chosen %d pair_first %d",
					generated, context != NULL && context->lowered,
					context != NULL && context->rejected,
					context != NULL && context->domain_costed, scope, paired, scans,
					original->planTree->total_cost,
					alternative != NULL ? alternative->planTree->total_cost : -1.0, chosen,
					context != NULL && context->pair_first)));
}

static PlannedStmt *
batch_choose_variant(Query *saved, PlannedStmt *original,
					 const char *query_string, int cursorOptions,
					 ParamListInfo boundParams, bool pair_first)
{
	AfBatchContext context = {0};
	AfBatchContext *previous = af_batch_context;
	Query	   *candidate;
	PlannedStmt *alternative = NULL;
	int			previous_depth = af_batch_depth;
	int			previous_collapse_limit = join_collapse_limit;
	int			previous_from_limit = from_collapse_limit;
	AfCostScope *previous_share_target = af_cost_share_target;
	bool		valid = true;
	bool		paired = false;
	int			batch_scans = 0;
	Bitmapset  *scope;
	CteScan    *producer_use = NULL;
	const char *root_rejection;

	if (native_af_mode != AF_ADMISSION_FIRST || af_batch_depth != 0 ||
		native_af_experiment_force != AF_EXP_AUTO)
		return original;
	if (saved == NULL)
	{
		batch_summary(NULL, false, false, false, 0, original, NULL, false);
		return original;
	}
	candidate = batch_query(saved, original, &context);
	if (candidate == NULL)
	{
		batch_summary(&context, false, false, false, 0, original, NULL, false);
		return original;
	}
	if (pair_first && !batch_keep_first_pair(candidate, &context))
		return original;
	af_batch_context = &context;
	af_batch_depth++;
	PG_TRY();
	{
		if (pair_first)
		{
			join_collapse_limit = 1;
			from_collapse_limit = 1;
		}
		af_cost_share_target = af_cost_scope;
		alternative = standard_planner(candidate, query_string, cursorOptions, boundParams);
	}
	PG_FINALLY();
	{
		af_batch_context = previous;
		af_batch_depth = previous_depth;
		join_collapse_limit = previous_collapse_limit;
		from_collapse_limit = previous_from_limit;
		af_cost_share_target = previous_share_target;
	}
	PG_END_TRY();
	if (alternative == NULL)
	{
		batch_summary(&context, true, false, false, 0, original, NULL, false);
		return original;
	}
	scope = batch_plan_scope(alternative->planTree, &context, false,
							 &valid, &paired, &batch_scans, &producer_use);
	root_rejection = valid && paired && batch_scans == 1 ?
		batch_root_check(saved, alternative, &context, scope, producer_use) :
		"root_join_or_key_scan_outside_rule";
	if (native_af_trace)
		ereport(NOTICE, (errmsg("native_af: shared root %s",
								root_rejection != NULL ? root_rejection : "admitted")));
	bms_free(scope);
	if (native_af_experiment_publish_shared &&
		context.lowered && !context.rejected && context.domain_costed &&
		root_rejection == NULL &&
		isfinite(alternative->planTree->total_cost) &&
		alternative->planTree->total_cost < original->planTree->total_cost)
	{
		batch_summary(&context, true, valid, paired, batch_scans,
					  original, alternative, true);

		/*
		 * This internal rewrite runs after the caller's RLS rewrite. Keep the
		 * chosen plan role-dependent even when standard_planner's own
		 * dependencies do not add the flag.
		 */
		alternative->dependsOnRole = true;
		return alternative;
	}
	batch_summary(&context, true, valid, paired, batch_scans,
				  original, alternative, false);
	return original;
}

/* -------------------------------------------------------------------------
 * Choosing between the flat and the shared-input plan
 * -------------------------------------------------------------------------
 */

PlannedStmt *
native_af_batch_choose(Query *saved, PlannedStmt *original,
					   const char *query_string, int cursorOptions,
					   ParamListInfo boundParams)
{
	PlannedStmt *flat;
	PlannedStmt *paired;

	if (native_af_mode != AF_ADMISSION_FIRST || af_batch_depth != 0 ||
		native_af_experiment_force != AF_EXP_AUTO)
		return original;
	flat = batch_choose_variant(saved, original, query_string, cursorOptions, boundParams, false);
	paired = batch_choose_variant(saved, original, query_string, cursorOptions, boundParams, true);
	return paired->planTree->total_cost < flat->planTree->total_cost ? paired : flat;
}

void
native_af_batch_prepare(PlannerInfo *root)
{
	AfBatchContext *context = af_batch_context;
	Node	   *lowered;
	Param	   *parameter;
	SubPlan    *source = NULL;
	Plan	   *plan;
	ListCell   *lc;
	double		rows;

	if (context == NULL || root->parse != context->query || context->lowered ||
		lsecond(context->filter->args) != context->keys)
		return;
	lowered = SS_process_sublinks(root, (Node *) context->keys, false);
	if (lowered == NULL || !IsA(lowered, Param))
	{
		context->rejected = true;
		return;
	}
	parameter = castNode(Param, lowered);
	foreach(lc, root->init_plans)
	{
		SubPlan    *item = lfirst_node(SubPlan, lc);

		if (item->subLinkType == ARRAY_SUBLINK && item->setParam != NIL &&
			list_length(item->setParam) == 1 &&
			linitial_int(item->setParam) == parameter->paramid)
		{
			if (source != NULL)
			{
				context->rejected = true;
				return;
			}
			source = item;
		}
	}
	if (source == NULL || parameter->paramkind != PARAM_EXEC ||
		parameter->paramtype != INT8ARRAYOID || source->parParam != NIL ||
		source->args != NIL || source->firstColType != INT8OID)
	{
		context->rejected = true;
		return;
	}
	plan = planner_subplan_get_plan(root, source);
	rows = clamp_row_est(plan->plan_rows);
	parameter->native_af_array_length = rows;
	parameter->native_af_batch_keys = true;
	/* Source and CTE producer are already charged by native InitPlans. */
	source->startup_cost += 2.0 * cpu_tuple_cost * rows + cpu_operator_cost * rows;
	if (rows > 1.0)
		source->startup_cost += 2.0 * cpu_operator_cost * rows * log(rows) / log(2.0);
	context->filter->args = list_make2(linitial(context->filter->args), parameter);
	context->param_id = parameter->paramid;
	context->array_plan_id = source->plan_id;
	context->lowered = true;
}

Cost
native_af_batch_bitmap_savings(PlannerInfo *root, RelOptInfo *rel,
							   Path *bitmapqual, ParamPathInfo *param_info,
							   double tuples_fetched)
{
	IndexPath  *path;
	RestrictInfo *key = NULL;
	ListCell   *lc;
	double		selectivity;
	Cost		index_cost;
	QualCost	qual_cost;
	double		tuples;
	double		pages;
	double		lossy = 0;
	double		rechecks = 0;
	double		table_pages;
	long		maxentries;

	if (native_af_mode != AF_ADMISSION_FIRST || af_batch_context == NULL ||
		root->parse != af_batch_context->query || !af_batch_context->lowered ||
		rel->relid != af_batch_context->inner_rti || param_info != NULL ||
		bitmapqual == NULL || !IsA(bitmapqual, IndexPath))
		return 0;
	path = castNode(IndexPath, bitmapqual);
	if (path->path.param_info != NULL || path->indexinfo->relam != BTREE_AM_OID ||
		path->indexinfo->indexprs != NIL || path->indexinfo->indpred != NIL)
		return 0;
	foreach(lc, path->indexclauses)
	{
		IndexClause *clause = lfirst_node(IndexClause, lc);
		ScalarArrayOpExpr *array;
		Node	   *right;

		if (clause->lossy)
			return 0;
		if (!IsA(clause->rinfo->clause, ScalarArrayOpExpr))
			continue;
		array = castNode(ScalarArrayOpExpr, clause->rinfo->clause);
		if (list_length(array->args) != 2)
			continue;
		right = lsecond(array->args);
		if (right == NULL || !IsA(right, Param) ||
			!castNode(Param, right)->native_af_batch_keys)
			continue;
		if (castNode(Param, right)->paramkind != PARAM_EXEC ||
			castNode(Param, right)->paramtype != INT8ARRAYOID ||
			castNode(Param, right)->paramid != af_batch_context->param_id ||
			castNode(Param, right)->native_af_array_length !=
			castNode(Param, lsecond(af_batch_context->filter->args))->native_af_array_length ||
			!IsA(linitial(array->args), Var) || clause->indexcol != 0 ||
			castNode(Var, linitial(array->args))->varno != rel->relid ||
			castNode(Var, linitial(array->args))->varattno != path->indexinfo->indexkeys[0] ||
			array->opno != af_batch_context->filter->opno)
			return 0;
		if (key != NULL || !array->useOr || array->opfuncid != F_INT8EQ ||
			array->hashfuncid != InvalidOid ||
			!list_member_ptr(rel->baserestrictinfo, clause->rinfo))
			return 0;
		key = clause->rinfo;
	}
	if (key == NULL)
		return 0;
	cost_qual_eval_node(&qual_cost, (Node *) key, root);
	cost_bitmap_tree_node(bitmapqual, &index_cost, &selectivity);
	tuples = clamp_row_est(selectivity * rel->tuples);
	table_pages = Max(1.0, (double) rel->pages);
	pages = Min((2.0 * table_pages * tuples) / (2.0 * table_pages + tuples),
				(double) rel->pages);
	maxentries = tbm_calculate_entries(work_mem * 1024.0);
	if (maxentries < pages)
		lossy = Max(0, pages - maxentries / 2);
	if (lossy > 0 && pages > 0)
		rechecks = Min(tuples_fetched,
					   clamp_row_est((lossy / pages) * rel->tuples));
	return Max(0, tuples_fetched - rechecks) * qual_cost.per_tuple;
}

/* Conditional domain of the first proven CTE R / filtered ordinary S pair.
 * No same-side or larger-join correction, row floor, or shared PPI mutation. */
void
native_af_batch_join_scope(PlannerInfo *root, RelOptInfo *joinrel,
						   RelOptInfo *outer_rel, RelOptInfo *inner_rel)
{
	AfBatchContext *context = af_batch_context;

	if (native_af_mode != AF_ADMISSION_FIRST || context == NULL ||
		root->parse != context->query || !context->lowered ||
		bms_num_members(joinrel->relids) <= 2 ||
		!bms_is_member(context->outer_rti, joinrel->relids) ||
		!bms_is_member(context->inner_rti, joinrel->relids))
		return;

	/*
	 * Called only where PG first sets shared joinrel.rows.  A later better
	 * partition must never overwrite this rejection or rescue its estimate.
	 */
	if ((bms_is_member(context->outer_rti, outer_rel->relids) &&
		 bms_is_member(context->inner_rti, inner_rel->relids)) ||
		(bms_is_member(context->inner_rti, outer_rel->relids) &&
		 bms_is_member(context->outer_rti, inner_rel->relids)))
		context->rejected = true;
}

bool
native_af_batch_join_rows(PlannerInfo *root, RelOptInfo *joinrel,
						  RelOptInfo *outer_rel, RelOptInfo *inner_rel,
						  double outer_rows, double inner_rows,
						  SpecialJoinInfo *sjinfo, List *restrictlist,
						  double *rows_out)
{
	AfBatchContext *context = af_batch_context;
	RelOptInfo *r;
	RelOptInfo *s;
	Bitmapset  *pair;
	List	   *remaining = NIL;
	ListCell   *lc;
	bool		marked = false;
	bool		edge = false;
	Selectivity other;

	if (native_af_mode != AF_ADMISSION_FIRST || context == NULL ||
		root->parse != context->query || !context->lowered || context->rejected ||
		sjinfo->jointype != JOIN_INNER ||
		outer_rel->reloptkind != RELOPT_BASEREL ||
		inner_rel->reloptkind != RELOPT_BASEREL ||
		bms_num_members(outer_rel->relids) != 1 ||
		bms_num_members(inner_rel->relids) != 1 ||
		outer_rows != outer_rel->rows || inner_rows != inner_rel->rows)
		return false;
	r = outer_rel->relid == context->outer_rti ? outer_rel : inner_rel;
	s = r == outer_rel ? inner_rel : outer_rel;
	if (r->relid != context->outer_rti || s->relid != context->inner_rti ||
		r->rtekind != RTE_CTE || s->rtekind != RTE_RELATION ||
		r->baserestrictinfo != NIL)
		return false;
	pair = bms_union(r->relids, s->relids);
	marked = bms_equal(pair, joinrel->relids);
	bms_free(pair);
	if (!marked)
		return false;
	marked = false;
	foreach(lc, s->baserestrictinfo)
	{
		RestrictInfo *qual = lfirst_node(RestrictInfo, lc);
		ScalarArrayOpExpr *array;
		Param	   *param;
		Var		   *key;

		if (!IsA(qual->clause, ScalarArrayOpExpr))
			continue;
		array = castNode(ScalarArrayOpExpr, qual->clause);
		if (list_length(array->args) != 2 || !IsA(linitial(array->args), Var) ||
			!IsA(lsecond(array->args), Param))
			continue;
		key = linitial_node(Var, array->args);
		param = lsecond_node(Param, array->args);
		if (param->native_af_batch_keys && param->paramkind == PARAM_EXEC &&
			param->paramtype == INT8ARRAYOID && param->paramid == context->param_id &&
			key->varno == context->inner_rti && key->varattno == context->inner_key &&
			array->useOr && array->opno == context->filter->opno)
			marked = true;
	}
	if (!marked)
		return false;
	foreach(lc, restrictlist)
	{
		RestrictInfo *qual = lfirst_node(RestrictInfo, lc);
		OpExpr	   *op;
		Var		   *a;
		Var		   *b;
		bool		covered = false;

		if (IsA(qual->clause, OpExpr))
		{
			op = castNode(OpExpr, qual->clause);
			if (builtin_equality(op) && get_opcode(op->opno) == F_INT8EQ &&
				list_length(op->args) == 2 && IsA(linitial(op->args), Var) &&
				IsA(lsecond(op->args), Var))
			{
				a = linitial_node(Var, op->args);
				b = lsecond_node(Var, op->args);
				if (b->varno == context->outer_rti)
				{
					Var		   *swap = a;

					a = b;
					b = swap;
				}
				covered = a->varno == context->outer_rti &&
					a->varattno == context->outer_key &&
					b->varno == context->inner_rti && b->varattno == context->inner_key &&
					a->vartype == INT8OID && b->vartype == INT8OID &&
					a->varlevelsup == 0 && b->varlevelsup == 0 &&
					bms_is_empty(a->varnullingrels) && bms_is_empty(b->varnullingrels);
			}
		}
		if (covered)
			edge = true;
		else
		{
			if (!bms_is_subset(qual->clause_relids, joinrel->relids))
				return false;
			remaining = lappend(remaining, qual);
		}
	}
	if (!edge)
		return false;
	other = clauselist_selectivity(root, remaining, 0, JOIN_INNER, sjinfo);
	if (!isfinite(other) || other < 0 || other > 1)
		return false;
	*rows_out = clamp_row_est(s->rows * other);
	context->domain_costed = true;
	return true;
}

/* -------------------------------------------------------------------------
 * Run-time join-input filter ("AF Join Input Authorization Filter")
 * -------------------------------------------------------------------------
 */

/*
 * Exact, optional AF join-input reduction. The protected scan and its RLS
 * quals are unchanged. The wrapper forwards directly until ordinary execution
 * has accumulated enough work to consider building the admitted bounded key
 * array in the same EState, role and statement snapshot.
 */
#define AF_PREFILTER_TRIGGER 1024
#define AF_PREFILTER_BITMAP_MAX_BYTES (1024 * 1024)

typedef struct AfPrefilterState
{
	CustomScanState css;
	PlanState  *child;
	AttrNumber	foreign_key_attr;
	uint64		seen;
	uint64		removed;
	uint64		activation_row;
	int			shared_access_budget;
	int64		initial_hits;
	int64		initial_reads;
	int64		checked_shared_accesses;
	bool		started;
	bool		attempted;
	bool		enabled;
	int64	   *keys;
	int			nkeys;
	uint64	   *key_bitmap;
	int64		key_bitmap_base;
	uint64		key_bitmap_span;
} AfPrefilterState;

static int
af_prefilter_int64_compare(const void *left, const void *right)
{
	int64		a = *(const int64 *) left;
	int64		b = *(const int64 *) right;

	return (a > b) - (a < b);
}

static inline bool
af_prefilter_contains(AfPrefilterState *state, int64 key)
{
	if (state->key_bitmap != NULL)
	{
		uint64		offset = (uint64) key - (uint64) state->key_bitmap_base;

		return offset <= state->key_bitmap_span &&
			(state->key_bitmap[offset / 64] & (UINT64CONST(1) << (offset % 64))) != 0;
	}
	return state->nkeys > 0 &&
		bsearch(&key, state->keys, state->nkeys, sizeof(int64), af_prefilter_int64_compare) != NULL;
}

static void
af_prefilter_activate(AfPrefilterState *state)
{
	CustomScan *scan = castNode(CustomScan, state->css.ss.ps.plan);
	EState	   *estate = state->css.ss.ps.state;
	List	   *info = scan->custom_private;
	Param	   *param = lsecond_node(Param, scan->custom_exprs);
	ParamExecData *value;
	SubPlanState *source;
	SubPlan    *subplan;
	Plan	   *source_plan;
	ArrayType  *array;
	Datum	   *entries;
	bool	   *isnull;
	int			count;
	int16		typlen;
	bool		typbyval;
	char		typalign;
	int			i;
	int64		min_key = PG_INT64_MAX;
	int64		max_key = PG_INT64_MIN;
	Oid			role = DatumGetObjectId(linitial_node(Const, info)->constvalue);
	int			maximum = intVal(lsecond(info));
	int			source_id = intVal(lthird(info));

	state->attempted = true;
	if (native_af_mode != AF_ADMISSION_FIRST || GetUserId() != role ||
		IsParallelWorker() || estate->es_epq_active != NULL ||
		!estate->es_native_af_complete_run ||
		param->paramkind != PARAM_EXEC || param->paramtype != INT8ARRAYOID ||
		estate->es_param_exec_vals == NULL ||
		param->paramid < 0 ||
		param->paramid >= list_length(estate->es_plannedstmt->paramExecTypes) ||
		list_nth_oid(estate->es_plannedstmt->paramExecTypes, param->paramid) != INT8ARRAYOID ||
		source_id <= 0 || source_id > list_length(estate->es_subplanstates) ||
		source_id > list_length(estate->es_plannedstmt->subplans))
		return;

	value = &estate->es_param_exec_vals[param->paramid];
	if (value->execPlan == NULL || !IsA(value->execPlan, SubPlanState))
		return;
	source = castNode(SubPlanState, value->execPlan);
	subplan = source->subplan;
	source_plan = list_nth(estate->es_plannedstmt->subplans, source_id - 1);
	if (subplan == NULL || subplan->subLinkType != ARRAY_SUBLINK ||
		subplan->plan_id != source_id || subplan->firstColType != INT8OID ||
		subplan->testexpr != NULL || subplan->parParam != NIL || subplan->args != NIL ||
		subplan->useHashTable || !IsA(subplan->setParam, IntList) ||
		list_length(subplan->setParam) != 1 ||
		linitial_int(subplan->setParam) != param->paramid ||
		source->planstate != list_nth(estate->es_subplanstates, source_id - 1) ||
		source->planstate->plan != source_plan || !IsA(source_plan, Limit) ||
		source_plan->targetlist == NIL ||
		exprType((Node *) linitial_node(TargetEntry, source_plan->targetlist)->expr) != INT8OID ||
		source->parent == NULL || source->parent->state != estate ||
		!native_af_policy_source_binding(estate, source->planstate, lfourth(info)))
		return;

	ExecSetParamPlan(source, state->css.ss.ps.ps_ExprContext);
	if (value->isnull)
		return;
	array = DatumGetArrayTypeP(value->value);
	if (ARR_ELEMTYPE(array) != INT8OID || ARR_NDIM(array) > 1 ||
		ArrayGetNItems(ARR_NDIM(array), ARR_DIMS(array)) > maximum)
		return;

	get_typlenbyvalalign(INT8OID, &typlen, &typbyval, &typalign);
	deconstruct_array(array, INT8OID, typlen, typbyval, typalign, &entries, &isnull, &count);
	if (count > 0)
		state->keys = MemoryContextAlloc(estate->es_query_cxt, sizeof(int64) * count);
	for (i = 0; i < count; i++)
	{
		int64		key;

		if (isnull[i])
			continue;
		key = DatumGetInt64(entries[i]);
		state->keys[state->nkeys++] = key;
		min_key = Min(min_key, key);
		max_key = Max(max_key, key);
	}
	if (state->nkeys > 1)
	{
		uint64		span = (uint64) max_key - (uint64) min_key;
		uint64		words = span / 64 + 1;

		/*
		 * Limit the span to 16 bits per key before rounding to whole words.
		 * Unsigned subtraction handles ranges spanning zero.
		 */
		if (span < (uint64) state->nkeys * 16 &&
			words <= AF_PREFILTER_BITMAP_MAX_BYTES / sizeof(uint64))
		{
			state->key_bitmap = MemoryContextAllocZero(estate->es_query_cxt, (Size) words * sizeof(uint64));
			state->key_bitmap_base = min_key;
			state->key_bitmap_span = span;
			for (i = 0; i < state->nkeys; i++)
			{
				uint64		offset = (uint64) state->keys[i] - (uint64) min_key;

				state->key_bitmap[offset / 64] |= UINT64CONST(1) << (offset % 64);
			}
			pfree(state->keys);
			state->keys = NULL;
		}
		else
			qsort(state->keys, state->nkeys, sizeof(int64), af_prefilter_int64_compare);
	}
	pfree(entries);
	pfree(isnull);
	state->enabled = true;
}

static void
af_prefilter_begin(CustomScanState *node, EState *estate, int eflags)
{
	AfPrefilterState *state = (AfPrefilterState *) node;
	CustomScan *scan = castNode(CustomScan, node->ss.ps.plan);
	Var		   *key;
	TupleDesc	input_type;

	if (list_length(scan->custom_plans) != 1 || list_length(scan->custom_exprs) != 2 ||
		list_length(scan->custom_private) != 5 || !IsA(linitial(scan->custom_exprs), Var) ||
		!IsA(lsecond(scan->custom_exprs), Param))
		elog(ERROR, "invalid AF prefilter plan");
	state->shared_access_budget = intVal(list_nth(scan->custom_private, 4));
	state->child = ExecInitNode(linitial(scan->custom_plans), estate, eflags);
	node->custom_ps = list_make1(state->child);

	/*
	 * The custom scan target list is a copy of the ordinary child's output.
	 * setrefs binds the proven equality key to that target-list position.
	 */
	key = linitial_node(Var, scan->custom_exprs);
	input_type = ExecGetResultType(state->child);
	if (key->varno != INDEX_VAR || key->varattno < 1 || key->varattno > input_type->natts ||
		key->vartype != INT8OID || TupleDescAttr(input_type, key->varattno - 1)->atttypid != INT8OID)
		elog(ERROR, "invalid AF prefilter key binding");
	state->foreign_key_attr = key->varattno;
}

static TupleTableSlot *
af_prefilter_exec(CustomScanState *node)
{
	AfPrefilterState *state = (AfPrefilterState *) node;
	ExprContext *context = node->ss.ps.ps_ExprContext;
	TupleTableSlot *scan_slot = node->ss.ss_ScanTupleSlot;
	ProjectionInfo *projection = node->ss.ps.ps_ProjInfo;
	TupleTableSlot *slot;
	int			columns = scan_slot->tts_tupleDescriptor->natts;

	if (!state->started)
	{
		state->initial_hits = pgBufferUsage.shared_blks_hit;
		state->initial_reads = pgBufferUsage.shared_blks_read;
		state->started = true;
	}

	for (;;)
	{
		bool		isnull;
		Datum		datum;

		slot = ExecProcNode(state->child);
		if (TupIsNull(slot))
			break;

		state->seen++;
		if (!state->attempted && state->seen > AF_PREFILTER_TRIGGER)
		{
			state->checked_shared_accesses =
				(pgBufferUsage.shared_blks_hit - state->initial_hits) +
				(pgBufferUsage.shared_blks_read - state->initial_reads);
			if (state->checked_shared_accesses >= state->shared_access_budget)
			{
				state->activation_row = state->seen;
				af_prefilter_activate(state);
			}
		}

		if (slot->tts_tupleDescriptor->natts != columns || scan_slot->tts_ops != &TTSOpsVirtual)
			elog(ERROR, "invalid AF prefilter slot");
		if (state->enabled)
		{
			datum = slot_getattr(slot, state->foreign_key_attr, &isnull);
			if (isnull || !af_prefilter_contains(state, DatumGetInt64(datum)))
			{
				state->removed++;
				continue;
			}
		}
		slot_getsomeattrs(slot, columns);
		ExecClearTuple(scan_slot);
		memcpy(scan_slot->tts_values, slot->tts_values, sizeof(Datum) * columns);
		memcpy(scan_slot->tts_isnull, slot->tts_isnull, sizeof(bool) * columns);
		ExecStoreVirtualTuple(scan_slot);
		ResetExprContext(context);
		context->ecxt_scantuple = scan_slot;
		return projection != NULL ? ExecProject(projection) : scan_slot;
	}
	ExecClearTuple(scan_slot);
	return projection != NULL ? ExecClearTuple(projection->pi_state.resultslot) : scan_slot;
}

static void
af_prefilter_end(CustomScanState *node)
{
	ExecEndNode(((AfPrefilterState *) node)->child);
}

static void
af_prefilter_rescan(CustomScanState *node)
{
	AfPrefilterState *state = (AfPrefilterState *) node;
	CustomScan *scan = castNode(CustomScan, node->ss.ps.plan);
	Param	   *param = lsecond_node(Param, scan->custom_exprs);

	/*
	 * The key set belongs to the same uncorrelated statement snapshot. Only
	 * ordinary child parameters can change as the join advances.
	 */
	if (bms_is_member(param->paramid, node->ss.ps.chgParam))
	{
		state->enabled = false;
		state->attempted = true;
	}
	if (node->ss.ps.chgParam != NULL)
		UpdateChangedParamSet(state->child, node->ss.ps.chgParam);
	if (state->child->chgParam == NULL)
		ExecReScan(state->child);
}

static void
af_prefilter_explain(CustomScanState *node, List *ancestors, ExplainState *es)
{
	AfPrefilterState *state = (AfPrefilterState *) node;

	ExplainPropertyInteger("AF Prefilter Trigger", NULL, AF_PREFILTER_TRIGGER, es);
	ExplainPropertyInteger("AF Prefilter Shared Access Budget", NULL, state->shared_access_budget, es);
	if (es->analyze)
	{
		ExplainPropertyBool("AF Prefilter Activated", state->enabled, es);
		if (state->enabled)
			ExplainPropertyText("AF Prefilter Key Representation", state->key_bitmap == NULL ? "sorted" : "bitmap", es);
		ExplainPropertyInteger("AF Prefilter Activation Attempt Row", NULL, state->activation_row, es);
		ExplainPropertyInteger("AF Prefilter Last Checked Shared Accesses", NULL, state->checked_shared_accesses, es);
		ExplainPropertyInteger("AF Prefilter Input Rows", NULL, state->seen, es);
		ExplainPropertyInteger("AF Prefilter Discarded Rows", NULL, state->removed, es);
	}
}

static const CustomExecMethods af_prefilter_exec_methods = {
	.CustomName = "AF Join Input Authorization Filter",
	.BeginCustomScan = af_prefilter_begin,
	.ExecCustomScan = af_prefilter_exec,
	.EndCustomScan = af_prefilter_end,
	.ReScanCustomScan = af_prefilter_rescan,
	.ExplainCustomScan = af_prefilter_explain,
};

static Node *
af_prefilter_create(CustomScan *scan)
{
	AfPrefilterState *state = palloc0(sizeof(AfPrefilterState));

	NodeSetTag(state, T_CustomScanState);
	state->css.methods = &af_prefilter_exec_methods;
	return (Node *) state;
}

static const CustomScanMethods af_prefilter_scan_methods = {
	.CustomName = "AF Join Input Authorization Filter",
	.CreateCustomScanState = af_prefilter_create
};

static bool
af_prefilter_supported_scan(Plan *plan)
{
	return IsA(plan, SeqScan) || IsA(plan, IndexScan) || IsA(plan, BitmapHeapScan);
}

static Plan **
af_prefilter_ordinary_input(Plan **link, List *foreign_keys, Var **selected)
{
	Plan	   *plan = *link;
	Plan	  **result;
	ListCell   *edge;

	if (plan == NULL || IsA(plan, MergeJoin) || IsA(plan, Gather) ||
		IsA(plan, GatherMerge) || IsA(plan, CustomScan))
		return NULL;
	if (af_prefilter_supported_scan(plan))
	{
		foreach(edge, foreign_keys)
		{
			Var		   *key = lfirst_node(Var, edge);
			ListCell   *column;

			if (key->varno != ((Scan *) plan)->scanrelid)
				continue;
			foreach(column, plan->targetlist)
			{
				TargetEntry *entry = lfirst_node(TargetEntry, column);

				if (IsA(entry->expr, Var) && stream_same_var(key, (Var *) entry->expr))
				{
					ListCell   *target;

					foreach(target, plan->targetlist)
					{
						Expr	   *expression = lfirst_node(TargetEntry, target)->expr;
						Var		   *value;

						if (!IsA(expression, Var))
							return NULL;
						value = castNode(Var, expression);
						if (value->varno != key->varno || value->varlevelsup != 0 || value->varattno <= 0)
							return NULL;
					}
					*selected = castNode(Var, entry->expr);
					return link;
				}
			}
		}
		return NULL;
	}

	/*
	 * The candidate must remain below a chain of ordinary monotone operators
	 * in the chosen INNER input. No cardinality or evaluation-order barrier.
	 */
	if (IsA(plan, NestLoop) || IsA(plan, HashJoin))
	{
		if (((Join *) plan)->jointype != JOIN_INNER)
			return NULL;
	}
	else if (!IsA(plan, Hash) && !IsA(plan, Sort) && !IsA(plan, Material))
		return NULL;
	result = af_prefilter_ordinary_input(&plan->lefttree, foreign_keys, selected);
	return result != NULL ? result : af_prefilter_ordinary_input(&plan->righttree, foreign_keys, selected);
}

static Plan **
af_prefilter_before_protected(Plan *plan, Index protected_rti)
{
	Plan	  **result;

	if (plan == NULL || IsA(plan, MergeJoin) || IsA(plan, Gather) ||
		IsA(plan, GatherMerge) || IsA(plan, CustomScan))
		return NULL;
	if (IsA(plan, NestLoop) && castNode(NestLoop, plan)->join.jointype == JOIN_INNER &&
		IsA(plan->righttree, IndexScan) && ((Scan *) plan->righttree)->scanrelid == protected_rti)
		return &plan->lefttree;
	result = af_prefilter_before_protected(plan->lefttree, protected_rti);
	return result != NULL ? result : af_prefilter_before_protected(plan->righttree, protected_rti);
}

static bool
af_prefilter_mark_serial(Plan *plan, Plan *wrapper)
{
	if (plan == NULL)
		return false;
	if (plan != wrapper &&
		!af_prefilter_mark_serial(plan->lefttree, wrapper) &&
		!af_prefilter_mark_serial(plan->righttree, wrapper))
		return false;
	plan->parallel_safe = false;
	return true;
}

void
native_af_add_join_input_filter(PlannerInfo *root, Plan *plan, Query *original, int cursorOptions)
{
	MembershipCandidate *candidate;
	SubPlan    *source;
	Param	   *param;
	Bitmapset  *relations = NULL;
	List	   *clauses = NIL;
	List	   *foreign_keys = NIL;
	List	   *source_oids = NIL;
	ListCell   *cell;
	Plan	  **outer;
	Plan	  **location;
	Plan	   *child;
	Var		   *foreign_key = NULL;
	CustomScan *wrapper;
	AfBatchVars business = {0};
	bool		literal_lists = true;
	int			shared_access_budget;

	if (native_af_mode != AF_ADMISSION_FIRST || native_af_experiment_force != AF_EXP_AUTO ||
		af_batch_depth != 0 || root->parent_root != NULL || original == NULL ||
		root->glob->parallelModeNeeded ||
		(cursorOptions & (CURSOR_OPT_FAST_PLAN | CURSOR_OPT_SCROLL)) ||
		list_length(root->native_af_membership) != 1 ||
		list_length(original->rtable) < 3 || original->hasWindowFuncs ||
		original->limitCount != NULL || original->limitOffset != NULL ||
		!native_af_readonly_statement(root))
		return;
	candidate = linitial(root->native_af_membership);
	source = candidate->enumerated.initplan;
	if (candidate->policy == NULL || source == NULL ||
		candidate->enumerated.key_filter == NULL ||
		!isfinite(candidate->enumerated.acl_rows) || candidate->enumerated.acl_rows < 1)
		return;
	outer = af_prefilter_before_protected(plan, candidate->rti);
	if (outer == NULL ||
		!stream_jointree((Node *) original->jointree, original, &relations, &clauses) ||
		bms_num_members(relations) < 3)
		return;

	foreach(cell, original->rtable)
	{
		RangeTblEntry *rte = lfirst_node(RangeTblEntry, cell);
		Index		rti = foreach_current_index(cell) + 1;
		bool		rls;

		if (rte->rtekind == RTE_JOIN)
			continue;
		if (!batch_relation(rte, &rls) || !batch_permission(original, rte) ||
			!bms_is_member(rti, relations) || rti >= root->simple_rel_array_size ||
			planner_rt_fetch(rti, root)->relid != rte->relid ||
			(rti == candidate->rti ? !rls : rls || rte->securityQuals != NIL))
			return;
	}
	foreach(cell, clauses)
	{
		Node	   *node = lfirst(cell);
		OpExpr	   *op;
		Var		   *left;
		Var		   *right;

		if (!stream_edge(node, original))
			continue;
		op = castNode(OpExpr, node);
		left = linitial_node(Var, op->args);
		right = lsecond_node(Var, op->args);
		if (stream_same_var(candidate->key, left))
			foreign_keys = lappend(foreign_keys, right);
		else if (stream_same_var(candidate->key, right))
			foreign_keys = lappend(foreign_keys, left);
	}
	location = af_prefilter_ordinary_input(outer, foreign_keys, &foreign_key);
	if (location == NULL)
		return;
	business.query = original;
	business.protected_rti = candidate->rti;
	if (contain_volatile_functions((Node *) original) ||
		batch_principal_expression((Node *) original, &literal_lists) ||
		batch_user_vars((Node *) original->targetList, &business) ||
		batch_user_vars((Node *) clauses, &business) ||
		batch_user_vars(original->havingQual, &business))
		return;
	param = lsecond_node(Param, castNode(ScalarArrayOpExpr, candidate->enumerated.key_filter->clause)->args);
	foreach(cell, castNode(Query, candidate->keys->subselect)->rtable)
	{
		RangeTblEntry *rte = lfirst_node(RangeTblEntry, cell);

		if (rte->rtekind == RTE_RELATION)
			source_oids = list_append_unique_oid(source_oids, rte->relid);
	}
	if (source_oids == NIL)
		return;
	foreach(cell, plan->initPlan)
	{
		SubPlan    *installed = lfirst_node(SubPlan, cell);

		if (installed->plan_id == source->plan_id || equal(installed->setParam, source->setParam))
			return;
	}

	/*
	 * Materializing an array consumes every witness, including duplicates.
	 * Use the bounded witness estimate as a conservative shared-access budget
	 * for ordinary business work before paying that startup. A short query
	 * that reaches the tuple trigger can still finish on the original input.
	 */
	shared_access_budget = Max(AF_PREFILTER_TRIGGER,
							   (int) ceil(Min(candidate->enumerated.acl_rows,
											  (double) native_af_max_authorized_keys + 1)));
	child = *location;
	wrapper = makeNode(CustomScan);
	wrapper->scan.plan.targetlist = copyObject(child->targetlist);
	wrapper->scan.plan.plan_rows = child->plan_rows;
	wrapper->scan.plan.plan_width = child->plan_width;
	wrapper->scan.plan.startup_cost = child->startup_cost;
	wrapper->scan.plan.total_cost = child->total_cost;
	wrapper->scan.scanrelid = ((Scan *) child)->scanrelid;
	wrapper->custom_relids = bms_make_singleton(wrapper->scan.scanrelid);
	wrapper->custom_plans = list_make1(child);
	wrapper->custom_scan_tlist = copyObject(child->targetlist);
	wrapper->custom_exprs = list_make2(copyObject(foreign_key), copyObject(param));
	wrapper->custom_private = list_make5(
										 makeConst(OIDOID, -1, InvalidOid, sizeof(Oid), ObjectIdGetDatum(GetUserId()), false, true),
										 makeInteger(native_af_max_authorized_keys), makeInteger(source->plan_id), source_oids,
										 makeInteger(shared_access_budget));
	wrapper->methods = &af_prefilter_scan_methods;
	plan->initPlan = lappend(plan->initPlan, source);
	*location = &wrapper->scan.plan;
	af_prefilter_mark_serial(plan, *location);
}
