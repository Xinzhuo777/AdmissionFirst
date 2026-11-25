/*
 * A finite selection/projection comparison with exact policy at the slot.
 *
 * Both roots implement the same checked native policy and fixed leakproof
 * integer predicate at one occurrence. They retain the same identity through
 * an ordinary scan boundary. The only two reachable requirements are the
 * root requirement and that requirement with the bound identity retained.
 * The enclosing query consumes the complete result. We use PostgreSQL total
 * cost, including a sort if demanded, and compare order/materialization
 * inputs before applying the additive selection/projection cost rule.
 */
#include "postgres.h"

#include <math.h>

#include "access/stratnum.h"
#include "catalog/pg_am_d.h"
#include "catalog/pg_opfamily_d.h"
#include "catalog/pg_type_d.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "optimizer/cost.h"
#include "optimizer/optimizer.h"
#include "optimizer/pathnode.h"
#include "optimizer/paths.h"
#include "optimizer/tlist.h"
#include "optimizer/native_af.h"
#include "optimizer/native_af_admission.h"
#include "optimizer/native_af_sp.h"
#include "parser/parsetree.h"
#include "parser/parse_relation.h"
#include "utils/fmgroids.h"
#include "utils/lsyscache.h"

typedef struct ExactRoot
{
	Index		occurrence;
	Oid			relation;
	Oid			principal;
	AttrNumber	identity;
	PathTarget *target;
	RestrictInfo *policy;
	RestrictInfo *selection;
	NativeAfScanDelivery delivery;
} ExactRoot;

static bool
plain_column(Var *var, Index occurrence)
{
	return var->varno == occurrence && var->varlevelsup == 0 &&
		var->varattno > 0 && bms_is_empty(var->varnullingrels);
}

/*
 * Restrict the candidate slot to the frozen SP grammar. The optional final
 * ordering is a physical requirement with a costed sort enforcer. No LIMIT,
 * early-stop parent, expression projection, or join is admitted here.
 */
static RestrictInfo *
sp_selection(PlannerInfo *root, RelOptInfo *rel, RangeTblEntry *rte,
			 RestrictInfo *policy)
{
	Query	   *query = root->parse;
	RestrictInfo *selection;
	OpExpr	   *op;
	Var		   *column;
	Const	   *value;
	Oid			function;
	ListCell   *cell;

	if (root->parent_root != NULL || query->commandType != CMD_SELECT ||
		query->jointree == NULL ||
		query->setOperations || query->cteList || query->distinctClause ||
		query->groupClause || query->groupingSets || query->havingQual ||
		query->hasAggs || query->hasWindowFuncs || query->hasTargetSRFs ||
		query->hasModifyingCTE || query->rowMarks || query->limitCount ||
		query->limitOffset ||
		(root->glob->parallelModeOK && !native_af_allow_serial_candidates()) ||
		rel->reloptkind != RELOPT_BASEREL || rel->lateral_relids != NULL ||
		list_length(query->jointree->fromlist) != 1 ||
		!IsA(linitial(query->jointree->fromlist), RangeTblRef) ||
		linitial_node(RangeTblRef, query->jointree->fromlist)->rtindex != rel->relid ||
		list_length(rel->baserestrictinfo) != 2 ||
		!list_member_ptr(rel->baserestrictinfo, policy) ||
		planner_rt_fetch(rel->relid, root) != rte)
		return NULL;

	foreach(cell, query->targetList)
	{
		TargetEntry *entry = lfirst_node(TargetEntry, cell);

		if (!IsA(entry->expr, Var) ||
			!plain_column(castNode(Var, entry->expr), rel->relid))
			return NULL;
	}

	selection = linitial(rel->baserestrictinfo);
	if (selection == policy)
		selection = lsecond(rel->baserestrictinfo);
	if (!IsA(selection->clause, OpExpr))
		return NULL;
	op = castNode(OpExpr, selection->clause);
	function = get_opcode(op->opno);
	if ((function != F_INT4EQ && function != F_INT8EQ) ||
		!get_func_leakproof(function) || op->opretset || op->opresulttype != BOOLOID ||
		list_length(op->args) != 2 ||
		!IsA(linitial(op->args), Var) || !IsA(lsecond(op->args), Const))
		return NULL;
	column = linitial_node(Var, op->args);
	value = lsecond_node(Const, op->args);
	if (!plain_column(column, rel->relid) ||
		column->vartype != value->consttype || value->constisnull)
		return NULL;
	return selection;
}

/*
 * Independently close each descriptor. The scan constructor will consume
 * exactly these restrictions and this target, on the same RTE/permissions
 * as the original query. An index is usable for the leakproof selection
 * only; the non-indexable policy remains a heap qualification.
 */
static bool
admit_exact_root(PlannerInfo *root, RelOptInfo *input, RangeTblEntry *rte,
				 RestrictInfo *policy, RestrictInfo *selection, Var *key,
				 IndexOptInfo *index, const NativeAfScanRequirement *need,
				 ExactRoot *result)
{
	RTEPermissionInfo *permissions;
	NativeAfScanRule rule = {
		.input = input->reltarget,
		.output = need->target,
		.target_filter = (Node *) selection->clause,
		.before_check = list_make1(selection->clause),
		.exact_check = (Node *) policy->clause,
		.identity = key->varattno
	};

	if (planner_rt_fetch(input->relid, root) != rte ||
		rte->perminfoindex == 0 || list_length(rte->securityQuals) != 1 ||
		list_length(linitial(rte->securityQuals)) != 1 ||
		policy->security_level != 0 ||
		!equal(policy->clause, linitial(linitial(rte->securityQuals))) ||
		!list_member_ptr(input->baserestrictinfo, policy) ||
		!list_member_ptr(input->baserestrictinfo, selection) ||
		!plain_column(key, input->relid) || key->vartype != INT8OID)
		return false;

	permissions = getRTEPermissionInfo(root->parse->rteperminfos, rte);
	if (permissions->relid != rte->relid ||
		(permissions->requiredPerms & ACL_SELECT) == 0)
		return false;
	if (index != NULL)
	{
		OpExpr	   *op = castNode(OpExpr, selection->clause);
		Var		   *column = linitial_node(Var, op->args);

		if (index->rel->relid != input->relid || index->relam != BTREE_AM_OID ||
			index->indpred != NIL || index->nkeycolumns == 0 ||
			index->indexkeys[0] != column->varattno ||
			index->opfamily[0] != INTEGER_BTREE_FAM_OID ||
			get_opfamily_member(INTEGER_BTREE_FAM_OID, column->vartype,
								column->vartype, BTEqualStrategyNumber) != op->opno)
			return false;
	}

	result->occurrence = input->relid;
	result->relation = permissions->relid;
	result->principal = OidIsValid(permissions->checkAsUser) ?
		permissions->checkAsUser : GetUserId();
	result->identity = key->varattno;
	result->target = input->reltarget;
	result->policy = policy;
	result->selection = selection;
	return native_af_admit_checked_scan(need, &rule, &result->delivery) == NULL;
}

static Cost
complete_cost(PlannerInfo *root, Path *path, List *order, bool *needs_sort)
{
	Path		sort = {0};

	*needs_sort = !pathkeys_contained_in(order, path->pathkeys);
	if (!*needs_sort)
		return path->total_cost;
	cost_sort(&sort, root, order, path->total_cost, path->rows,
			  path->pathtarget->width, 0.0, work_mem, -1.0);
	return sort.total_cost;
}

static const char *
compare_requirement(const ExactRoot *better, const ExactRoot *worse,
					Path *index, Path *scan, bool need_identity,
					bool index_sort, bool scan_sort, Cost index_cost, Cost scan_cost)
{
	const char *preservation = native_af_scan_preserves(&better->delivery, &worse->delivery,
														need_identity);

	if (preservation != NULL)
		return preservation;
	if (better->occurrence != worse->occurrence ||
		better->relation != worse->relation || better->principal != worse->principal ||
		index->parent->relid != better->occurrence ||
		scan->parent->relid != worse->occurrence ||
		index->pathtarget != better->target || scan->pathtarget != worse->target ||
		!list_member_ptr(index->parent->baserestrictinfo, better->policy) ||
		!list_member_ptr(scan->parent->baserestrictinfo, worse->policy) ||
		!equal(better->policy->clause, worse->policy->clause) ||
		!equal(better->selection->clause, worse->selection->clause) ||
		!equal(better->target->exprs, worse->target->exprs) ||
		(need_identity && better->identity != worse->identity))
		return "binding_mismatch";

	/* Both produce streaming heap tuples, with no output materialization. */
	if (index_sort != scan_sort ||
		compare_pathkeys(index->pathkeys, scan->pathkeys) != PATHKEYS_EQUAL)
		return "order_or_enforcer_mismatch";
	if (index->rows != scan->rows || index->pathtarget->width != scan->pathtarget->width ||
		!isfinite(index->rows) || !isfinite(index_cost) || !isfinite(scan_cost))
		return "cost_input_mismatch";
	return index_cost <= scan_cost ? "pass" : "cost_order_failed";
}

static Float *
cost_value(double amount)
{
	return makeFloat(psprintf("%.17g", amount));
}

/*
 * Return the surviving AF-private paths. The caller may publish them only in
 * this SP scope. Never remove an ordinary path based on a bare cost ordering
 * or apply this result to upper operators outside the admitted grammar.
 *
 * Evidence consists solely of copyObject-safe nodes for a cached Plan.
 */
List *
native_af_sp_exact_paths(PlannerInfo *root, RelOptInfo *rel, RangeTblEntry *rte,
						 RestrictInfo *checked_policy, Var *key, List **evidence)
{
	RestrictInfo *selection = sp_selection(root, rel, rte, checked_policy);
	NativeAfScanRequirement need;
	RelOptInfo *input;
	ExactRoot	scan_root;
	Path	   *scan;
	List	   *survivors = NIL;
	List	   *comparisons = NIL;
	List	   *order = root->sort_pathkeys;
	ListCell   *cell;
	int			rejected_carrier = 0;
	bool		drop_scan = false;

	*evidence = NIL;
	if (selection == NULL || !enable_seqscan ||
		(order == NIL && !enable_bitmapscan) ||
		(order != NIL && (!enable_indexscan || !enable_sort)) ||
		!native_af_scan_requirement(root, rel, rte, &need))
		return NIL;

	/*
	 * A visible-only projection is a candidate only when it differs from
	 * the identity-retaining projection. It must pass the same admission
	 * check before a physical path can be constructed or costed.
	 */
	if (!list_member(rel->reltarget->exprs, key))
	{
		ExactRoot	projected;

		if (!admit_exact_root(root, rel, rte, checked_policy, selection,
							  key, NULL, &need, &projected))
			rejected_carrier++;
	}

	input = palloc(sizeof(*input));
	memcpy(input, rel, sizeof(*input));
	input->consider_parallel = false;
	input->reltarget = copy_pathtarget(rel->reltarget);
	if (!list_member(input->reltarget->exprs, key))
		add_column_to_pathtarget(input->reltarget, (Expr *) key, 0);
	if (!admit_exact_root(root, input, rte, checked_policy, selection,
						  key, NULL, &need, &scan_root))
		return NIL;
	set_pathtarget_cost_width(root, input->reltarget);
	scan = create_seqscan_path(root, input, NULL, 0);
	survivors = list_make1(scan);

	foreach(cell, rel->indexlist)
	{
		IndexOptInfo *index = lfirst_node(IndexOptInfo, cell);
		IndexOptInfo *private_index;
		ExactRoot	index_root;
		IndexClause *clause;
		IndexPath  *index_scan;
		Path	   *candidate;
		List	   *keys = NIL;
		ScanDirection direction = ForwardScanDirection;
		Cost		index_cost;
		Cost		scan_cost;
		bool		index_sort;
		bool		scan_sort;
		const char *at_root;
		const char *at_projection;

		if ((order == NIL && !index->amhasgetbitmap) ||
			(order != NIL && !index->amhasgettuple) ||
			!admit_exact_root(root, input, rte, checked_policy, selection,
							  key, index, &need, &index_root))
			continue;

		if (order != NIL)
		{
			keys = build_index_pathkeys(root, index, direction);
			if (!pathkeys_contained_in(order, keys))
			{
				direction = BackwardScanDirection;
				keys = build_index_pathkeys(root, index, direction);
			}
			if (!pathkeys_contained_in(order, keys))
				continue;
			keys = truncate_useless_pathkeys(root, rel, keys);
			if (!pathkeys_contained_in(order, keys))
				continue;
		}

		private_index = palloc(sizeof(*private_index));
		memcpy(private_index, index, sizeof(*private_index));
		private_index->rel = input;
		clause = makeNode(IndexClause);
		clause->rinfo = selection;
		clause->indexquals = list_make1(selection);
		index_scan = create_index_path(root, private_index, list_make1(clause),
									   NIL, NIL, keys, direction, false, NULL, 1.0, false);
		candidate = order == NIL ?
			(Path *) create_bitmap_heap_path(root, input, (Path *) index_scan,
											NULL, 1.0, 0) : (Path *) index_scan;
		survivors = lappend(survivors, candidate);
		index_cost = complete_cost(root, candidate, order, &index_sort);
		scan_cost = complete_cost(root, scan, order, &scan_sort);
		at_root = compare_requirement(&index_root, &scan_root, candidate, scan,
									  false, index_sort, scan_sort, index_cost, scan_cost);
		at_projection = compare_requirement(&index_root, &scan_root, candidate, scan,
											true, index_sort, scan_sort, index_cost, scan_cost);
		if (native_af_planner_trace_enabled())
			ereport(NOTICE, (errmsg("native_af: SP replacement root %s projection %s",
								   at_root, at_projection)));
		if (strcmp(at_root, "pass") == 0 && strcmp(at_projection, "pass") == 0)
			drop_scan = true;

		comparisons = lappend(comparisons, list_make4(
			makeString(psprintf("%u", index->indexoid)),
			list_make2(makeString(pstrdup(at_root)), makeString(pstrdup(at_projection))),
			list_make4(cost_value(index_cost), cost_value(scan_cost),
					   cost_value(candidate->rows), cost_value(scan->rows)),
			list_make2(makeInteger(index_sort), makeInteger(scan_sort))));
	}
	if (comparisons == NIL)
		return NIL;
	if (drop_scan)
		survivors = list_delete_ptr(survivors, scan);
	if (native_af_planner_trace_enabled())
		ereport(NOTICE,
				(errmsg("native_af: SP occurrence %u admitted %d rejected missing carrier %d pruned %d survivors %d",
						rel->relid, 1 + list_length(comparisons), rejected_carrier,
						drop_scan, list_length(survivors))));
	*evidence = list_make5(makeInteger(rel->relid), makeInteger(key->varattno),
						   makeInteger(rejected_carrier), makeInteger(drop_scan),
						   comparisons);
	return survivors;
}

void
native_af_sp_explain(List *evidence, ExplainState *es)
{
	List	   *comparisons = list_nth(evidence, 4);
	ListCell   *cell;

	ExplainPropertyInteger("AF SP Occurrence", NULL, intVal(linitial(evidence)), es);
	ExplainPropertyInteger("AF SP Carrier Attribute", NULL, intVal(lsecond(evidence)), es);
	ExplainPropertyInteger("AF SP Rejected Missing Carrier Before Cost", NULL,
						   intVal(lthird(evidence)), es);
	ExplainPropertyInteger("AF SP Generated", NULL,
						   1 + list_length(comparisons) + intVal(lthird(evidence)), es);
	ExplainPropertyInteger("AF SP Admitted And Costed", NULL, 1 + list_length(comparisons), es);
	ExplainPropertyInteger("AF SP Pruned", NULL, intVal(lfourth(evidence)), es);
	ExplainPropertyInteger("AF SP Survivors", NULL,
						   1 + list_length(comparisons) - intVal(lfourth(evidence)), es);
	ExplainOpenGroup("AF SP Comparisons", "AF SP Comparisons", false, es);
	foreach(cell, comparisons)
	{
		List	   *comparison = lfirst(cell);
		List	   *verdicts = lsecond(comparison);
		List	   *costs = lthird(comparison);
		List	   *enforcers = lfourth(comparison);

		ExplainOpenGroup("Comparison", NULL, true, es);
		ExplainPropertyText("Index OID", strVal(linitial(comparison)), es);
		ExplainPropertyText("Root Requirement", strVal(linitial(verdicts)), es);
		ExplainPropertyText("Root Plus Carrier Requirement", strVal(lsecond(verdicts)), es);
		ExplainPropertyFloat("Index Cost With Enforcers", NULL, floatVal(linitial(costs)), 8, es);
		ExplainPropertyFloat("Scan Cost With Enforcers", NULL, floatVal(lsecond(costs)), 8, es);
		ExplainPropertyFloat("Index Rows", NULL, floatVal(lthird(costs)), 8, es);
		ExplainPropertyFloat("Scan Rows", NULL, floatVal(lfourth(costs)), 8, es);
		ExplainPropertyBool("Index Needs Sort", intVal(linitial(enforcers)), es);
		ExplainPropertyBool("Scan Needs Sort", intVal(lsecond(enforcers)), es);
		ExplainCloseGroup("Comparison", NULL, true, es);
	}
	ExplainCloseGroup("AF SP Comparisons", "AF SP Comparisons", false, es);
}
