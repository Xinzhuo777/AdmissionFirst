/*
 * An authorization index is a PostgreSQL partial B-tree on the protected
 * heap. It is eligible only when its catalog predicate covers exactly the
 * rewritten policy at this occurrence. The original permissions, snapshot,
 * and native index maintenance then apply to each access.
 */
#include "postgres.h"

#include "access/htup_details.h"
#include "access/stratnum.h"
#include "catalog/pg_am_d.h"
#include "catalog/pg_class.h"
#include "catalog/pg_inherits.h"
#include "catalog/pg_namespace_d.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_opfamily_d.h"
#include "catalog/pg_type_d.h"
#include "miscadmin.h"
#include "optimizer/cost.h"
#include "optimizer/native_af.h"
#include "optimizer/native_af_partial.h"
#include "optimizer/optimizer.h"
#include "optimizer/pathnode.h"
#include "optimizer/paths.h"
#include "parser/parse_relation.h"
#include "parser/parsetree.h"
#include "utils/fmgroids.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"

static bool
integer_type(Oid type)
{
	return type == INT4OID || type == INT8OID;
}

static bool
local_column(Node *node, Index rti)
{
	Var		   *var;

	if (!IsA(node, Var))
		return false;
	var = (Var *) node;
	return var->varno == (int) rti && var->varlevelsup == 0 && var->varattno > 0 &&
		bms_is_empty(var->varnullingrels);
}

static bool
integer_literal(Node *node)
{
	Const	   *value;

	if (!IsA(node, Const))
		return false;
	value = (Const *) node;
	return integer_type(value->consttype) && !value->constisnull;
}

static Oid
builtin_binary_operator(OpExpr *op)
{
	HeapTuple	tuple;
	Form_pg_operator form;
	Oid			function = InvalidOid;

	if (op->opretset || list_length(op->args) != 2 ||
		OidIsValid(op->inputcollid) || OidIsValid(op->opcollid))
		return InvalidOid;
	tuple = SearchSysCache1(OPEROID, ObjectIdGetDatum(op->opno));
	if (!HeapTupleIsValid(tuple))
		return InvalidOid;
	form = (Form_pg_operator) GETSTRUCT(tuple);
	if (form->oprnamespace == PG_CATALOG_NAMESPACE)
		function = form->oprcode;
	ReleaseSysCache(tuple);
	return function;
}

static bool
integer_policy_value(Node *node, Index rti)
{
	OpExpr	   *op;
	Node	   *left;
	Const	   *right;
	Oid			function;

	if (local_column(node, rti))
		return integer_type(((Var *) node)->vartype);
	if (!IsA(node, OpExpr))
		return false;
	op = (OpExpr *) node;
	function = builtin_binary_operator(op);
	if (function != F_INT4MOD && function != F_INT8MOD)
		return false;
	left = linitial(op->args);
	if (!local_column(left, rti) ||
		!integer_type(((Var *) left)->vartype) ||
		!integer_literal(lsecond(op->args)))
		return false;
	right = lsecond_node(Const, op->args);
	return right->consttype == INT8OID ?
		DatumGetInt64(right->constvalue) != 0 :
		DatumGetInt32(right->constvalue) != 0;
}

static bool
local_policy_term(Node *node, Index rti)
{
	OpExpr	   *op;
	Oid			function;
	Node	   *left;
	Node	   *right;

	check_stack_depth();
	if (IsA(node, BoolExpr))
	{
		BoolExpr   *boolean = castNode(BoolExpr, node);
		ListCell   *lc;

		if ((boolean->boolop != AND_EXPR && boolean->boolop != OR_EXPR) ||
			boolean->args == NIL)
			return false;
		foreach(lc, boolean->args)
			if (!local_policy_term(lfirst(lc), rti))
				return false;
		return true;
	}
	if (!IsA(node, OpExpr))
		return false;
	op = (OpExpr *) node;
	function = builtin_binary_operator(op);
	if (op->opresulttype != BOOLOID ||
		(function != F_INT4EQ && function != F_INT8EQ &&
		 function != F_INT48EQ && function != F_INT84EQ))
		return false;
	left = linitial(op->args);
	right = lsecond(op->args);
	return (integer_policy_value(left, rti) && integer_literal(right)) ||
		(integer_literal(left) && integer_policy_value(right, rti));
}

/* Read the policy from this RTE after planner expression preprocessing. */
static List *
partial_policy(PlannerInfo *root, RelOptInfo *rel, RangeTblEntry *rte)
{
	Query	   *query = root->parse;
	RTEPermissionInfo *permissions;
	List	   *policy;
	ListCell   *lc;
	HeapTuple	tuple;
	Form_pg_class relation;
	bool		heap_rls;

	if (!query->hasRowSecurity ||
		(root->glob->parallelModeOK && !native_af_allow_serial_candidates()) ||
		rel->reloptkind != RELOPT_BASEREL ||
		!bms_is_empty(rel->lateral_relids) ||
		planner_rt_fetch(rel->relid, root) != rte ||
		rte->rtekind != RTE_RELATION || rte->relkind != RELKIND_RELATION ||
		rte->tablesample != NULL || rte->perminfoindex == 0 ||
		(rte->inh && has_subclass(rte->relid)) ||
		list_length(rte->securityQuals) != 1 ||
		linitial(rte->securityQuals) == NULL ||
		!IsA(linitial(rte->securityQuals), List))
		return NIL;
	if (!native_af_readonly_statement(root))
		return NIL;

	permissions = getRTEPermissionInfo(query->rteperminfos, rte);
	if (permissions->relid != rte->relid || permissions->requiredPerms != ACL_SELECT)
		return NIL;
	tuple = SearchSysCache1(RELOID, ObjectIdGetDatum(rte->relid));
	if (!HeapTupleIsValid(tuple))
		return NIL;
	relation = (Form_pg_class) GETSTRUCT(tuple);
	heap_rls = relation->relam == HEAP_TABLE_AM_OID && relation->relrowsecurity;
	ReleaseSysCache(tuple);
	if (!heap_rls)
		return NIL;

	policy = linitial(rte->securityQuals);
	foreach(lc, policy)
		if (!local_policy_term(lfirst(lc), rel->relid))
			return NIL;
	return policy;
}

static bool
admit_partial_index(RelOptInfo *rel, List *policy, IndexOptInfo *index)
{
	ListCell   *lc;
	int			i;

	if (index->rel != rel || index->relam != BTREE_AM_OID || index->unique ||
		index->hypothetical || !index->amhasgettuple || !index->amoptionalkey ||
		index->nkeycolumns < 1 || index->indexprs != NIL ||
		list_length(index->indpred) != list_length(policy))
		return false;
	for (i = 0; i < index->ncolumns; i++)
		if (index->indexkeys[i] <= 0)
			return false;
	for (i = 0; i < index->nkeycolumns; i++)
		if (index->opfamily[i] != INTEGER_BTREE_FAM_OID &&
			index->opfamily[i] != TEXT_BTREE_FAM_OID)
			return false;

	/*
	 * Catalog predicates and rewritten policy conjuncts use the same base
	 * RTE number. Compare both ways so neither a missing nor an extra
	 * predicate can authorize this artifact. Conjunct order is immaterial
	 * in this pure grammar.
	 */
	foreach(lc, policy)
		if (!list_member(index->indpred, lfirst(lc)))
			return false;
	foreach(lc, index->indpred)
		if (!list_member(policy, lfirst(lc)))
			return false;
	return true;
}

static List *
remaining_restrictions(RelOptInfo *rel, List *policy)
{
	List	   *restrictions = NIL;
	ListCell   *lc;

	foreach(lc, rel->baserestrictinfo)
	{
		RestrictInfo *rinfo = lfirst_node(RestrictInfo, lc);

		/* Keep every other restriction and its original security level. */
		if (rinfo->security_level != 0 || !list_member(policy, rinfo->clause))
			restrictions = lappend(restrictions, rinfo);
	}
	return restrictions;
}

static bool
point_key_operand(Node *node)
{
	if (IsA(node, Const))
		return !((Const *) node)->constisnull;
	return IsA(node, Param) && ((Param *) node)->paramkind == PARAM_EXTERN;
}

static bool
point_key(Node *node, IndexOptInfo *index)
{
	return local_column(node, index->rel->relid) &&
		((Var *) node)->varattno == index->indexkeys[0];
}

static bool
keyed_path(IndexPath *path)
{
	IndexOptInfo *index = path->indexinfo;
	ListCell   *lc;

	foreach(lc, path->indexclauses)
	{
		IndexClause *clause = lfirst_node(IndexClause, lc);
		OpExpr	   *op;
		Node	   *left;
		Node	   *right;

		if (clause->indexcol != 0 || clause->lossy ||
			!IsA(clause->rinfo->clause, OpExpr))
			continue;
		op = (OpExpr *) clause->rinfo->clause;
		if (list_length(op->args) != 2 ||
			get_op_opfamily_strategy(op->opno, index->opfamily[0]) !=
			BTEqualStrategyNumber)
			continue;
		left = linitial(op->args);
		right = lsecond(op->args);
		if ((point_key(left, index) && point_key_operand(right)) ||
			(point_key_operand(left) && point_key(right, index)))
			return true;
	}
	return false;
}

static NativeAfPartialPath *
partial_path(IndexPath *path, bool keyed)
{
	NativeAfPartialPath *candidate = palloc(sizeof(*candidate));

	candidate->path = path;
	candidate->keyed = keyed;
	candidate->index_oid = path->indexinfo->indexoid;
	return candidate;
}

List *
native_af_partial_paths(PlannerInfo *root, RelOptInfo *rel,
						RangeTblEntry *rte, List *private_indexes,
						bool prefer_first_family)
{
	List	   *policy;
	List	   *restrictions;
	List	   *paths = NIL;
	ListCell   *lc;

	if (private_indexes == NIL || !enable_indexscan)
		return NIL;
	policy = partial_policy(root, rel, rte);
	if (policy == NIL)
		return NIL;
	restrictions = remaining_restrictions(rel, policy);

	foreach(lc, private_indexes)
	{
		IndexOptInfo *original = lfirst_node(IndexOptInfo, lc);
		IndexOptInfo *index;
		RelOptInfo *alternate;
		ListCell   *lp;
		bool		have_enum = false;
		bool		have_key = false;

		if (!admit_partial_index(rel, policy, original))
			continue;

		/*
		 * Only the admitted artifact goes through native index costing.
		 * Keep the original relation and restrictions intact for other
		 * paths. The alternate represents the same RTE and same target.
		 */
		alternate = palloc(sizeof(*alternate));
		memcpy(alternate, rel, sizeof(*alternate));
		index = palloc(sizeof(*index));
		memcpy(index, original, sizeof(*index));
		index->rel = alternate;
		index->predOK = true;
		index->indrestrictinfo = restrictions;
		/*
		 * The published artifact paths are plain index scans. A bitmap heap
		 * path would be discarded after native generation, so do not let it
		 * eliminate an available keyed scan in the private pathlist.
		 */
		index->amhasgetbitmap = false;
		alternate->indexlist = list_make1(index);
		alternate->pathlist = NIL;
		alternate->partial_pathlist = NIL;
		alternate->consider_parallel = false;
		alternate->has_eclass_joins = false;
		alternate->joininfo = NIL;
		create_index_paths(root, alternate);

		foreach(lp, alternate->pathlist)
		{
			Path	   *path = lfirst(lp);
			IndexPath  *scan;
			bool		keyed;

			if (!IsA(path, IndexPath) || path->param_info != NULL)
				continue;
			scan = (IndexPath *) path;
			keyed = keyed_path(scan);
			paths = lappend(paths, partial_path(scan, keyed));
			have_enum |= !keyed;
			have_key |= keyed;
		}

		/* Native generation normally folds a point key into every scan. */
		if (!have_enum && !(prefer_first_family && have_key))
		{
			IndexPath  *scan;

			scan = create_index_path(root, index, NIL, NIL, NIL, NIL,
									 ForwardScanDirection, false, NULL, 1.0, false);
			paths = lappend(paths, partial_path(scan, false));
		}
	}
	return paths;
}
