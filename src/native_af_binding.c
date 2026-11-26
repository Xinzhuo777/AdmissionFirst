/*-------------------------------------------------------------------------
 *
 * native_af_binding.c
 *	  Run-time binding checks for a fresh membership key array.
 *
 *
 * All checks inspect native plan state or catalog metadata. The caller invokes
 * this before evaluating the array InitPlan or fetching from either branch,
 * and selects its exact native fallback when a check returns false.
 */
#include "postgres.h"

#include "access/htup_details.h"
#include "catalog/pg_am_d.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_index.h"
#include "catalog/pg_namespace_d.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_type_d.h"
#include "nodes/nodeFuncs.h"
#include "nodes/extensible.h"
#include "optimizer/native_af_binding.h"
#include "parser/parse_relation.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"

/* Catalog checks also reject a dropped or no-longer-usable index. */
static bool
index_belongs_to_heap(Oid index_oid, Oid heap_oid, AttrNumber key_attribute)
{
	HeapTuple	tuple;
	Form_pg_index index;
	Form_pg_class relation;
	bool		valid;

	tuple = SearchSysCache1(INDEXRELID, ObjectIdGetDatum(index_oid));
	if (!HeapTupleIsValid(tuple))
		return false;
	index = (Form_pg_index) GETSTRUCT(tuple);
	valid = index->indrelid == heap_oid && index->indisvalid &&
		index->indisready && index->indislive;
	if (valid && key_attribute > 0)
		valid = index->indisunique && index->indimmediate &&
			index->indnkeyatts == 1 && index->indkey.values[0] == key_attribute &&
			heap_attisnull(tuple, Anum_pg_index_indexprs, NULL) &&
			heap_attisnull(tuple, Anum_pg_index_indpred, NULL);
	ReleaseSysCache(tuple);
	if (!valid)
		return false;

	tuple = SearchSysCache1(RELOID, ObjectIdGetDatum(index_oid));
	if (!HeapTupleIsValid(tuple))
		return false;
	relation = (Form_pg_class) GETSTRUCT(tuple);
	valid = relation->relkind == RELKIND_INDEX;
	if (valid && key_attribute > 0)
		valid = relation->relam == BTREE_AM_OID;
	ReleaseSysCache(tuple);
	return valid;
}

static bool
bigint_attribute(Oid heap_oid, AttrNumber attribute)
{
	HeapTuple	tuple;
	Form_pg_attribute column;
	bool		valid;

	tuple = SearchSysCache2(ATTNUM, ObjectIdGetDatum(heap_oid),
							Int16GetDatum(attribute));
	if (!HeapTupleIsValid(tuple))
		return false;
	column = (Form_pg_attribute) GETSTRUCT(tuple);
	valid = !column->attisdropped && column->atttypid == INT8OID;
	ReleaseSysCache(tuple);
	return valid;
}

static RangeTblEntry *
bound_relation(PlannedStmt *statement, Index rti)
{
	RangeTblEntry *rte;

	if (rti == 0 || rti > (Index) list_length(statement->rtable))
		return NULL;
	rte = list_nth_node(RangeTblEntry, statement->rtable, rti - 1);
	return rte->rtekind == RTE_RELATION ? rte : NULL;
}

static bool
bigint_equality(Oid operator_oid)
{
	HeapTuple	tuple;
	Form_pg_operator operation;
	bool		valid;

	tuple = SearchSysCache1(OPEROID, ObjectIdGetDatum(operator_oid));
	if (!HeapTupleIsValid(tuple))
		return false;
	operation = (Form_pg_operator) GETSTRUCT(tuple);
	valid = operation->oprnamespace == PG_CATALOG_NAMESPACE &&
		operation->oprcode == F_INT8EQ;
	ReleaseSysCache(tuple);
	return valid;
}

static bool
bigint_output(Node *expression)
{
	if (IsA(expression, Var))
		return castNode(Var, expression)->vartype == INT8OID;
	if (IsA(expression, Const))
		return castNode(Const, expression)->consttype == INT8OID;
	if (IsA(expression, Param))
		return castNode(Param, expression)->paramtype == INT8OID;
	return false;
}

/* Match both the physical index key and the original protected column. */
static bool
array_qualification(List *qualifications, Index varno, AttrNumber attribute,
					int param_id)
{
	ListCell   *cell;

	foreach(cell, qualifications)
	{
		ScalarArrayOpExpr *expression;
		Var		   *key;
		Param	   *parameter;

		if (!IsA(lfirst(cell), ScalarArrayOpExpr))
			continue;
		expression = lfirst_node(ScalarArrayOpExpr, cell);
		if (!expression->useOr || expression->opfuncid != F_INT8EQ ||
			expression->hashfuncid != InvalidOid || !bigint_equality(expression->opno) ||
			list_length(expression->args) != 2 ||
			!IsA(linitial(expression->args), Var) ||
			!IsA(lsecond(expression->args), Param))
			continue;
		key = linitial_node(Var, expression->args);
		parameter = lsecond_node(Param, expression->args);
		if (key->varno == (int) varno && key->varattno == attribute &&
			key->vartype == INT8OID && key->varlevelsup == 0 &&
			bms_is_empty(key->varnullingrels) &&
			parameter->paramkind == PARAM_EXEC &&
			parameter->paramtype == INT8ARRAYOID && parameter->paramid == param_id)
			return true;
	}
	return false;
}

static bool
index_output_binding(IndexOnlyScan *scan, Index expected_rti,
					 AttrNumber expected_attribute)
{
	ListCell   *cell;

	foreach(cell, scan->indextlist)
	{
		TargetEntry *entry = lfirst_node(TargetEntry, cell);
		Var		   *key;

		if (entry->resno != 1 || entry->resjunk || !IsA(entry->expr, Var))
			continue;
		key = castNode(Var, entry->expr);
		return key->varno == (int) expected_rti &&
			key->varattno == expected_attribute && key->vartype == INT8OID &&
			key->varlevelsup == 0 && bms_is_empty(key->varnullingrels);
	}
	return false;
}

static bool
protected_index_binding(Plan *child, Index expected_rti, Oid expected_index,
						AttrNumber expected_attribute, int param_id)
{
	if (IsA(child, IndexScan))
	{
		IndexScan  *scan = castNode(IndexScan, child);

		return scan->scan.scanrelid == expected_rti && scan->indexid == expected_index &&
			array_qualification(scan->indexqual, INDEX_VAR, 1, param_id) &&
			array_qualification(scan->indexqualorig, expected_rti,
								expected_attribute, param_id);
	}
	if (IsA(child, IndexOnlyScan))
	{
		IndexOnlyScan *scan = castNode(IndexOnlyScan, child);

		return scan->scan.scanrelid == expected_rti && scan->indexid == expected_index &&
			array_qualification(scan->indexqual, INDEX_VAR, 1, param_id) &&
			index_output_binding(scan, expected_rti, expected_attribute);
	}
	return false;
}

typedef struct SourceBinding
{
	EState	   *estate;
	List	   *relation_oids;
	bool		uses_current_user;
} SourceBinding;

static bool
direct_principal_permissions(PlannedStmt *statement, RangeTblEntry *rte)
{
	RTEPermissionInfo *permissions;

	if (rte->perminfoindex == 0 ||
		rte->perminfoindex > list_length(statement->permInfos))
		return false;
	permissions = getRTEPermissionInfo(statement->permInfos, rte);
	return permissions->relid == rte->relid &&
		permissions->requiredPerms == ACL_SELECT &&
		!OidIsValid(permissions->checkAsUser);
}

static bool
source_relation_binding(Scan *scan, Oid index_oid, SourceBinding *binding)
{
	RangeTblEntry *rte = bound_relation(binding->estate->es_plannedstmt,
										scan->scanrelid);

	if (rte == NULL || !list_member_oid(binding->relation_oids, rte->relid))
		return false;
	if (binding->uses_current_user &&
		!direct_principal_permissions(binding->estate->es_plannedstmt, rte))
		return false;
	return !OidIsValid(index_oid) || index_belongs_to_heap(index_oid, rte->relid, 0);
}

/* A true walker result denotes a failed binding and stops the traversal. */
static bool
source_state_mismatch(PlanState *state, SourceBinding *binding)
{
	Plan	   *plan = state->plan;
	bool		valid;

	if (state->state != binding->estate || plan == NULL ||
		state->initPlan != NIL || state->subPlan != NIL)
		return true;

	switch (nodeTag(plan))
	{
		case T_SeqScan:
		case T_BitmapHeapScan:
		case T_TidScan:
		case T_TidRangeScan:
			valid = source_relation_binding((Scan *) plan, InvalidOid, binding);
			break;
		case T_IndexScan:
			valid = source_relation_binding((Scan *) plan,
											castNode(IndexScan, plan)->indexid, binding);
			break;
		case T_IndexOnlyScan:
			valid = source_relation_binding((Scan *) plan,
											castNode(IndexOnlyScan, plan)->indexid, binding);
			break;
		case T_BitmapIndexScan:
			valid = source_relation_binding((Scan *) plan,
											castNode(BitmapIndexScan, plan)->indexid, binding);
			break;
		case T_Result:
		case T_Append:
		case T_MergeAppend:
		case T_BitmapAnd:
		case T_BitmapOr:
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
			valid = true;
			break;
		default:
			/* The admitted ACL grammar has no other relation-producing node. */
			valid = false;
			break;
	}
	if (!valid)
		return true;
	return planstate_tree_walker(state, source_state_mismatch, binding);
}

/* Callers separately bind the actual SubPlanState, identity and parameters. */
bool
native_af_policy_source_binding(EState *estate, PlanState *source_state,
								List *source_relation_oids)
{
	SourceBinding binding = {0};

	if (estate == NULL || estate->es_plannedstmt == NULL || source_state == NULL ||
		source_state->state != estate || source_relation_oids == NIL ||
		!IsA(source_relation_oids, OidList))
		return false;
	binding.estate = estate;
	binding.relation_oids = source_relation_oids;
	binding.uses_current_user = true;
	return !source_state_mismatch(source_state, &binding);
}

bool
native_af_member_binding(EState *estate, Plan *index_child,
						 Index expected_rti, Oid expected_heap,
						 Oid expected_index, AttrNumber expected_attribute,
						 int param_id, int source_plan_id,
						 List *source_relation_oids, bool uses_current_user)
{
	PlannedStmt *statement;
	RangeTblEntry *protected_rte;
	ParamExecData *parameter;
	SubPlanState *source;
	SubPlan    *subplan;
	Plan	   *source_plan;
	PlanState  *source_state;
	TargetEntry *first_column;
	SourceBinding binding = {0};

	if (estate == NULL || index_child == NULL || estate->es_plannedstmt == NULL ||
		estate->es_param_exec_vals == NULL || !OidIsValid(expected_heap) ||
		!OidIsValid(expected_index) || expected_attribute <= 0 || param_id < 0 ||
		source_plan_id <= 0 || source_relation_oids == NIL ||
		!IsA(source_relation_oids, OidList))
		return false;
	statement = estate->es_plannedstmt;
	if (param_id >= list_length(statement->paramExecTypes) ||
		list_nth_oid(statement->paramExecTypes, param_id) != INT8ARRAYOID ||
		source_plan_id > list_length(statement->subplans) ||
		source_plan_id > list_length(estate->es_subplanstates))
		return false;
	protected_rte = bound_relation(statement, expected_rti);
	if (protected_rte == NULL || protected_rte->relid != expected_heap ||
		(uses_current_user &&
		 !direct_principal_permissions(statement, protected_rte)) ||
		!bigint_attribute(expected_heap, expected_attribute) ||
		!index_belongs_to_heap(expected_index, expected_heap, expected_attribute) ||
		!protected_index_binding(index_child, expected_rti, expected_index,
								 expected_attribute, param_id))
		return false;

	parameter = &estate->es_param_exec_vals[param_id];
	if (parameter->execPlan == NULL || !IsA(parameter->execPlan, SubPlanState))
		return false;
	source = castNode(SubPlanState, parameter->execPlan);
	subplan = source->subplan;
	source_plan = (Plan *) list_nth(statement->subplans, source_plan_id - 1);
	source_state = (PlanState *) list_nth(estate->es_subplanstates, source_plan_id - 1);
	if (subplan == NULL || source_plan == NULL || source_state == NULL ||
		subplan->subLinkType != ARRAY_SUBLINK || subplan->plan_id != source_plan_id ||
		subplan->firstColType != INT8OID || subplan->testexpr != NULL ||
		subplan->parParam != NIL || subplan->args != NIL ||
		subplan->useHashTable || !IsA(subplan->setParam, IntList) ||
		list_length(subplan->setParam) != 1 ||
		linitial_int(subplan->setParam) != param_id ||
		source->planstate != source_state || source_state->plan != source_plan ||
		source->parent == NULL || source->parent->state != estate ||
		source_plan->targetlist == NIL)
		return false;
	if (!IsA(linitial(source_plan->targetlist), TargetEntry))
		return false;
	first_column = linitial_node(TargetEntry, source_plan->targetlist);
	if (first_column->resjunk || first_column->resno != 1 ||
		!bigint_output((Node *) first_column->expr))
		return false;

	binding.estate = estate;
	binding.relation_oids = source_relation_oids;
	binding.uses_current_user = uses_current_user;
	return !source_state_mismatch(source_state, &binding);
}

/* A copied input slot must still identify the original protected heap key. */
static bool
hash_policy_key(Node *expression, Plan *child, Index rti, AttrNumber attribute)
{
	Var		   *key;

	if (!IsA(expression, Var))
		return false;
	key = castNode(Var, expression);
	if (key->vartype != INT8OID || key->varlevelsup != 0)
		return false;
	if (key->varno == rti && key->varattno == attribute)
		return true;
	if (child != NULL && IsA(child, IndexOnlyScan) && key->varno == INDEX_VAR &&
		key->varattno > 0 &&
		key->varattno <= list_length(castNode(IndexOnlyScan, child)->indextlist))
	{
		TargetEntry *entry = list_nth_node(TargetEntry,
										   castNode(IndexOnlyScan, child)->indextlist, key->varattno - 1);

		return hash_policy_key((Node *) entry->expr, NULL, rti, attribute);
	}
	if (child != NULL && IsA(child, CustomScan) && key->varno == INDEX_VAR &&
		key->varattno > 0 &&
		key->varattno <= list_length(castNode(CustomScan, child)->custom_scan_tlist))
	{
		TargetEntry *entry = list_nth_node(TargetEntry,
										   castNode(CustomScan, child)->custom_scan_tlist, key->varattno - 1);

		return !entry->resjunk &&
			hash_policy_key((Node *) entry->expr, NULL, rti, attribute);
	}
	return false;
}

bool
native_af_hash_policy_binding(EState *estate, PlanState *child,
							  Index expected_rti, Oid expected_heap,
							  AttrNumber expected_attribute, int source_plan_id,
							  List *source_relation_oids)
{
	PlannedStmt *statement;
	RangeTblEntry *protected_rte;
	SubPlanState *source = NULL;
	SubPlan    *subplan = NULL;
	Plan	   *source_plan;
	PlanState  *source_state;
	ListCell   *cell;
	OpExpr	   *test;
	Node	   *key;
	Node	   *parameter;
	Param	   *output;
	SourceBinding binding = {0};

	if (estate == NULL || child == NULL || child->state != estate ||
		estate->es_plannedstmt == NULL || source_plan_id <= 0 ||
		source_relation_oids == NIL || !IsA(source_relation_oids, OidList) ||
		(!IsA(child->plan, SeqScan) && !IsA(child->plan, IndexScan) &&
		 !IsA(child->plan, IndexOnlyScan) && !IsA(child->plan, BitmapHeapScan) &&
		 (!IsA(child->plan, CustomScan) ||
		  castNode(CustomScan, child->plan)->methods == NULL ||
		  castNode(CustomScan, child->plan)->methods->CustomName == NULL ||
		  strcmp(castNode(CustomScan, child->plan)->methods->CustomName,
				 "AF Prefix Guard") != 0)) ||
		((Scan *) child->plan)->scanrelid != expected_rti)
		return false;
	statement = estate->es_plannedstmt;
	protected_rte = bound_relation(statement, expected_rti);
	if (protected_rte == NULL || protected_rte->relid != expected_heap ||
		!direct_principal_permissions(statement, protected_rte) ||
		!bigint_attribute(expected_heap, expected_attribute) ||
		source_plan_id > list_length(statement->subplans) ||
		source_plan_id > list_length(estate->es_subplanstates))
		return false;

	/*
	 * The ordinary scan / Prefix Guard ExecScan executes this actual qual.
	 * custom_exprs are proof copies and are deliberately not the owner here.
	 */
	foreach(cell, child->plan->qual)
		if (IsA(lfirst(cell), SubPlan) &&
			lfirst_node(SubPlan, cell)->plan_id == source_plan_id)
	{
		if (subplan != NULL)
			return false;
		subplan = lfirst_node(SubPlan, cell);
	}
	if (subplan == NULL || subplan->subLinkType != ANY_SUBLINK ||
		!subplan->useHashTable || subplan->firstColType != INT8OID ||
		subplan->parParam != NIL || subplan->args != NIL ||
		subplan->setParam != NIL || list_length(subplan->paramIds) != 1 ||
		!IsA(subplan->testexpr, OpExpr))
		return false;
	test = castNode(OpExpr, subplan->testexpr);
	if (!bigint_equality(test->opno) || test->opretset ||
		test->opresulttype != BOOLOID || list_length(test->args) != 2)
		return false;
	key = linitial(test->args);
	parameter = lsecond(test->args);
	if (IsA(key, Param))
	{
		key = lsecond(test->args);
		parameter = linitial(test->args);
	}
	if (!hash_policy_key(key, child->plan, expected_rti, expected_attribute) ||
		!IsA(parameter, Param))
		return false;
	output = castNode(Param, parameter);
	if (output->paramkind != PARAM_EXEC || output->paramtype != INT8OID ||
		output->paramid != linitial_int(subplan->paramIds) ||
		output->paramid < 0 ||
		output->paramid >= list_length(statement->paramExecTypes) ||
		list_nth_oid(statement->paramExecTypes, output->paramid) != INT8OID)
		return false;
	foreach(cell, child->subPlan)
		if (IsA(lfirst(cell), SubPlanState) &&
			lfirst_node(SubPlanState, cell)->subplan == subplan)
	{
		if (source != NULL)
			return false;
		source = lfirst_node(SubPlanState, cell);
	}
	source_plan = (Plan *) list_nth(statement->subplans, source_plan_id - 1);
	source_state = (PlanState *) list_nth(estate->es_subplanstates, source_plan_id - 1);
	if (source == NULL || source_plan == NULL || source_state == NULL ||
		source->parent != child || source->planstate != source_state ||
		source_state->plan != source_plan || source_plan->targetlist == NIL ||
		!IsA(linitial(source_plan->targetlist), TargetEntry) ||
		linitial_node(TargetEntry, source_plan->targetlist)->resjunk ||
		!bigint_output((Node *) linitial_node(TargetEntry, source_plan->targetlist)->expr))
		return false;
	binding.estate = estate;
	binding.relation_oids = source_relation_oids;
	/* Completed hash is scoped to the same direct caller at all sources. */
	binding.uses_current_user = true;
	return !source_state_mismatch(source_state, &binding);
}
