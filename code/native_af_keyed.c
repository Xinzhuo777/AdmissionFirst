/*
 * Exact query-key restriction for a fresh membership key set.
 *
 * For rows satisfying the original base qualification id = value, the
 * admitted array of authorized IDs and its subset restricted to value give
 * the same authorization answer. The caller retains that base qualification.
 */
#include "postgres.h"

#include "catalog/pg_type_d.h"
#include "nodes/makefuncs.h"
#include "optimizer/native_af_keyed.h"
#include "utils/fmgroids.h"
#include "utils/lsyscache.h"

static bool
bound_key(const Node *node, const Var *key)
{
	const Var  *var;

	if (!IsA(node, Var))
		return false;
	var = castNode(Var, node);
	return var->varno == key->varno && var->varattno == key->varattno &&
		var->varattno > 0 && var->varlevelsup == 0 && var->vartype == INT8OID &&
		bms_is_empty(var->varnullingrels);
}

static const Expr *
query_value(const RestrictInfo *qual, Relids relids, const Var *key, Oid equality)
{
	const OpExpr *op;
	const Node *value;

	if (qual->pseudoconstant || qual->outer_relids != NULL ||
		qual->has_clone || qual->is_clone ||
		!bms_equal(qual->clause_relids, relids) ||
		!bms_equal(qual->required_relids, relids) ||
		!IsA(qual->clause, OpExpr))
		return NULL;
	op = castNode(OpExpr, qual->clause);
	if (op->opno != equality || op->opretset || op->opresulttype != BOOLOID ||
		list_length(op->args) != 2)
		return NULL;
	if (bound_key(linitial(op->args), key))
		value = lsecond(op->args);
	else if (bound_key(lsecond(op->args), key))
		value = linitial(op->args);
	else
		return NULL;

	if (IsA(value, Const))
	{
		const Const *constant = castNode(Const, value);

		if (constant->consttype == INT8OID && !constant->constisnull)
			return (const Expr *) constant;
	}
	else if (IsA(value, Param))
	{
		const Param *parameter = castNode(Param, value);

		if (parameter->paramkind == PARAM_EXTERN && parameter->paramtype == INT8OID &&
			parameter->paramid > 0)
			return (const Expr *) parameter;
	}
	return NULL;
}

SubLink *
native_af_keyed_sublink(RelOptInfo *rel, const Var *key, Oid equality,
					   const SubLink *enumeration, const RestrictInfo *policy)
{
	const Query *source;
	const TargetEntry *entry;
	const Var  *acl_key;
	const Expr *value = NULL;
	ListCell   *cell;
	SubLink    *result;
	Query	   *acl;
	Expr	   *filter;

	if (rel->reloptkind != RELOPT_BASEREL || key->varno != rel->relid ||
		!bound_key((const Node *) key, key) || get_opcode(equality) != F_INT8EQ ||
		!get_func_leakproof(F_INT8EQ) || enumeration->subLinkType != ARRAY_SUBLINK ||
		enumeration->testexpr != NULL || !IsA(enumeration->subselect, Query) ||
		!list_member_ptr(rel->baserestrictinfo, policy))
		return NULL;
	source = castNode(Query, enumeration->subselect);
	if (source->jointree == NULL || list_length(source->targetList) != 1)
		return NULL;
	entry = linitial_node(TargetEntry, source->targetList);
	if (entry->resjunk || !IsA(entry->expr, Var))
		return NULL;
	acl_key = castNode(Var, entry->expr);
	if (!bound_key((const Node *) acl_key, acl_key))
		return NULL;

	foreach(cell, rel->baserestrictinfo)
	{
		const RestrictInfo *qual = lfirst_node(RestrictInfo, cell);

		if (qual == policy)
			continue;
		value = query_value(qual, rel->relids, key, equality);
		if (value != NULL)
			break;
	}
	if (value == NULL)
		return NULL;

	result = (SubLink *) copyObject(enumeration);
	acl = castNode(Query, result->subselect);
	acl_key = castNode(Var, linitial_node(TargetEntry, acl->targetList)->expr);
	filter = make_opclause(equality, BOOLOID, false, (Expr *) copyObject(acl_key),
						   (Expr *) copyObject(value), InvalidOid, InvalidOid);
	acl->jointree->quals = make_and_qual(acl->jointree->quals, (Node *) filter);
	return result;
}
