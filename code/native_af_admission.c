/* Independently close the requirement of a checked single-occurrence scan. */
#include "postgres.h"

#include "access/sysattr.h"
#include "miscadmin.h"
#include "nodes/nodeFuncs.h"
#include "optimizer/clauses.h"
#include "optimizer/native_af_admission.h"
#include "parser/parse_relation.h"
#include "parser/parsetree.h"
#include "utils/snapmgr.h"

typedef struct NativeAfColumnUse
{
	Index occurrence;
	Bitmapset *columns;
} NativeAfColumnUse;

static bool
column_use(Node *node, void *context)
{
	NativeAfColumnUse *use = context;

	if (node == NULL)
		return false;
	if (IsA(node, Var))
	{
		Var *var = castNode(Var, node);

		if (var->varno != use->occurrence || var->varlevelsup != 0 ||
			!bms_is_empty(var->varnullingrels) || var->varattno == 0 ||
			(var->varattno < 0 && var->varattno != SelfItemPointerAttributeNumber))
			return true;
		use->columns = bms_add_member(use->columns,
									 var->varattno - FirstLowInvalidHeapAttributeNumber);
		return false;
	}
	return expression_tree_walker(node, column_use, context);
}

/* Only a bare Var supplies a row value to the pending check. References
 * inside a computed projection cannot substitute for that value. */
static Bitmapset *
scan_carriers(Index occurrence, PathTarget *target)
{
	NativeAfColumnUse use = {occurrence, NULL};
	ListCell *cell;

	foreach(cell, target->exprs)
	{
		Node *expression = lfirst(cell);

		if (IsA(expression, Var))
			column_use(expression, &use);
	}
	return use.columns;
}

bool
native_af_scan_requirement(PlannerInfo *root, RelOptInfo *rel,
						   RangeTblEntry *rte, NativeAfScanRequirement *need)
{
	NativeAfColumnUse output = {rel->relid, NULL};
	RTEPermissionInfo *permission;

	if (rel->relid == 0 || rel->reloptkind != RELOPT_BASEREL ||
		rte->rtekind != RTE_RELATION || planner_rt_fetch(rel->relid, root) != rte ||
		rte->perminfoindex == 0 || list_length(rte->securityQuals) != 1 ||
		!IsA(linitial(rte->securityQuals), List) ||
		list_length(linitial(rte->securityQuals)) != 1 ||
		column_use((Node *) rel->reltarget->exprs, &output))
		return false;
	permission = getRTEPermissionInfo(root->parse->rteperminfos, rte);
	if (permission->relid != rte->relid || (permission->requiredPerms & ACL_SELECT) == 0)
		return false;
	*need = (NativeAfScanRequirement) {
		.planner = root,
		.relation = rte,
		.permission = permission,
		.occurrence = rel->relid,
		.query_role = GetUserId(),
		.principal = OidIsValid(permission->checkAsUser) ? permission->checkAsUser : GetUserId(),
		.snapshot = ActiveSnapshotSet() ? GetActiveSnapshot() : NULL,
		.policy = linitial(linitial(rte->securityQuals)),
		.target = rel->reltarget,
		.restrictions = rel->baserestrictinfo,
		.output_columns = output.columns
	};
	return true;
}

static bool
binding_current(const NativeAfScanRequirement *need)
{
	RangeTblEntry *rte = planner_rt_fetch(need->occurrence, need->planner);
	RTEPermissionInfo *permission;

	if (rte != need->relation || rte->perminfoindex == 0 ||
		need->query_role != GetUserId() || list_length(rte->securityQuals) != 1 ||
		!IsA(linitial(rte->securityQuals), List) ||
		list_length(linitial(rte->securityQuals)) != 1)
		return false;
	permission = getRTEPermissionInfo(need->planner->parse->rteperminfos, rte);
	return permission == need->permission &&
		permission->relid == rte->relid &&
		need->principal == (OidIsValid(permission->checkAsUser) ? permission->checkAsUser : GetUserId()) &&
		need->snapshot == (ActiveSnapshotSet() ? GetActiveSnapshot() : NULL) &&
		need->policy == linitial(linitial(rte->securityQuals));
}

/* A one-arm policy has already passed the provider's PG-arm proof. Rebind
 * the witness to the active policy rather than treating it as a new policy. */
static bool
same_exact_check(Node *original, Node *selected)
{
	if (equal(original, selected))
		return true;
	if (IsA(original, AlternativeSubPlan) && IsA(selected, AlternativeSubPlan))
	{
		List *arms = castNode(AlternativeSubPlan, selected)->subplans;

		return list_length(arms) == 1 &&
			list_member(castNode(AlternativeSubPlan, original)->subplans, linitial(arms));
	}
	return false;
}

/* A slot must supply both the target and the active obligation regardless of
 * what the provider happens to report. All obligations in this fragment
 * remain live up to the scan boundary. */
static const char *
scan_root(const NativeAfScanRequirement *need, const NativeAfScanDelivery *state)
{
	if (state->binding != need || !binding_current(need))
		return "active_occurrence_binding_mismatch";
	if (!state->covers_target ||
		!bms_is_subset(need->output_columns, state->carriers) ||
		!equal(state->output->exprs, need->target->exprs))
		return "requested_target_not_delivered";
	if (state->pending != NULL || !state->exact)
		return "root_requires_exact_policy";
	return NULL;
}

const char *
native_af_admit_checked_scan(const NativeAfScanRequirement *need,
							 const NativeAfScanRule *rule, NativeAfScanDelivery *out)
{
	NativeAfColumnUse checks = {need->occurrence, NULL};
	NativeAfColumnUse early = {need->occurrence, NULL};
	NativeAfColumnUse later = {need->occurrence, NULL};
	Bitmapset *carriers = scan_carriers(need->occurrence, rule->input);
	ListCell *cell;
	bool target_required = false;

	*out = (NativeAfScanDelivery) {
		.binding = need,
		.input = rule->input,
		.output = rule->output,
		.target_filter = rule->target_filter,
		.prefix = rule->validated_prefix,
		.carriers = carriers,
		.identity = rule->identity,
		.pending = need->policy
	};
	foreach(cell, need->restrictions)
	{
		RestrictInfo *restriction = lfirst_node(RestrictInfo, cell);

		if ((Node *) restriction->clause == rule->target_filter ||
			equal(restriction->clause, rule->target_filter))
		{
			target_required = true;
			break;
		}
	}
	if (!target_required)
		return "target_filter_not_required_at_slot";
	if (rule->exact_check == NULL || !same_exact_check(need->policy, rule->exact_check))
		return "exact_policy_binding_mismatch";
	if (column_use(rule->exact_check, &checks) ||
		!bms_is_subset(checks.columns, carriers) ||
		(rule->identity != 0 &&
		 !bms_is_member(rule->identity - FirstLowInvalidHeapAttributeNumber, carriers)))
		return "pending_check_input_or_carrier_missing";
	out->check_inputs = checks.columns;
	foreach(cell, rule->before_check)
	{
		Node *expression = lfirst(cell);

		if (contain_leaked_vars(expression))
			return "protected_read_before_exact_policy";
	}
	if (column_use((Node *) rule->before_check, &early) ||
		(rule->validated_prefix != NIL && !bms_is_subset(early.columns, carriers)))
		return "early_filter_input_missing";
	if (column_use((Node *) rule->after_check, &later) ||
		!bms_is_subset(later.columns, carriers))
		return "post_policy_input_missing";

	if (rule->validated_prefix != NIL)
		out->covers_target = equal(rule->validated_prefix, rule->before_check) &&
			list_member(rule->after_check, rule->target_filter);
	else
		out->covers_target = list_length(rule->before_check) == 1 &&
			equal(linitial(rule->before_check), rule->target_filter);
	out->pending = NULL;
	out->exact = true;
	return scan_root(need, out);
}

/* Both admitted roots must meet the same reachable requirement. Index and
 * heap alternatives may use different physical providers under this binding.
 * Callers still compare order, enforcers and complete comparable costs. */
const char *
native_af_scan_preserves(const NativeAfScanDelivery *better,
						 const NativeAfScanDelivery *worse, bool need_identity)
{
	if (better->binding != worse->binding ||
		scan_root(better->binding, better) != NULL ||
		scan_root(worse->binding, worse) != NULL ||
		!equal(better->target_filter, worse->target_filter) ||
		!equal(better->prefix, worse->prefix) ||
		!bms_equal(better->check_inputs, worse->check_inputs))
		return "authorization_or_target_mismatch";
	if (!equal(better->output->exprs, worse->output->exprs) ||
		!equal(better->input->exprs, worse->input->exprs) ||
		(need_identity && (better->identity == 0 || better->identity != worse->identity)))
		return "required_policy_inputs_or_carrier_mismatch";
	return NULL;
}
