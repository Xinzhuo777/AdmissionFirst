/* Validate the lowered membership access before its first tuple request. */
#ifndef NATIVE_AF_BINDING_H
#define NATIVE_AF_BINDING_H

#include "nodes/execnodes.h"

/* source_relation_oids is an OidList from the admitted ACL Query. */
extern bool native_af_member_binding(EState *estate, Plan *index_child,
									 Index expected_rti, Oid expected_heap,
									 Oid expected_index, AttrNumber expected_attribute,
									 int param_id, int source_plan_id,
									 List *source_relation_oids,
									 bool uses_current_user);

extern bool native_af_hash_policy_binding(EState *estate, PlanState *child,
										  Index expected_rti, Oid expected_heap,
										  AttrNumber expected_attribute,
										  int source_plan_id,
										  List *source_relation_oids);

/* The owner must bind the actual source SubPlanState and parameter contract. */
extern bool native_af_policy_source_binding(EState *estate,
											PlanState *source_state,
											List *source_relation_oids);

#endif
