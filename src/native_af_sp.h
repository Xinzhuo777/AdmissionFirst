/* Selection/projection replacement for admitted native exact-policy paths. */
#ifndef NATIVE_AF_SP_H
#define NATIVE_AF_SP_H

#include "commands/explain.h"
#include "nodes/pathnodes.h"

extern List *native_af_sp_exact_paths(PlannerInfo *root, RelOptInfo *rel,
									  RangeTblEntry *rte, RestrictInfo *checked_policy,
									  Var *key, List **evidence);
extern void native_af_sp_explain(List *evidence, ExplainState *es);

#endif
