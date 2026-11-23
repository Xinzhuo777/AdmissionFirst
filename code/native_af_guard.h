/* Bounded built-in prefix candidates with an actual pending exact policy. */
#ifndef NATIVE_AF_GUARD_H
#define NATIVE_AF_GUARD_H

#include "nodes/pathnodes.h"

extern void native_af_guard_initialize(void);
/* AF only. Ordinary paths remain visible. closed_policy is the core admitted
 * closed-ACL exact check, or NULL: only the former permits the finite SP test. */
extern List *native_af_guard_paths(PlannerInfo *root, RelOptInfo *rel,
								 RangeTblEntry *rte, RestrictInfo *closed_policy,
								 RestrictInfo *completed_hash_policy);

#endif
