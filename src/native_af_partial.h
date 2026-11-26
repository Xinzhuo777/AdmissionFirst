/* AF Policy Index paths over authorization partial indexes (native_af_partial.c). */
#ifndef NATIVE_AF_PARTIAL_H
#define NATIVE_AF_PARTIAL_H

#include "nodes/pathnodes.h"

/* Planner-only descriptor; the executor binding uses the index OID. */
typedef struct NativeAfPartialPath
{
	IndexPath  *path;
	bool		keyed;
	Oid			index_oid;
} NativeAfPartialPath;

extern List *native_af_partial_paths(PlannerInfo *root, RelOptInfo *rel,
									 RangeTblEntry *rte, List *private_indexes,
									 bool prefer_first_family);

#endif
