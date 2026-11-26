/* Bind an admitted membership key set to an exact query key. */
#ifndef NATIVE_AF_KEYED_H
#define NATIVE_AF_KEYED_H

#include "nodes/pathnodes.h"

extern SubLink *native_af_keyed_sublink(RelOptInfo *rel, const Var *key, Oid equality,
										const SubLink *enumeration,
										const RestrictInfo *policy);

#endif
