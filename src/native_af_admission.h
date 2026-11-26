/*-------------------------------------------------------------------------
 *
 * native_af_admission.h
 *	  Requirement, rule and delivery records of the admission check
 *	  (native_af_admission.c).
 *
 *-------------------------------------------------------------------------
 */
#ifndef NATIVE_AF_ADMISSION_H
#define NATIVE_AF_ADMISSION_H

#include "nodes/pathnodes.h"
#include "utils/snapshot.h"

typedef struct NativeAfScanRequirement
{
	PlannerInfo *planner;
	RangeTblEntry *relation;
	RTEPermissionInfo *permission;
	Index		occurrence;
	Oid			query_role;
	Oid			principal;
	Snapshot	snapshot;
	Node	   *policy;
	PathTarget *target;
	List	   *restrictions;
	Bitmapset  *output_columns;
} NativeAfScanRequirement;

/* The caller validates the provider's exact selection or necessary prefix. */
typedef struct NativeAfScanRule
{
	PathTarget *input;
	PathTarget *output;
	Node	   *target_filter;
	List	   *before_check;
	List	   *after_check;
	Node	   *exact_check;
	List	   *validated_prefix;
	AttrNumber	identity;
} NativeAfScanRule;

typedef struct NativeAfScanDelivery
{
	const NativeAfScanRequirement *binding;
	PathTarget *input;
	PathTarget *output;
	Node	   *target_filter;
	List	   *prefix;
	Bitmapset  *check_inputs;
	Bitmapset  *carriers;
	AttrNumber	identity;
	Node	   *pending;
	bool		covers_target;
	bool		exact;
} NativeAfScanDelivery;

extern bool native_af_scan_requirement(PlannerInfo *root, RelOptInfo *rel,
									   RangeTblEntry *rte, NativeAfScanRequirement *need);
extern const char *native_af_admit_checked_scan(const NativeAfScanRequirement *need,
												const NativeAfScanRule *rule, NativeAfScanDelivery *out);
extern const char *native_af_scan_preserves(const NativeAfScanDelivery *better,
											const NativeAfScanDelivery *worse, bool need_identity);

#endif
