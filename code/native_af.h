/* AdmissionFirst integration for the PostgreSQL 16 optimizer. */
#ifndef NATIVE_AF_H
#define NATIVE_AF_H

#include "nodes/pathnodes.h"
#include "nodes/params.h"
#include "nodes/plannodes.h"
#include "nodes/execnodes.h"

extern void native_af_initialize(void);
extern void native_af_note_planning(void);
extern bool native_af_stream_execution_allowed(void);
extern void native_af_note_stream_heap_execution(void);
extern void native_af_note_stream_index_execution(void);
extern void native_af_note_stream_index_read(void);
extern void native_af_stream_mark_index(PlannerInfo *root, IndexPath *path,
                                        IndexScan *scan);
extern void native_af_stream_finalize(PlannerInfo *root, Plan *plan);
extern void native_af_add_join_input_filter(PlannerInfo *root, Plan *plan, Query *original, int cursorOptions);
extern void *native_af_cost_enter(Query *parse);
extern void native_af_cost_leave(void *token);
extern double native_af_cache_io_fraction(PlannerInfo *root, Oid relation_oid,
                                         double pages, double page_events, double scans);
extern Query *native_af_batch_save(Query *parse);
extern PlannedStmt *native_af_batch_choose(Query *saved, PlannedStmt *original,
							const char *query_string, int cursorOptions,
							ParamListInfo boundParams);
extern void native_af_batch_prepare(PlannerInfo *root);
extern Cost native_af_batch_bitmap_savings(PlannerInfo *root, RelOptInfo *rel,
										   Path *bitmapqual, ParamPathInfo *param_info,
										   double tuples_fetched);
extern bool native_af_batch_join_rows(PlannerInfo *root, RelOptInfo *joinrel,
					RelOptInfo *outer_rel, RelOptInfo *inner_rel,
					double outer_rows, double inner_rows, SpecialJoinInfo *sjinfo,
					List *restrictlist, double *rows_out);
extern void native_af_batch_join_scope(PlannerInfo *root, RelOptInfo *joinrel,
					RelOptInfo *outer_rel, RelOptInfo *inner_rel);
extern bool native_af_readonly_statement(PlannerInfo *root);
extern bool native_af_allow_serial_candidates(void);
extern bool native_af_serial_acl_source(PlannerInfo *root);
extern bool native_af_serial_policy(PlannerInfo *root, Node *expression);
extern bool native_af_serial_plan(Plan *plan);
extern void native_af_check_serial_scan(CustomScan *scan, EState *estate);
extern void native_af_collect_index(PlannerInfo *root, IndexOptInfo *index,
									const char *name);
extern void native_af_prepare_membership(PlannerInfo *root, Index rti,
										 RangeTblEntry *rte);
extern void native_af_size_paths(PlannerInfo *root, RelOptInfo *rel,
									 RangeTblEntry *rte);
extern void native_af_add_paths(PlannerInfo *root, RelOptInfo *rel,
								 RangeTblEntry *rte);

#endif
