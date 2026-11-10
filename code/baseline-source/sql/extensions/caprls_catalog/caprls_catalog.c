#include "postgres.h"

#include <string.h>
#include <stdlib.h>

#include "caprls_path_cost_contract.h"

#include "access/xact.h"
#include "access/htup_details.h"
#include "commands/explain.h"
#include "executor/executor.h"
#include "executor/spi.h"
#include "executor/tuptable.h"
#include "fmgr.h"
#include "nodes/bitmapset.h"
#include "nodes/extensible.h"
#include "nodes/makefuncs.h"
#include "nodes/pathnodes.h"
#include "nodes/pg_list.h"
#include "nodes/plannodes.h"
#include "nodes/value.h"
#include "optimizer/pathnode.h"
#include "optimizer/paths.h"
#include "parser/parsetree.h"
#include "utils/builtins.h"
#include "utils/datum.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"

PG_MODULE_MAGIC;

void _PG_init(void);
void _PG_fini(void);

static set_rel_pathlist_hook_type prev_set_rel_pathlist_hook = NULL;

static bool caprls_enable_path_witness = false;
static double caprls_auth_index_cost_factor = 0.95;
static double caprls_barrier_cost_factor = 1.05;
static bool caprls_path_witness_catalog_lookup_active = false;

typedef struct CaprlsPathWitnessCatalogRow
{
    bool found;
    char *policy_access_occurrence_id;
    char *policy_id;
    char *artifact_id;
    char *rid_domain_id;
    char *relname;
    char *policy_predicate;
    char *expected_versions_json;
    char *artifact_relname;
    char *base_rid_col;
    char *artifact_invalid_action;
    double base_rows;
    double artifact_rows;
} CaprlsPathWitnessCatalogRow;

typedef struct CaprlsPathWitnessMetadata
{
    const char *template_id;
    const char *policy_access_occurrence_id;
    const char *policy_id;
    const char *artifact_id;
    const char *rid_domain_id;
    const char *relname;
    const char *policy_predicate;
    const char *expected_versions_json;
    const char *artifact_relname;
    const char *base_rid_col;
    const char *artifact_invalid_action;
} CaprlsPathWitnessMetadata;

typedef struct CaprlsPathWitnessState
{
    CustomScanState css;
    int64 rows_total;
    int64 rows_remaining;
    int64 rows_emitted;
    bool post_execution_recorded;
    const char *template_id;
    CaprlsPathWitnessMetadata metadata;
    int cached_attr_count;
    Datum **cached_values;
    bool **cached_isnull;
} CaprlsPathWitnessState;

enum
{
    CAPRLS_PRIVATE_TEMPLATE_ID = 0,
    CAPRLS_PRIVATE_POLICY_ACCESS = 1,
    CAPRLS_PRIVATE_POLICY_ID = 2,
    CAPRLS_PRIVATE_ARTIFACT_ID = 3,
    CAPRLS_PRIVATE_RID_DOMAIN_ID = 4,
    CAPRLS_PRIVATE_RELNAME = 5,
    CAPRLS_PRIVATE_POLICY_PREDICATE = 6,
    CAPRLS_PRIVATE_EXPECTED_VERSIONS = 7,
    CAPRLS_PRIVATE_ARTIFACT_RELNAME = 8,
    CAPRLS_PRIVATE_BASE_RID_COL = 9,
    CAPRLS_PRIVATE_ARTIFACT_INVALID_ACTION = 10,
};

static Plan *caprls_plan_custom_path(PlannerInfo *root,
                                     RelOptInfo *rel,
                                     CustomPath *best_path,
                                     List *tlist,
                                     List *clauses,
                                     List *custom_plans);
static Node *caprls_create_custom_scan_state(CustomScan *cscan);
static void caprls_begin_custom_scan(CustomScanState *node, EState *estate, int eflags);
static TupleTableSlot *caprls_exec_custom_scan(CustomScanState *node);
static void caprls_end_custom_scan(CustomScanState *node);
static void caprls_rescan_custom_scan(CustomScanState *node);
static void caprls_explain_custom_scan(CustomScanState *node, List *ancestors, ExplainState *es);
static void caprls_set_rel_pathlist(PlannerInfo *root, RelOptInfo *rel, Index rti, RangeTblEntry *rte);

static CustomPathMethods caprls_barrier_path_methods = {
    "CaprlsBarrierPath",
    caprls_plan_custom_path,
    NULL,
};

static CustomPathMethods caprls_auth_index_path_methods = {
    "CaprlsAuthIndexPath",
    caprls_plan_custom_path,
    NULL,
};

static CustomScanMethods caprls_barrier_scan_methods = {
    "CaprlsBarrierPath",
    caprls_create_custom_scan_state,
};

static CustomScanMethods caprls_auth_index_scan_methods = {
    "CaprlsAuthIndexPath",
    caprls_create_custom_scan_state,
};

static CustomExecMethods caprls_exec_methods = {
    "CaprlsPathWitness",
    caprls_begin_custom_scan,
    caprls_exec_custom_scan,
    caprls_end_custom_scan,
    caprls_rescan_custom_scan,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    caprls_explain_custom_scan,
};

static const char *
caprls_private_string(List *custom_private, int index, const char *fallback)
{
    const char *value;

    if (custom_private == NIL || list_length(custom_private) <= index)
        return fallback;
    value = strVal(list_nth(custom_private, index));
    if (value == NULL || value[0] == '\0')
        return fallback;
    return value;
}

static const char *
caprls_private_nullable_string(List *custom_private, int index)
{
    const char *value;

    if (custom_private == NIL || list_length(custom_private) <= index)
        return NULL;
    value = strVal(list_nth(custom_private, index));
    if (value == NULL || value[0] == '\0')
        return NULL;
    return value;
}

static CaprlsPathWitnessMetadata
caprls_metadata_from_private(List *custom_private)
{
    CaprlsPathWitnessMetadata metadata;

    metadata.template_id = caprls_private_string(custom_private, CAPRLS_PRIVATE_TEMPLATE_ID, "unknown");
    metadata.policy_access_occurrence_id = caprls_private_string(custom_private, CAPRLS_PRIVATE_POLICY_ACCESS, "unknown-occurrence");
    metadata.policy_id = caprls_private_string(custom_private, CAPRLS_PRIVATE_POLICY_ID, "unknown-policy");
    metadata.artifact_id = caprls_private_nullable_string(custom_private, CAPRLS_PRIVATE_ARTIFACT_ID);
    metadata.rid_domain_id = caprls_private_string(custom_private, CAPRLS_PRIVATE_RID_DOMAIN_ID, "unknown-rid-domain");
    metadata.relname = caprls_private_string(custom_private, CAPRLS_PRIVATE_RELNAME, "unknown_relation");
    metadata.policy_predicate = caprls_private_string(custom_private, CAPRLS_PRIVATE_POLICY_PREDICATE, "true");
    metadata.expected_versions_json = caprls_private_string(custom_private, CAPRLS_PRIVATE_EXPECTED_VERSIONS, "[]");
    metadata.artifact_relname = caprls_private_nullable_string(custom_private, CAPRLS_PRIVATE_ARTIFACT_RELNAME);
    metadata.base_rid_col = caprls_private_string(custom_private, CAPRLS_PRIVATE_BASE_RID_COL, "id");
    metadata.artifact_invalid_action = caprls_private_string(custom_private, CAPRLS_PRIVATE_ARTIFACT_INVALID_ACTION, "fallback");
    return metadata;
}

static const char *
caprls_template_from_private(List *custom_private)
{
    return caprls_metadata_from_private(custom_private).template_id;
}

static char *
caprls_sql_literal_or_null(const char *value)
{
    if (value == NULL || value[0] == '\0')
        return pstrdup("NULL");
    return quote_literal_cstr(value);
}

static const char *
caprls_quote_relation_identifier(const char *value)
{
    const char *dot;

    if (value == NULL || value[0] == '\0')
        return quote_identifier("unknown_relation");
    dot = strchr(value, '.');
    if (dot != NULL && dot[1] != '\0')
    {
        char *schema = pnstrdup(value, dot - value);
        char *quoted = quote_qualified_identifier(schema, dot + 1);

        pfree(schema);
        return quoted;
    }
    return quote_identifier(value);
}

static char *
caprls_spi_value_copy(HeapTuple tuple, TupleDesc tupdesc, int column)
{
    char *value = SPI_getvalue(tuple, tupdesc, column);
    if (value == NULL)
        return NULL;
    return pstrdup(value);
}

static double
caprls_spi_float8_or(HeapTuple tuple, TupleDesc tupdesc, int column, double fallback)
{
    char *value = SPI_getvalue(tuple, tupdesc, column);
    if (value == NULL || value[0] == '\0')
        return fallback;
    return atof(value);
}

static CaprlsPathWitnessCatalogRow
caprls_lookup_path_witness_catalog(const char *relname)
{
    CaprlsPathWitnessCatalogRow row;
    volatile bool saved_enable_path_witness = caprls_enable_path_witness;
    char *sql;
    int ret;
    bool catalog_tables_exist = false;

    memset(&row, 0, sizeof(row));
    if (relname == NULL || !IsTransactionState() || caprls_path_witness_catalog_lookup_active)
        return row;

    caprls_path_witness_catalog_lookup_active = true;
    caprls_enable_path_witness = false;
    PG_TRY();
    {
        if (SPI_connect() != SPI_OK_CONNECT)
            elog(ERROR, "CAPRLS path witness catalog lookup could not connect to SPI");

        ret = SPI_execute(
            "SELECT to_regclass('caprls_catalog.policy_catalog') IS NOT NULL "
            "AND to_regclass('caprls_catalog.rid_domain') IS NOT NULL "
            "AND to_regclass('caprls_catalog.artifact_catalog') IS NOT NULL "
            "AND to_regclass('caprls_catalog.artifact_dependencies') IS NOT NULL",
            true,
            0);
        if (ret != SPI_OK_SELECT || SPI_processed != 1)
        {
            SPI_finish();
            elog(ERROR, "CAPRLS path witness catalog existence probe failed: %d", ret);
        }
        catalog_tables_exist = strcmp(SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1), "t") == 0;

        if (catalog_tables_exist)
        {
            sql = psprintf(
                "SELECT "
                "p.policy_id, "
                "('pa_' || p.relname || '_1') AS policy_access_occurrence_id, "
                "r.domain_id, "
                "a.artifact_id, "
                "COALESCE(NULLIF(p.exact_sql, ''), 'true') AS policy_predicate, "
                "CASE WHEN a.artifact_id IS NULL THEN '[]' ELSE jsonb_build_array("
                "    jsonb_build_object("
                "      'dep_kind', 'policy', "
                "      'dep_name', p.policy_id, "
                "      'version_at_build', COALESCE(a.policy_version, p.policy_version, 0)"
                "    ), "
                "    jsonb_build_object("
                "      'dep_kind', 'membership', "
                "      'dep_name', COALESCE(a.user_scope, 'unknown-user'), "
                "      'version_at_build', COALESCE(a.membership_version, 0)"
                "    ), "
                "    jsonb_build_object("
                "      'dep_kind', 'context', "
                "      'dep_name', COALESCE(a.group_scope_hash, 'ctx1'), "
                "      'version_at_build', COALESCE(a.context_version, 0)"
                "    ), "
                "    jsonb_build_object("
                "      'dep_kind', 'base', "
                "      'dep_name', p.relname, "
                "      'version_at_build', COALESCE(a.base_version, 0)"
                "    ), "
                "    jsonb_build_object("
                "      'dep_kind', 'rid_domain', "
                "      'dep_name', r.domain_id, "
                "      'version_at_build', 0"
                "    )"
                ")::text END AS expected_versions_json, "
                "a.materialized_rel::text AS artifact_relname, "
                "r.surrogate_col AS base_rid_col, "
                "COALESCE(a.invalid_action, 'fallback') AS artifact_invalid_action, "
                "GREATEST(COALESCE(NULLIF(c.reltuples, -1), 1000), 1)::float8 AS base_rows, "
                "GREATEST(COALESCE(a.declared_cardinality::float8, NULLIF(ac.reltuples, -1), "
                "                  COALESCE(NULLIF(c.reltuples, -1), 1000) * 0.1), 1)::float8 "
                "  AS artifact_rows "
                "FROM caprls_catalog.policy_catalog p "
                "JOIN caprls_catalog.rid_domain r ON r.relname = p.relname "
                "LEFT JOIN LATERAL ("
                "  SELECT artifact_id, materialized_rel, declared_cardinality, "
                "         policy_version, membership_version, context_version, base_version, "
                "         user_scope, group_scope_hash, invalid_action "
                "  FROM caprls_catalog.artifact_catalog ac "
                "  WHERE ac.relname = p.relname "
                "    AND ac.policy_id = p.policy_id "
                "    AND ac.artifact_type = 'auth_idx' "
                "    AND ac.valid "
                "  ORDER BY artifact_id "
                "  LIMIT 1"
                ") a ON true "
                "JOIN pg_class c ON c.oid = p.relname::regclass "
                "LEFT JOIN pg_class ac ON ac.oid = a.materialized_rel "
                "WHERE p.relname = %s "
                "ORDER BY p.policy_id, r.domain_id "
                "LIMIT 1",
                quote_literal_cstr(relname));
            ret = SPI_execute(sql, true, 0);
            if (ret != SPI_OK_SELECT)
            {
                SPI_finish();
                elog(ERROR, "CAPRLS path witness catalog query failed: %d", ret);
            }
            if (SPI_processed == 1)
            {
                HeapTuple tuple = SPI_tuptable->vals[0];
                TupleDesc tupdesc = SPI_tuptable->tupdesc;

                row.found = true;
                row.policy_id = caprls_spi_value_copy(tuple, tupdesc, 1);
                row.policy_access_occurrence_id = caprls_spi_value_copy(tuple, tupdesc, 2);
                row.rid_domain_id = caprls_spi_value_copy(tuple, tupdesc, 3);
                row.artifact_id = caprls_spi_value_copy(tuple, tupdesc, 4);
                row.policy_predicate = caprls_spi_value_copy(tuple, tupdesc, 5);
                row.expected_versions_json = caprls_spi_value_copy(tuple, tupdesc, 6);
                row.artifact_relname = caprls_spi_value_copy(tuple, tupdesc, 7);
                row.base_rid_col = caprls_spi_value_copy(tuple, tupdesc, 8);
                row.artifact_invalid_action = caprls_spi_value_copy(tuple, tupdesc, 9);
                row.base_rows = caprls_spi_float8_or(tuple, tupdesc, 10, 1000.0);
                row.artifact_rows = caprls_spi_float8_or(tuple, tupdesc, 11, row.base_rows);
                row.relname = pstrdup(relname);
            }
        }
        SPI_finish();
    }
    PG_CATCH();
    {
        caprls_enable_path_witness = saved_enable_path_witness;
        caprls_path_witness_catalog_lookup_active = false;
        PG_RE_THROW();
    }
    PG_END_TRY();
    caprls_enable_path_witness = saved_enable_path_witness;
    caprls_path_witness_catalog_lookup_active = false;
    return row;
}

static List *
caprls_make_private(const char *template_id, const CaprlsPathWitnessCatalogRow *catalog)
{
    List *private = NIL;

    private = lappend(private, makeString(pstrdup(template_id)));
    private = lappend(private, makeString(pstrdup(catalog->policy_access_occurrence_id)));
    private = lappend(private, makeString(pstrdup(catalog->policy_id)));
    private = lappend(private, makeString(pstrdup(catalog->artifact_id == NULL ? "" : catalog->artifact_id)));
    private = lappend(private, makeString(pstrdup(catalog->rid_domain_id)));
    private = lappend(private, makeString(pstrdup(catalog->relname)));
    private = lappend(private, makeString(pstrdup(catalog->policy_predicate)));
    private = lappend(private, makeString(pstrdup(catalog->expected_versions_json)));
    private = lappend(private, makeString(pstrdup(catalog->artifact_relname == NULL ? "" : catalog->artifact_relname)));
    private = lappend(private, makeString(pstrdup(catalog->base_rid_col == NULL ? "" : catalog->base_rid_col)));
    private = lappend(private, makeString(pstrdup(catalog->artifact_invalid_action == NULL ? "fallback" : catalog->artifact_invalid_action)));
    return private;
}

static double
caprls_positive_or(double value, double fallback)
{
    if (value > 0.0)
        return value;
    if (fallback > 0.0)
        return fallback;
    return 1.0;
}

static double
caprls_catalog_rows_for_template(const char *template_id,
                                 const CaprlsPathWitnessCatalogRow *catalog,
                                 const Path *subpath)
{
    if (strcmp(template_id, "CaprlsAuthIndexPath") == 0 && catalog->artifact_id != NULL)
        return caprls_positive_or(catalog->artifact_rows, subpath->rows);
    return caprls_positive_or(catalog->base_rows, subpath->rows);
}

static double
caprls_catalog_cost_for_template(const char *template_id,
                                 const CaprlsPathWitnessCatalogRow *catalog,
                                 const Path *subpath)
{
    const double row_count = caprls_catalog_rows_for_template(template_id, catalog, subpath);

    if (strcmp(template_id, "CaprlsAuthIndexPath") == 0 && catalog->artifact_id != NULL)
        return CAPRLS_PATH_COST_ARTIFACT_LOOKUP_STARTUP +
               row_count * CAPRLS_PATH_COST_ARTIFACT_BASE_FETCH_UNIT;
    return row_count * (CAPRLS_PATH_COST_BASE_SCAN_UNIT +
                        CAPRLS_PATH_COST_POLICY_EVAL_UNIT);
}

static bool
caprls_execute_pre_observation_sql(const CaprlsPathWitnessMetadata *metadata)
{
    int ret;
    char *sql;
    bool validation_passed = true;

    if (strcmp(metadata->template_id, "CaprlsAuthIndexPath") == 0 && metadata->artifact_id != NULL)
    {
        sql = psprintf(
            "SELECT caprls_catalog.caprls_assert_artifact_valid("
            "%s,"
            "%s::jsonb,"
            "%s,"
            "%s,"
            "%s,"
            "jsonb_build_object("
            "'Template', %s,"
            "'Dom', %s,"
            "'AuthSet', 'exact',"
            "'Freshness', 'valid',"
            "'ContextScope', 'ctx1',"
            "'SnapshotScope', 'executing_snapshot',"
            "'ValidationPhase', 'BeginCustomScan',"
            "'Phase', 'metadata_before_execution'"
            "))",
            caprls_sql_literal_or_null(metadata->artifact_id),
            quote_literal_cstr(metadata->expected_versions_json),
            quote_literal_cstr(metadata->artifact_invalid_action),
            quote_literal_cstr(metadata->template_id),
            quote_literal_cstr(metadata->policy_access_occurrence_id),
            quote_literal_cstr(metadata->template_id),
            quote_literal_cstr(metadata->rid_domain_id));
    }
    else
    {
        sql = psprintf(
            "SELECT caprls_catalog.caprls_record_path_observation("
            "%s,"
            "%s,"
            "%s,"
            "%s,"
            "%s,"
            "'execute',"
            "jsonb_build_object("
            "'Template', %s,"
            "'Dom', %s,"
            "'AuthSet', 'exact-boundary',"
            "'SafetyLevel', 'authorize-before-user-qual',"
            "'SnapshotScope', 'executing_snapshot',"
            "'ValidationPhase', 'BeginCustomScan',"
            "'Phase', 'metadata_before_execution'"
            "))",
            quote_literal_cstr(metadata->template_id),
            quote_literal_cstr(metadata->policy_access_occurrence_id),
            quote_literal_cstr(metadata->policy_id),
            caprls_sql_literal_or_null(metadata->artifact_id),
            quote_literal_cstr(metadata->rid_domain_id),
            quote_literal_cstr(metadata->template_id),
            quote_literal_cstr(metadata->rid_domain_id));
    }

    if (SPI_connect() != SPI_OK_CONNECT)
        elog(ERROR, "CAPRLS path witness could not connect to SPI");
    ret = SPI_execute(sql, false, 0);
    if (ret < 0)
    {
        SPI_finish();
        elog(ERROR, "CAPRLS path witness observation SQL failed: %d", ret);
    }
    if (strcmp(metadata->template_id, "CaprlsAuthIndexPath") == 0 && metadata->artifact_id != NULL)
    {
        bool isnull = false;
        Datum validation_datum;

        if (ret != SPI_OK_SELECT || SPI_processed != 1)
        {
            SPI_finish();
            elog(ERROR, "CAPRLS path witness validation SQL returned unexpected result: %d", ret);
        }
        validation_datum = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &isnull);
        validation_passed = !isnull && DatumGetBool(validation_datum);
    }
    SPI_finish();
    return validation_passed;
}

static void
caprls_execute_post_observation_sql(const CaprlsPathWitnessMetadata *metadata, int64 rows_emitted)
{
    int ret;
    char *sql;

    if (strcmp(metadata->template_id, "CaprlsAuthIndexPath") == 0 && metadata->artifact_id != NULL)
    {
        sql = psprintf(
            "SELECT caprls_catalog.caprls_record_path_observation("
            "%s,"
            "%s,"
            "%s,"
            "%s,"
            "%s,"
            "'execute',"
            "jsonb_build_object("
            "'Template', %s,"
            "'Dom', %s,"
            "'AuthSet', 'exact',"
            "'Freshness', 'valid',"
            "'ContextScope', 'ctx1',"
            "'SnapshotScope', 'executing_snapshot',"
            "'Phase', 'post_execution',"
            "'RowsEmitted', %lld"
            "))",
            quote_literal_cstr(metadata->template_id),
            quote_literal_cstr(metadata->policy_access_occurrence_id),
            quote_literal_cstr(metadata->policy_id),
            caprls_sql_literal_or_null(metadata->artifact_id),
            quote_literal_cstr(metadata->rid_domain_id),
            quote_literal_cstr(metadata->template_id),
            quote_literal_cstr(metadata->rid_domain_id),
            (long long) rows_emitted);
    }
    else
    {
        sql = psprintf(
            "SELECT caprls_catalog.caprls_record_path_observation("
            "%s,"
            "%s,"
            "%s,"
            "%s,"
            "%s,"
            "'execute',"
            "jsonb_build_object("
            "'Template', %s,"
            "'Dom', %s,"
            "'AuthSet', 'exact-boundary',"
            "'SafetyLevel', 'authorize-before-user-qual',"
            "'SnapshotScope', 'executing_snapshot',"
            "'Phase', 'post_execution',"
            "'RowsEmitted', %lld"
            "))",
            quote_literal_cstr(metadata->template_id),
            quote_literal_cstr(metadata->policy_access_occurrence_id),
            quote_literal_cstr(metadata->policy_id),
            caprls_sql_literal_or_null(metadata->artifact_id),
            quote_literal_cstr(metadata->rid_domain_id),
            quote_literal_cstr(metadata->template_id),
            quote_literal_cstr(metadata->rid_domain_id),
            (long long) rows_emitted);
    }

    if (SPI_connect() != SPI_OK_CONNECT)
        elog(ERROR, "CAPRLS path witness could not connect to SPI");
    ret = SPI_execute(sql, false, 0);
    if (ret < 0)
    {
        SPI_finish();
        elog(ERROR, "CAPRLS path witness post-execution observation SQL failed: %d", ret);
    }
    SPI_finish();
}

static char *
caprls_row_query_sql(const CaprlsPathWitnessMetadata *metadata)
{
    if (strcmp(metadata->template_id, "CaprlsAuthIndexPath") == 0 &&
        metadata->artifact_id != NULL &&
        metadata->artifact_relname != NULL)
        return psprintf(
            "SELECT r.* FROM %s r "
            "JOIN %s a ON r.%s = a.rid "
            "WHERE a.artifact_id = %s "
            "  AND a.rid_domain_id = %s",
            caprls_quote_relation_identifier(metadata->relname),
            caprls_quote_relation_identifier(metadata->artifact_relname),
            quote_identifier(metadata->base_rid_col),
            quote_literal_cstr(metadata->artifact_id),
            quote_literal_cstr(metadata->rid_domain_id));
    if (metadata->policy_predicate != NULL && metadata->policy_predicate[0] != '\0')
        return psprintf("SELECT * FROM %s WHERE %s",
                        caprls_quote_relation_identifier(metadata->relname),
                        metadata->policy_predicate);
    return psprintf("SELECT * FROM %s", caprls_quote_relation_identifier(metadata->relname));
}

static int64
caprls_load_result_rows(CaprlsPathWitnessState *state)
{
    int ret;
    uint64 row_idx;
    MemoryContext cache_context = CurrentMemoryContext;
    MemoryContext oldcontext;
    volatile bool saved_enable_path_witness = caprls_enable_path_witness;
    char *sql;

    state->cached_attr_count = 0;
    state->cached_values = NULL;
    state->cached_isnull = NULL;
    caprls_enable_path_witness = false;

    PG_TRY();
    {
        if (SPI_connect() != SPI_OK_CONNECT)
            elog(ERROR, "CAPRLS path witness could not connect to SPI");
        sql = caprls_row_query_sql(&state->metadata);
        ret = SPI_execute(sql, true, 0);
        if (ret != SPI_OK_SELECT)
        {
            SPI_finish();
            elog(ERROR, "CAPRLS path witness row query failed: %d", ret);
        }

        oldcontext = MemoryContextSwitchTo(cache_context);
        state->rows_total = (int64) SPI_processed;
        if (SPI_processed > 0)
        {
            TupleDesc tupdesc = SPI_tuptable->tupdesc;
            int attr_count = tupdesc->natts;

            state->cached_attr_count = attr_count;
            state->cached_values = palloc0(sizeof(Datum *) * SPI_processed);
            state->cached_isnull = palloc0(sizeof(bool *) * SPI_processed);
            for (row_idx = 0; row_idx < SPI_processed; row_idx++)
            {
                HeapTuple tuple = SPI_tuptable->vals[row_idx];
                int attr_idx;

                state->cached_values[row_idx] = palloc0(sizeof(Datum) * attr_count);
                state->cached_isnull[row_idx] = palloc0(sizeof(bool) * attr_count);
                for (attr_idx = 0; attr_idx < attr_count; attr_idx++)
                {
                    Form_pg_attribute attr = TupleDescAttr(tupdesc, attr_idx);
                    bool isnull = false;
                    Datum value;

                    if (attr->attisdropped)
                    {
                        state->cached_isnull[row_idx][attr_idx] = true;
                        continue;
                    }
                    value = SPI_getbinval(tuple, tupdesc, attr_idx + 1, &isnull);
                    state->cached_isnull[row_idx][attr_idx] = isnull;
                    if (!isnull)
                        state->cached_values[row_idx][attr_idx] = datumCopy(value, attr->attbyval, attr->attlen);
                }
            }
        }
        MemoryContextSwitchTo(oldcontext);
        SPI_finish();
    }
    PG_CATCH();
    {
        caprls_enable_path_witness = saved_enable_path_witness;
        PG_RE_THROW();
    }
    PG_END_TRY();
    caprls_enable_path_witness = saved_enable_path_witness;
    return state->rows_total;
}

static CustomPath *
caprls_make_path(PlannerInfo *root,
                 RelOptInfo *rel,
                 const CustomPathMethods *methods,
                 const char *template_id,
                 const CaprlsPathWitnessCatalogRow *catalog,
                 double cost_factor)
{
    Path *subpath = create_seqscan_path(root, rel, NULL, 0);
    CustomPath *path = makeNode(CustomPath);
    double catalog_rows = caprls_catalog_rows_for_template(template_id, catalog, subpath);
    double catalog_cost = caprls_catalog_cost_for_template(template_id, catalog, subpath);
    double debug_multiplier = cost_factor;

    path->path.type = T_CustomPath;
    path->path.pathtype = T_CustomScan;
    path->path.parent = rel;
    path->path.pathtarget = rel->reltarget;
    path->path.param_info = NULL;
    path->path.parallel_aware = false;
    path->path.parallel_safe = false;
    path->path.parallel_workers = 0;
    path->path.rows = catalog_rows;
    path->path.startup_cost = subpath->startup_cost + 0.01;
    path->path.total_cost = Max(path->path.startup_cost + 0.01,
                                path->path.startup_cost + catalog_cost);
    if (debug_multiplier != 1.0)
        path->path.total_cost = Max(path->path.startup_cost + 0.01,
                                    path->path.total_cost * debug_multiplier);
    path->path.pathkeys = NIL;
    path->flags = CUSTOMPATH_SUPPORT_PROJECTION;
    path->custom_paths = NIL;
    path->custom_private = caprls_make_private(template_id, catalog);
    path->methods = methods;
    return path;
}

static Plan *
caprls_plan_custom_path(PlannerInfo *root,
                        RelOptInfo *rel,
                        CustomPath *best_path,
                        List *tlist,
                        List *clauses,
                        List *custom_plans)
{
    CustomScan *cscan = makeNode(CustomScan);
    const char *template_id = caprls_template_from_private(best_path->custom_private);

    cscan->scan.plan.targetlist = tlist;
    cscan->scan.plan.qual = NIL;
    cscan->scan.scanrelid = 0;
    cscan->flags = best_path->flags;
    cscan->custom_plans = NIL;
    cscan->custom_exprs = NIL;
    cscan->custom_private = best_path->custom_private;
    cscan->custom_scan_tlist = tlist;
    cscan->custom_relids = bms_make_singleton(rel->relid);
    cscan->methods = (strcmp(template_id, "CaprlsAuthIndexPath") == 0)
                         ? &caprls_auth_index_scan_methods
                         : &caprls_barrier_scan_methods;
    return (Plan *) cscan;
}

static Node *
caprls_create_custom_scan_state(CustomScan *cscan)
{
    CaprlsPathWitnessState *state = palloc0(sizeof(CaprlsPathWitnessState));
    NodeSetTag(&state->css, T_CustomScanState);
    state->css.methods = &caprls_exec_methods;
    state->css.slotOps = &TTSOpsVirtual;
    return (Node *) &state->css;
}

static void
caprls_begin_custom_scan(CustomScanState *node, EState *estate, int eflags)
{
    CaprlsPathWitnessState *state = (CaprlsPathWitnessState *) node;
    CustomScan *cscan = (CustomScan *) node->ss.ps.plan;
    bool validation_passed;

    state->metadata = caprls_metadata_from_private(cscan->custom_private);
    state->template_id = state->metadata.template_id;
    state->post_execution_recorded = false;
    state->rows_emitted = 0;
    /*
     * The validation/metadata observation runs inside BeginCustomScan, hence in
     * the executor's transaction snapshot for this CustomScan.  This is the C
     * path-witness counterpart of the Python runners' same-snapshot
     * caprls_assert_artifact_valid gate.
     */
    validation_passed = caprls_execute_pre_observation_sql(&state->metadata);
    if (!validation_passed &&
        strcmp(state->metadata.template_id, "CaprlsAuthIndexPath") == 0 &&
        strcmp(state->metadata.artifact_invalid_action, "fallback") == 0)
    {
        state->metadata.template_id = "CaprlsBarrierPath";
        state->template_id = state->metadata.template_id;
    }
    else if (!validation_passed &&
             strcmp(state->metadata.template_id, "CaprlsAuthIndexPath") == 0)
    {
        ereport(ERROR,
                (errcode(MAKE_SQLSTATE('P', '8', 'A', '0', '1')),
                 errmsg("CAPRLS artifact validation rejected auth-index path"),
                 errdetail("CAPRLS_ARTIFACT_STALE")));
    }
    state->rows_total = caprls_load_result_rows(state);
    state->rows_remaining = state->rows_total;
}

static TupleTableSlot *
caprls_exec_custom_scan(CustomScanState *node)
{
    CaprlsPathWitnessState *state = (CaprlsPathWitnessState *) node;
    TupleTableSlot *slot = node->ss.ss_ScanTupleSlot;
    TupleDesc tupdesc;
    int natts;
    int source_natts;
    int idx;
    int64 row_idx;

    if (slot == NULL)
        slot = node->ss.ps.ps_ResultTupleSlot;
    if (slot == NULL)
        elog(ERROR, "CAPRLS path witness custom scan has no tuple slot");

    if (state->rows_remaining <= 0 || state->rows_emitted >= state->rows_total)
        return ExecClearTuple(slot);

    ExecClearTuple(slot);
    tupdesc = slot->tts_tupleDescriptor;
    natts = tupdesc == NULL ? 0 : tupdesc->natts;
    source_natts = Min(natts, state->cached_attr_count);
    row_idx = state->rows_emitted;
    for (idx = 0; idx < natts; idx++)
    {
        bool isnull = true;
        Datum value = (Datum) 0;

        slot->tts_values[idx] = (Datum) 0;
        if (idx < source_natts && state->cached_values != NULL && state->cached_isnull != NULL)
        {
            value = state->cached_values[row_idx][idx];
            isnull = state->cached_isnull[row_idx][idx];
        }
        slot->tts_values[idx] = value;
        slot->tts_isnull[idx] = isnull;
    }
    ExecStoreVirtualTuple(slot);
    state->rows_remaining--;
    state->rows_emitted++;
    return slot;
}

static void
caprls_end_custom_scan(CustomScanState *node)
{
    CaprlsPathWitnessState *state = (CaprlsPathWitnessState *) node;

    if (!state->post_execution_recorded && state->template_id != NULL)
    {
        caprls_execute_post_observation_sql(&state->metadata, state->rows_emitted);
        state->post_execution_recorded = true;
    }
}

static void
caprls_rescan_custom_scan(CustomScanState *node)
{
    CaprlsPathWitnessState *state = (CaprlsPathWitnessState *) node;

    state->rows_remaining = state->rows_total;
    state->rows_emitted = 0;
    state->post_execution_recorded = false;
}

static void
caprls_explain_custom_scan(CustomScanState *node, List *ancestors, ExplainState *es)
{
    CustomScan *cscan = (CustomScan *) node->ss.ps.plan;
    CaprlsPathWitnessMetadata metadata = caprls_metadata_from_private(cscan->custom_private);
    ExplainPropertyText("CAPRLS Template", metadata.template_id, es);
    ExplainPropertyText("CAPRLS PolicyAccess", metadata.policy_access_occurrence_id, es);
    if (metadata.artifact_relname != NULL)
        ExplainPropertyText("CAPRLS Artifact Relation", metadata.artifact_relname, es);
    ExplainPropertyText("CAPRLS Invalid Action", metadata.artifact_invalid_action, es);
    ExplainPropertyText("CAPRLS Validation ABI", "caprls_catalog", es);
    ExplainPropertyText("CAPRLS Validation Snapshot", "executing_snapshot", es);
}

static void
caprls_set_rel_pathlist(PlannerInfo *root, RelOptInfo *rel, Index rti, RangeTblEntry *rte)
{
    const char *relname;
    CaprlsPathWitnessCatalogRow catalog;

    if (prev_set_rel_pathlist_hook)
        prev_set_rel_pathlist_hook(root, rel, rti, rte);

    if (!caprls_enable_path_witness)
        return;
    if (rte == NULL || rte->rtekind != RTE_RELATION)
        return;
    if (rel->reloptkind != RELOPT_BASEREL)
        return;

    relname = get_rel_name(rte->relid);
    catalog = caprls_lookup_path_witness_catalog(relname);
    if (!catalog.found)
        return;

    add_path(rel, (Path *) caprls_make_path(root,
                                            rel,
                                            &caprls_barrier_path_methods,
                                            "CaprlsBarrierPath",
                                            &catalog,
                                            caprls_barrier_cost_factor));
    if (catalog.artifact_id != NULL)
        add_path(rel, (Path *) caprls_make_path(root,
                                                rel,
                                                &caprls_auth_index_path_methods,
                                                "CaprlsAuthIndexPath",
                                                &catalog,
                                                caprls_auth_index_cost_factor));
}

void
_PG_init(void)
{
    DefineCustomBoolVariable(
        "caprls_catalog.enable_path_witness",
        "Enable CAPRLS CustomScan path witness.",
        NULL,
        &caprls_enable_path_witness,
        false,
        PGC_USERSET,
        0,
        NULL,
        NULL,
        NULL);
    DefineCustomRealVariable(
        "caprls_catalog.auth_index_cost_factor",
        "Cost factor for the CAPRLS auth-index custom path witness.",
        NULL,
        &caprls_auth_index_cost_factor,
        0.95,
        0.01,
        100.0,
        PGC_USERSET,
        0,
        NULL,
        NULL,
        NULL);
    DefineCustomRealVariable(
        "caprls_catalog.barrier_cost_factor",
        "Cost factor for the CAPRLS barrier custom path witness.",
        NULL,
        &caprls_barrier_cost_factor,
        1.05,
        0.01,
        100.0,
        PGC_USERSET,
        0,
        NULL,
        NULL,
        NULL);

    RegisterCustomScanMethods(&caprls_barrier_scan_methods);
    RegisterCustomScanMethods(&caprls_auth_index_scan_methods);
    prev_set_rel_pathlist_hook = set_rel_pathlist_hook;
    set_rel_pathlist_hook = caprls_set_rel_pathlist;
}

void
_PG_fini(void)
{
    set_rel_pathlist_hook = prev_set_rel_pathlist_hook;
}
