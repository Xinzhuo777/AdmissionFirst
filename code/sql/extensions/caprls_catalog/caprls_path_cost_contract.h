#ifndef CAPRLS_PATH_COST_CONTRACT_H
#define CAPRLS_PATH_COST_CONTRACT_H

/*
 * Bounded CustomScan catalog path cost contract.
 *
 * These constants define the C witness cost interface for the two bounded
 * path families exposed by caprls_catalog.c.  Keep them in sync with
 * caprls_core.catalog_path_cost; tests/test_catalog_extension.py verifies
 * the Python and C contracts agree.
 */
#define CAPRLS_PATH_COST_BASE_SCAN_UNIT 0.01
#define CAPRLS_PATH_COST_POLICY_EVAL_UNIT 0.02
#define CAPRLS_PATH_COST_ARTIFACT_LOOKUP_STARTUP 0.05
#define CAPRLS_PATH_COST_ARTIFACT_BASE_FETCH_UNIT 0.01

#endif
