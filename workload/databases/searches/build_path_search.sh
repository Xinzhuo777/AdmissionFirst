#!/bin/sh
# Build the document-path-search fixture database (default name: path_search).
#
# Content: a document table (1,000,000 rows: id, tenant_id, path, title), a
# share-ACL table (2,000,004 rows), a group-membership table (13,120 rows),
# three row-level-security policies, per-column statistics targets of 1000,
# and the three reader roles (cluster-wide; created if missing).  All object
# names are those of the reference database; see sql/path_search_setup.sql.
#
# Steps: create an empty UTF8 / C-locale database from template0, load
# sql/path_search_setup.sql in one transaction (tables, deterministic data,
# indexes, policies, grants, statistics targets), then run
# sql/path_search_post_load.sql in a new session (VACUUM (FREEZE, ANALYZE)),
# and finally load the reference planner statistics (stats/, skip with -R).
#
# Usage: build_path_search.sh [-b PG_BIN_DIR] [-H SOCKET_DIR] [-p PORT]
#                             [-d DATABASE] [-U SUPERUSER] [-R]
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
FIXTURE_LABEL="document-path-search"
FIXTURE_DEFAULT_DB=path_search
. "$HERE/fixture_common.sh"
fixture_parse_args "$@"

start=$(fixture_now)
echo "creating database $FIXTURE_DB"
fixture_create_database
echo "loading data (one transaction)"
fixture_psql "$FIXTURE_DB" -f "$HERE/sql/path_search_setup.sql"
echo "vacuum (freeze, analyze)"
fixture_psql "$FIXTURE_DB" -f "$HERE/sql/path_search_post_load.sql"
fixture_load_statistics "$HERE/stats/path_search_statistics.sql"
fixture_query "$FIXTURE_DB" "CHECKPOINT" >/dev/null
end=$(fixture_now)
echo "document-path-search fixture ready in database $FIXTURE_DB ($((end - start)) s)"
