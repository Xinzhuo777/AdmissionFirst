#!/bin/sh
# Build the title-search fixture database (default name: title_search).
#
# Content: public.prefix_doc (524,288 documents: id, title, secret),
# public.share_acl, public.group_membership, the audit table
# public.prefix_audit with its logging function public.prefix_audit_secret,
# the metadata table public.prefix_formal_meta, three row-level-security
# policies, and the cluster roles af_prefix_sparse / af_prefix_medium /
# af_prefix_dense (created if missing).
#
# Steps: create an empty UTF8 / C-locale database from template0, load
# sql/title_search_setup.sql in one transaction (tables, deterministic data,
# indexes, policies, grants, ANALYZE), then run sql/title_search_finish.sql
# (audit table emptied, audit sequence positioned, heap hint bits settled),
# and finally load the reference planner statistics (stats/, skip with -R).
#
# Usage: build_title_search.sh [-b PG_BIN_DIR] [-H SOCKET_DIR] [-p PORT]
#                              [-d DATABASE] [-U SUPERUSER] [-R]
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
FIXTURE_LABEL="title-search"
FIXTURE_DEFAULT_DB=title_search
. "$HERE/fixture_common.sh"
fixture_parse_args "$@"

start=$(fixture_now)
echo "creating database $FIXTURE_DB"
fixture_create_database
echo "loading data (one transaction)"
fixture_psql "$FIXTURE_DB" -f "$HERE/sql/title_search_setup.sql"
echo "finishing (audit state, hint bits)"
fixture_psql "$FIXTURE_DB" -o /dev/null -f "$HERE/sql/title_search_finish.sql"
fixture_load_statistics "$HERE/stats/title_search_statistics.sql"
fixture_query "$FIXTURE_DB" "CHECKPOINT" >/dev/null
end=$(fixture_now)
echo "title-search fixture ready in database $FIXTURE_DB ($((end - start)) s)"
