#!/bin/sh
# Build PostgreSQL 16.11 with AdmissionFirst into a new, separate directory.
#
#   sh src/build.sh NEW_BUILD_DIRECTORY
#
# The script obtains the PostgreSQL 16.11 source archive, checks its SHA-256,
# applies postgres16.patch, copies the AdmissionFirst sources into the tree,
# and installs into NEW_BUILD_DIRECTORY/install. Nothing outside the new
# directory is changed.
#
# Environment:
#   NATIVE_AF_SOURCE_ARCHIVE  use this local postgresql-16.11.tar.bz2 instead
#                             of downloading it (it is checked the same way)
#   NATIVE_AF_BUILD_JOBS      parallel make jobs (default 6)
#   NATIVE_AF_STOCK=1         build unmodified PostgreSQL 16.11 instead (used
#                             for the IN-rewrite and key-array baselines)
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 NEW_BUILD_DIRECTORY" >&2
    exit 2
fi
source_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
mkdir "$1"
build_dir=$(CDPATH='' cd -- "$1" && pwd)
cd "$build_dir"
jobs=${NATIVE_AF_BUILD_JOBS:-6}
stock=${NATIVE_AF_STOCK:-0}

# SHA-256 helper: shasum on macOS and most Linux systems, sha256sum otherwise.
if command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$@"; }
else
    sha256() { sha256sum "$@"; }
fi

# AdmissionFirst sources: compiled into the planner and included by it.
modules="native_af native_af_sp native_af_keyed native_af_partial native_af_binding
         native_af_guard native_af_admission native_af_os_cache"

# 1. Obtain and verify the upstream source (tag REL_16_11).
version=16.11
archive="postgresql-$version.tar.bz2"
url="https://ftp.postgresql.org/pub/source/v$version/$archive"
archive_sha256=6deb08c23d03d77d8f8bd1c14049eeef64aef8968fd8891df2dfc0b42f178eac
if [ -n "${NATIVE_AF_SOURCE_ARCHIVE:-}" ]; then
    cp "$NATIVE_AF_SOURCE_ARCHIVE" "$archive"
else
    curl --fail --location --silent --show-error "$url" -o "$archive"
fi
printf '%s  %s\n' "$archive_sha256" "$archive" | sha256 -c -
printf '%s\n' d61dd817be70749d14e982a369e97fdda9d5cba6 > REL_16_11.commit

# Record the digests of the AdmissionFirst inputs used for this build.
[ "$stock" = 1 ] && modules= && echo "building unmodified PostgreSQL $version"
(
    for module in $modules; do
        printf '%s\n' "$source_dir/$module.c" "$source_dir/$module.h"
    done
    [ "$stock" = 1 ] || printf '%s\n' "$source_dir/postgres16.patch"
) | while read -r file; do sha256 "$file"; done > implementation.sha256

# 2. Patch the PostgreSQL tree and add the AdmissionFirst sources.
tar -xjf "$archive"
cd "postgresql-$version"
if [ "$(uname -s)" = Darwin ] && command -v brew >/dev/null 2>&1; then
    openssl_prefix=$(brew --prefix openssl@3)
    CPPFLAGS="${CPPFLAGS:-} -I$openssl_prefix/include"
    LDFLAGS="${LDFLAGS:-} -L$openssl_prefix/lib"
    export CPPFLAGS LDFLAGS
fi
[ "$stock" = 1 ] || patch -p1 < "$source_dir/postgres16.patch"
for module in $modules; do
    cp "$source_dir/$module.c" src/backend/optimizer/plan/
    cp "$source_dir/$module.h" src/include/optimizer/
done

# 3. Configure, build and install. Two standard contrib modules are added:
#    pgcrypto (used by the application workload) and pg_prewarm (used by
#    tools/replay.py to bring each database into the page cache).
./configure --prefix="$build_dir/install" --without-icu --without-readline \
    --without-zlib --with-openssl --enable-depend > "$build_dir/configure.log" 2>&1
make -j "$jobs" > "$build_dir/build.log" 2>&1
make install > "$build_dir/install.log" 2>&1
make -C contrib/pgcrypto -j "$jobs" > "$build_dir/pgcrypto-build.log" 2>&1
make -C contrib/pgcrypto install > "$build_dir/pgcrypto-install.log" 2>&1
make -C contrib/pg_prewarm -j "$jobs" > "$build_dir/pg_prewarm-build.log" 2>&1
make -C contrib/pg_prewarm install > "$build_dir/pg_prewarm-install.log" 2>&1
"$build_dir/install/bin/postgres" --version
