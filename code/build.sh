#!/bin/sh
# Build an isolated PostgreSQL release tree with the native AF changes.
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 NEW_BUILD_DIRECTORY" >&2
    exit 2
fi
kernel_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
mkdir "$1"
build_dir=$(CDPATH='' cd -- "$1" && pwd)
cd "$build_dir"

version=16.11
archive="postgresql-$version.tar.bz2"
url="https://ftp.postgresql.org/pub/source/v$version/$archive"
sha256=6deb08c23d03d77d8f8bd1c14049eeef64aef8968fd8891df2dfc0b42f178eac
if [ -n "${NATIVE_AF_SOURCE_ARCHIVE:-}" ]; then
    cp "$NATIVE_AF_SOURCE_ARCHIVE" "$archive"
else
    curl --fail --location --silent --show-error "$url" -o "$archive"
fi
printf '%s  %s\n' "$sha256" "$archive" | shasum -a 256 -c -
printf '%s\n' d61dd817be70749d14e982a369e97fdda9d5cba6 > REL_16_11.commit
shasum -a 256 "$kernel_dir"/native_af.c "$kernel_dir"/native_af.h \
    "$kernel_dir"/native_af_sp.c "$kernel_dir"/native_af_sp.h \
    "$kernel_dir"/native_af_keyed.c "$kernel_dir"/native_af_keyed.h \
    "$kernel_dir"/native_af_partial.c "$kernel_dir"/native_af_partial.h \
    "$kernel_dir"/native_af_binding.c "$kernel_dir"/native_af_binding.h \
    "$kernel_dir"/native_af_guard.c "$kernel_dir"/native_af_guard.h \
    "$kernel_dir"/native_af_os_cache.c "$kernel_dir"/native_af_os_cache.h \
    "$kernel_dir"/postgres16.patch > implementation.sha256
tar -xjf "$archive"
cd "postgresql-$version"
if [ "$(uname -s)" = Darwin ] && command -v brew >/dev/null 2>&1; then
    openssl_prefix=$(brew --prefix openssl@3)
    CPPFLAGS="${CPPFLAGS:-} -I$openssl_prefix/include"
    LDFLAGS="${LDFLAGS:-} -L$openssl_prefix/lib"
    export CPPFLAGS LDFLAGS
fi
patch -p1 < "$kernel_dir/postgres16.patch"
cp "$kernel_dir/native_af.c" "$kernel_dir/native_af_sp.c" \
   "$kernel_dir/native_af_keyed.c" "$kernel_dir/native_af_partial.c" \
   "$kernel_dir/native_af_binding.c" "$kernel_dir/native_af_guard.c" "$kernel_dir/native_af_os_cache.c" src/backend/optimizer/plan/
cp "$kernel_dir/native_af.h" "$kernel_dir/native_af_sp.h" \
   "$kernel_dir/native_af_keyed.h" "$kernel_dir/native_af_partial.h" \
   "$kernel_dir/native_af_binding.h" "$kernel_dir/native_af_guard.h" "$kernel_dir/native_af_os_cache.h" src/include/optimizer/
./configure --prefix="$build_dir/install" --without-icu --without-readline \
    --without-zlib --with-openssl --enable-depend > "$build_dir/configure.log" 2>&1
make -j "${NATIVE_AF_BUILD_JOBS:-6}" > "$build_dir/build.log" 2>&1
make install > "$build_dir/install.log" 2>&1
make -C contrib/pgcrypto -j "${NATIVE_AF_BUILD_JOBS:-6}" > "$build_dir/pgcrypto-build.log" 2>&1
make -C contrib/pgcrypto install > "$build_dir/pgcrypto-install.log" 2>&1
"$build_dir/install/bin/postgres" --version
