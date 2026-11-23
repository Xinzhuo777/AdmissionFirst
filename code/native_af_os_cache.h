#ifndef AF_OS_CACHE_H
#define AF_OS_CACHE_H
#include <stddef.h>
#include <stdint.h>

#define AF_OS_CACHE_MAX_SAMPLES 4096
#define AF_OS_CACHE_MAX_FILE_BYTES UINT64_C(1073741824)

typedef struct AfOsCacheResult
{
    int known;
    int error_number;
    const char *reason;
    uint64_t file_bytes;
    uint64_t os_page_bytes;
    uint64_t sampled_pages;
    uint64_t resident_pages;
    uint64_t elapsed_ns;
    double resident_fraction;
    double io_fraction; /* Always 1.0 on UNKNOWN; caller keeps original cost. */
} AfOsCacheResult;

/* Caller owns fd and admission/permissions. Never reads mapped/file contents,
 * prints metadata, changes task settings, or retains any per-query state.
 * A regular PG segment <=1GiB is sampled through a fresh PROT_NONE mapping.
 * budget is the maximum number of OS pages, not PostgreSQL 8KiB blocks.
 * 1=metadata known, 0=UNKNOWN with io_fraction=1.0. */
int af_os_cache_probe_fd(int fd, size_t budget, AfOsCacheResult *result);
#endif
