#include "postgres.h"
#include "optimizer/native_af_os_cache.h"
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/sysctl.h>
#define AF_FILE_MTIME_SEC(s) ((s).st_mtimespec.tv_sec)
#define AF_FILE_MTIME_NSEC(s) ((s).st_mtimespec.tv_nsec)
#else
#define AF_FILE_MTIME_SEC(s) ((s).st_mtim.tv_sec)
#define AF_FILE_MTIME_NSEC(s) ((s).st_mtim.tv_nsec)
#ifndef MINCORE_INCORE
#define MINCORE_INCORE 0x1
#endif
#endif

static uint64_t monotonic_ns(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (uint64_t) now.tv_sec * UINT64_C(1000000000) + now.tv_nsec;
}

static int unknown(AfOsCacheResult *r, int err, const char *reason, uint64_t start)
{
    r->known = 0;
    r->error_number = err;
    r->reason = reason;
    r->resident_fraction = 0;
    r->io_fraction = 1.0;
    r->elapsed_ns = monotonic_ns() - start;
    return 0;
}

int af_os_cache_probe_fd(int fd, size_t budget, AfOsCacheResult *r)
{
    struct stat before, after;
    void *mapping;
    uint64_t start = monotonic_ns(), pages, count, i;
    long page_bytes;
    double weighted_resident = 0, weighted_sample = 0;
    int saved_error = 0;

    if (r == NULL) return 0;
    memset(r, 0, sizeof(*r));
    r->io_fraction = 1.0;
    r->reason = "unknown";
    if (budget == 0 || budget > AF_OS_CACHE_MAX_SAMPLES)
        return unknown(r, EINVAL, "invalid_budget", start);
#ifdef __APPLE__
    {
        int footprint = -1;
        size_t bytes = sizeof(footprint);
        if (sysctlbyname("vm.self_region_footprint", &footprint, &bytes, NULL, 0) != 0)
            return unknown(r, errno, "footprint_mode_unavailable", start);
        if (footprint != 0)
            return unknown(r, ENOTSUP, "footprint_mode_not_file_cache", start);
    }
#else
    return unknown(r, ENOTSUP, "platform_not_validated", start);
#endif
    page_bytes = sysconf(_SC_PAGESIZE);
    if (page_bytes <= 0)
        return unknown(r, EINVAL, "invalid_os_page_size", start);
    r->os_page_bytes = (uint64_t) page_bytes;
    if (fstat(fd, &before) != 0)
        return unknown(r, errno, "fstat", start);
    if (!S_ISREG(before.st_mode) || before.st_size <= 0 ||
        (uint64_t) before.st_size > AF_OS_CACHE_MAX_FILE_BYTES)
        return unknown(r, ENOTSUP, "unsupported_file_or_segment_size", start);
    r->file_bytes = (uint64_t) before.st_size;
    pages = (r->file_bytes + r->os_page_bytes - 1) / r->os_page_bytes;
    count = pages < budget ? pages : budget;
    mapping = mmap(NULL, (size_t) before.st_size, PROT_NONE, MAP_SHARED, fd, 0);
    if (mapping == MAP_FAILED)
        return unknown(r, errno, "mmap", start);
    for (i = 0; i < count; i++)
    {
        uint64_t first = i * pages / count;
        uint64_t limit = (i + 1) * pages / count;
        uint64_t page = first + ((i * UINT64_C(2654435761) + UINT64_C(1013904223)) % (limit - first));
        uint64_t offset = page * r->os_page_bytes;
        uint64_t bytes = r->file_bytes - offset;
        char state = 0;
        if (bytes > r->os_page_bytes) bytes = r->os_page_bytes;
        if (mincore((char *) mapping + offset, (size_t) bytes, &state) != 0)
        {
            saved_error = errno;
            break;
        }
        r->sampled_pages++;
        weighted_sample += (double) bytes;
        if (state & MINCORE_INCORE)
        {
            r->resident_pages++;
            weighted_resident += (double) bytes;
        }
    }
    if (munmap(mapping, (size_t) before.st_size) != 0 && saved_error == 0)
        saved_error = errno;
    if (saved_error != 0)
        return unknown(r, saved_error, "mincore_or_munmap", start);
    if (fstat(fd, &after) != 0)
        return unknown(r, errno, "post_fstat", start);
    if (before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_size != after.st_size || AF_FILE_MTIME_SEC(before) != AF_FILE_MTIME_SEC(after) ||
        AF_FILE_MTIME_NSEC(before) != AF_FILE_MTIME_NSEC(after))
        return unknown(r, EAGAIN, "file_changed_during_probe", start);
    r->known = 1;
    r->reason = "ok";
    r->resident_fraction = weighted_resident / weighted_sample;
    r->io_fraction = 1.0 - r->resident_fraction;
    r->elapsed_ns = monotonic_ns() - start;
    return 1;
}
