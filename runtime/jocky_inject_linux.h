/*
 * jocky_inject_linux.h
 * ---------------------
 * JOCKY Linux process injection API.
 *
 * WHAT THIS IS:
 *   ptrace-based process memory inspector and stealth injector.
 *   This is the same mechanism used by:
 *     gdb        — sets breakpoints by writing 0xCC into target memory
 *     strace     — intercepts syscalls via PTRACE_SYSCALL
 *     Valgrind   — reads/writes target memory for analysis
 *     JOCKY      — reads target memory for forensic evidence
 *
 * WHY WE NEED THIS FOR JOCKY:
 *   Without injection, the JOCKY agent reads what the kernel
 *   exposes via /proc. A sophisticated rootkit can hide from /proc.
 *
 *   With injection, we run inside a trusted process (e.g. apache2).
 *   From inside that process we can:
 *     - Read heap memory (find hidden malware strings/configs)
 *     - Access memory-mapped files the process has open
 *     - Scan for IOCs (Indicators of Compromise) from inside
 *     - Appear as a thread of that trusted process to any monitor
 *
 * TWO MODES:
 *   1. INSPECT mode  — attach, read memory, detach (read-only, forensic)
 *   2. INJECT  mode  — attach, inject stub, run in target context, detach
 *
 * FORENSIC SCOPE:
 *   Inspect mode: 100% read-only. No modification of target.
 *   Inject  mode: writes a temporary stub, restores original bytes after.
 *                 Net effect on target = zero (clean restore).
 *                 This is exactly how gdb breakpoints work.
 */

#ifndef JOCKY_INJECT_LINUX_H
#define JOCKY_INJECT_LINUX_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

/* ── Return codes ────────────────────────────────────────────── */
#define JINJ_OK            0
#define JINJ_ERR_ATTACH   -1
#define JINJ_ERR_PEEK     -2
#define JINJ_ERR_POKE     -3
#define JINJ_ERR_GETREGS  -4
#define JINJ_ERR_SETREGS  -5
#define JINJ_ERR_NOMEM    -6
#define JINJ_ERR_MAPS     -7
#define JINJ_ERR_NOTFOUND -8

/* ── Memory region from /proc/PID/maps ───────────────────────── */
#define JOCKY_MAX_REGIONS 512

typedef struct {
    unsigned long start;
    unsigned long end;
    char          perms[8];       /* rwxp or similar */
    unsigned long offset;
    char          path[256];      /* mapped file or [heap]/[stack] */
    int           is_executable;
    int           is_writable;
    int           is_anonymous;
} jocky_region_t;

/* ── Process snapshot ────────────────────────────────────────── */
typedef struct {
    pid_t          pid;
    char           name[256];
    char           exe[512];
    char           cmdline[1024];
    jocky_region_t regions[JOCKY_MAX_REGIONS];
    int            region_count;
} jocky_proc_t;

/* ── Injection context ───────────────────────────────────────── */
typedef struct {
    pid_t          target_pid;
    int            attached;
    unsigned long  inject_addr;   /* where we wrote our stub */
    unsigned char  saved_bytes[64]; /* original bytes we overwrote */
    int            saved_len;
} jocky_inject_ctx_t;

/* ── IOC scan result ─────────────────────────────────────────── */
typedef struct {
    unsigned long addr;
    char          match[128];     /* what was found */
    char          context[64];    /* surrounding bytes (hex) */
} jocky_ioc_hit_t;

#define JOCKY_MAX_HITS 256

typedef struct {
    jocky_ioc_hit_t hits[JOCKY_MAX_HITS];
    int             count;
} jocky_scan_result_t;

/* ── Public API ──────────────────────────────────────────────── */

/* Process discovery */
int  jocky_find_target_process(const char *name, pid_t *out_pid);
int  jocky_snapshot_process(pid_t pid, jocky_proc_t *out);

/* Memory reading (inspect mode — read only, no ptrace needed for /proc/mem) */
long jocky_read_process_mem(pid_t pid, unsigned long addr,
                             void *buf, size_t len);

/* Memory region scanning */
int  jocky_scan_for_iocs(pid_t pid, jocky_proc_t *proc,
                          const char **patterns, int pattern_count,
                          jocky_scan_result_t *out);

/* Full forensic memory dump of a region */
int  jocky_dump_region(pid_t pid, jocky_region_t *region,
                        const char *out_path);

/* ptrace attach/detach */
int  jocky_attach(jocky_inject_ctx_t *ctx, pid_t pid);
int  jocky_detach(jocky_inject_ctx_t *ctx);

/* Injection (inject mode — writes stub, executes, restores) */
int  jocky_inject_stub(jocky_inject_ctx_t *ctx,
                        unsigned char *shellcode, size_t len,
                        unsigned long *out_ret);

/* High-level forensic functions */
void jocky_stealth_inject_and_scan(pid_t target_pid);
void jocky_inspect_process_memory(pid_t pid);
void jocky_find_and_inject(const char *target_name);

#endif /* JOCKY_INJECT_LINUX_H */
