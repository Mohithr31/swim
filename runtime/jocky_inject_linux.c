/*
 * ============================================================
 * JOCKY EXPERIMENTAL / RESEARCH-ONLY COMPONENT
 * ============================================================
 * STATUS : NON-OPERATIONAL — NOT COMPILED IN PRODUCTION BUILDS
 * PURPOSE: Academic reference implementation for defensive
 *          forensic research only.
 *
 * This file is NOT invoked by tools/build_jocky.py or any
 * production build path. It must NOT be shipped in release
 * packages without explicit review.
 *
 * Review required before any operational use:
 *   see docs/DEPLOYMENT.md §12 "Security Notes"
 * ============================================================
 */
/*
 * jocky_inject_linux.c
 * ---------------------
 * JOCKY Linux ptrace-based process injector and memory forensics engine.
 *
 * HOW ptrace WORKS:
 *
 *   ptrace is a Linux kernel facility for process inspection and control.
 *   It is the foundation of every debugger and syscall tracer on Linux.
 *
 *   PTRACE_ATTACH    → stop target process, give us control
 *   PTRACE_PEEKDATA  → read 8 bytes from target's virtual address space
 *   PTRACE_POKEDATA  → write 8 bytes into target's virtual address space
 *   PTRACE_GETREGS   → read target's CPU registers (RIP, RSP, RAX, etc.)
 *   PTRACE_SETREGS   → write target's CPU registers
 *   PTRACE_CONT      → resume target process
 *   PTRACE_DETACH    → release target, restore normal execution
 *
 * HOW INJECTION WORKS (same as gdb breakpoints):
 *
 *   1. PTRACE_ATTACH  → stop target
 *   2. PTRACE_GETREGS → save RIP (instruction pointer) and all registers
 *   3. Find executable region in target's address space
 *   4. PTRACE_PEEKDATA → save original bytes at that address
 *   5. PTRACE_POKEDATA → write our stub (shellcode) at that address
 *   6. PTRACE_SETREGS  → set RIP = our stub address
 *   7. PTRACE_CONT     → target runs our stub
 *   8. Wait for SIGTRAP (our stub ends with int3 = 0xCC)
 *   9. PTRACE_SETREGS  → restore original registers
 *  10. PTRACE_POKEDATA → restore original bytes
 *  11. PTRACE_DETACH   → target resumes normally, unaware we were there
 *
 * NET EFFECT ON TARGET: zero. Bytes restored. Registers restored.
 * This is IDENTICAL to how gdb sets and clears a breakpoint.
 *
 * MEMORY READING (simpler, no ptrace needed):
 *   We can read a process's memory by opening /proc/PID/mem
 *   and seeking to the address we want.
 *   This is what Volatility and memory forensics tools do.
 *   Root or PTRACE_ATTACH required for non-child processes.
 *
 * COMPILE:
 *   gcc -O2 -o test_inject_linux test_inject_linux.c jocky_inject_linux.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>       /* struct user_regs_struct */
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

/* Include after system headers to avoid type conflicts */
#include "jocky_inject_linux.h"
#include "jocky_syscall_linux.h"

/* ════════════════════════════════════════════════════════════════
 * INTERNAL HELPERS
 * ════════════════════════════════════════════════════════════════ */

static void log_inj(const char *tag, const char *msg) {
    printf("[jocky-inject] [%s] %s\n", tag, msg);
}

static void log_inj_fmt(const char *tag, const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    printf("[jocky-inject] [%s] %s\n", tag, buf);
}

/* ════════════════════════════════════════════════════════════════
 * PROCESS DISCOVERY
 * Uses direct syscalls (our stealth layer) to enumerate /proc
 * ════════════════════════════════════════════════════════════════ */

/*
 * jocky_find_target_process
 * Finds the PID of a running process by name.
 * Uses direct syscall getdents64 to read /proc.
 * Returns JINJ_OK on success, pid written to *out_pid.
 */
int jocky_find_target_process(const char *name, pid_t *out_pid) {
    static char dents_buf[4096];
    static char comm_buf[256];
    static char path_buf[64];

    int dir_fd = jocky_open("/proc", SC_O_RDONLY | SC_O_DIRECTORY);
    if (dir_fd < 0) return JINJ_ERR_MAPS;

    long bytes;
    while ((bytes = jocky_getdents64(dir_fd,
                (struct jocky_dirent64 *)dents_buf,
                sizeof(dents_buf))) > 0) {
        long off = 0;
        while (off < bytes) {
            struct jocky_dirent64 *d =
                (struct jocky_dirent64 *)(dents_buf + off);

            /* Only numeric entries are PIDs */
            int is_pid = 1;
            for (int i = 0; d->d_name[i]; i++)
                if (d->d_name[i] < '0' || d->d_name[i] > '9')
                    { is_pid = 0; break; }

            if (is_pid && d->d_name[0]) {
                /* Read /proc/PID/comm */
                jocky_strcpy(path_buf, "/proc/");
                jocky_strcat(path_buf, d->d_name);
                jocky_strcat(path_buf, "/comm");

                int fd = jocky_open(path_buf, SC_O_RDONLY);
                if (fd >= 0) {
                    long n = jocky_read(fd, comm_buf, sizeof(comm_buf)-1);
                    jocky_close(fd);
                    if (n > 0) {
                        /* strip newline */
                        for (int i = 0; i < n; i++)
                            if (comm_buf[i] == '\n') { comm_buf[i]=0; break; }
                        comm_buf[n] = 0;

                        if (strcmp(comm_buf, name) == 0) {
                            *out_pid = (pid_t)atoi(d->d_name);
                            jocky_close(dir_fd);
                            return JINJ_OK;
                        }
                    }
                }
            }
            off += d->d_reclen;
        }
    }
    jocky_close(dir_fd);
    return JINJ_ERR_NOTFOUND;
}

/* ════════════════════════════════════════════════════════════════
 * MEMORY MAP PARSING
 * Reads /proc/PID/maps to understand the target's address space.
 * Essential for finding: executable regions, heap, stack, libs.
 * ════════════════════════════════════════════════════════════════ */

/*
 * jocky_snapshot_process
 * Reads all available information about a process:
 *   - Name, exe path, cmdline
 *   - Full memory map (regions, permissions, file mappings)
 */
int jocky_snapshot_process(pid_t pid, jocky_proc_t *out) {
    static char buf[65536];
    static char path[64];
    static char tmp[32];

    memset(out, 0, sizeof(*out));
    out->pid = pid;

    /* Read /proc/PID/comm */
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        int n = read(fd, out->name, sizeof(out->name)-1);
        if (n > 0) {
            out->name[n] = 0;
            for (int i = 0; i < n; i++)
                if (out->name[i] == '\n') { out->name[i]=0; break; }
        }
        close(fd);
    }

    /* Read /proc/PID/exe via readlink */
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    ssize_t rn = readlink(path, out->exe, sizeof(out->exe)-1);
    if (rn > 0) out->exe[rn] = 0;

    /* Read /proc/PID/cmdline */
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    fd = open(path, O_RDONLY);
    if (fd >= 0) {
        int n = read(fd, out->cmdline, sizeof(out->cmdline)-1);
        close(fd);
        if (n > 0) {
            /* replace nulls with spaces for display */
            for (int i = 0; i < n-1; i++)
                if (out->cmdline[i] == 0) out->cmdline[i] = ' ';
            out->cmdline[n] = 0;
        }
    }

    /* Parse /proc/PID/maps */
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    fd = open(path, O_RDONLY);
    if (fd < 0) return JINJ_ERR_MAPS;

    int  n    = read(fd, buf, sizeof(buf)-1);
    close(fd);
    if (n <= 0) return JINJ_ERR_MAPS;
    buf[n] = 0;

    /* Parse each line:
     * 7f3a2b000000-7f3a2c000000 r-xp 00000000 08:01 12345  /lib/x86_64.../libc.so */
    char *line = buf;
    out->region_count = 0;

    while (*line && out->region_count < JOCKY_MAX_REGIONS) {
        jocky_region_t *r = &out->regions[out->region_count];
        memset(r, 0, sizeof(*r));

        /* Parse start-end */
        char *dash = strchr(line, '-');
        if (!dash) break;
        *dash = 0;
        r->start = strtoul(line, NULL, 16);
        line = dash + 1;

        char *space = strchr(line, ' ');
        if (!space) break;
        *space = 0;
        r->end = strtoul(line, NULL, 16);
        line = space + 1;

        /* Parse permissions: rwxp */
        strncpy(r->perms, line, 4);
        r->perms[4] = 0;
        r->is_executable = (r->perms[2] == 'x');
        r->is_writable   = (r->perms[1] == 'w');
        r->is_anonymous  = 1; /* will be set to 0 if path found */

        /* Skip to path (after offset, dev, inode) */
        space = strchr(line, '\n');
        if (!space) break;

        /* Find the path — it's after the 5th field */
        char *p = line;
        int fields = 0;
        while (*p && *p != '\n') {
            if (*p == ' ') {
                while (*p == ' ') p++;
                fields++;
                if (fields == 4) {
                    /* skip trailing spaces */
                    while (*p == ' ') p++;
                    if (*p && *p != '\n') {
                        /* this is the path */
                        int pi = 0;
                        while (*p && *p != '\n' && pi < 255)
                            r->path[pi++] = *p++;
                        r->path[pi] = 0;
                        r->is_anonymous = (r->path[0] == 0 ||
                                           r->path[0] == '[');
                    }
                    break;
                }
            } else {
                p++;
            }
        }

        out->region_count++;
        line = space + 1;
    }

    return JINJ_OK;
}

/* ════════════════════════════════════════════════════════════════
 * MEMORY READING via /proc/PID/mem
 * Reads target process memory without needing PTRACE_PEEKDATA.
 * Much faster for large reads (PEEKDATA is 8 bytes at a time).
 * Requires: root OR ptrace_scope=0 OR PTRACE_ATTACH first.
 * ════════════════════════════════════════════════════════════════ */

long jocky_read_process_mem(pid_t pid, unsigned long addr,
                             void *buf, size_t len) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    off_t pos = lseek(fd, (off_t)addr, SEEK_SET);
    if (pos == (off_t)-1) { close(fd); return -1; }

    long n = read(fd, buf, len);
    close(fd);
    return n;
}

/* ════════════════════════════════════════════════════════════════
 * IOC SCANNING
 * Scans a process's memory regions for Indicators of Compromise.
 * Examples:
 *   - Known C2 domain strings
 *   - Shellcode patterns (e.g. \x4d\x5a = MZ header in heap = reflective loader)
 *   - Base64-encoded config blocks
 *   - XOR keys or crypto constants
 * ════════════════════════════════════════════════════════════════ */

/* Default IOC patterns to search for */
static const char *DEFAULT_IOCS[] = {
    /* Shellcode indicators */
    "\x4d\x5a",             /* MZ header in unexpected region = PE in memory */

    /* Common C2 patterns */
    "cmd.exe",
    "powershell",
    "/bin/sh",
    "wget ",
    "curl ",
    "nc -",
    "bash -i",
    "python -c",

    /* Crypto mining */
    "stratum+tcp",
    "xmrig",

    /* Suspicious strings */
    "reverse_shell",
    "backdoor",
    "/tmp/.x",
    "/dev/shm/",

    /* Base64 encoded /bin/sh */
    "L2Jpbi9zaA==",

    NULL
};

int jocky_scan_for_iocs(pid_t pid, jocky_proc_t *proc,
                          const char **patterns, int pattern_count,
                          jocky_scan_result_t *out) {
    if (!out) return JINJ_ERR_NOMEM;
    memset(out, 0, sizeof(*out));

    if (!patterns || pattern_count <= 0) {
        patterns      = DEFAULT_IOCS;
        pattern_count = 0;
        while (DEFAULT_IOCS[pattern_count]) pattern_count++;
    }

    /* Scan each readable memory region */
    static char mem_buf[65536];

    for (int ri = 0; ri < proc->region_count; ri++) {
        jocky_region_t *region = &proc->regions[ri];

        /* Skip kernel/special regions */
        if (strstr(region->path, "[vdso]"))   continue;
        if (strstr(region->path, "[vsyscall]")) continue;

        /* Skip execute-only regions (not interesting for strings) */
        if (!region->is_writable && !region->is_anonymous
            && !region->is_executable) continue;

        unsigned long addr = region->start;
        unsigned long end  = region->end;

        /* Read in 64KB chunks */
        while (addr < end && out->count < JOCKY_MAX_HITS) {
            size_t chunk = sizeof(mem_buf);
            if (addr + chunk > end) chunk = end - addr;

            long n = jocky_read_process_mem(pid, addr, mem_buf, chunk);
            if (n <= 0) { addr += chunk; continue; }

            /* Scan for each IOC pattern in this chunk */
            for (int pi = 0; pi < pattern_count; pi++) {
                const char *pat    = patterns[pi];
                size_t      patlen = strlen(pat);
                if (patlen == 0) continue;

                /* Simple byte search */
                for (long i = 0; i <= n - (long)patlen; i++) {
                    if (memcmp(mem_buf + i, pat, patlen) == 0) {
                        if (out->count >= JOCKY_MAX_HITS) break;

                        jocky_ioc_hit_t *hit = &out->hits[out->count++];
                        hit->addr = addr + i;
                        snprintf(hit->match, sizeof(hit->match),
                                 "%s", pat[0] < 32 ? "(binary pattern)" : pat);

                        /* Capture surrounding bytes as hex */
                        int ctx_start = (i > 8) ? i - 8 : 0;
                        int ctx_len   = 16;
                        if (ctx_start + ctx_len > n)
                            ctx_len = n - ctx_start;
                        char *cp = hit->context;
                        for (int ci = 0; ci < ctx_len; ci++) {
                            snprintf(cp, 4, "%02x ",
                                     (unsigned char)mem_buf[ctx_start + ci]);
                            cp += 3;
                        }
                    }
                }
            }
            addr += n;
        }
    }
    return JINJ_OK;
}

/* ════════════════════════════════════════════════════════════════
 * ptrace ATTACH / DETACH
 * ════════════════════════════════════════════════════════════════ */

/*
 * jocky_attach
 * Attaches to target process using PTRACE_ATTACH.
 * This stops the target and gives us full control.
 * We save the injection context for later restore.
 */
int jocky_attach(jocky_inject_ctx_t *ctx, pid_t pid) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->target_pid = pid;

    log_inj_fmt("ATTACH", "attaching to pid=%d via ptrace", pid);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("[jocky-inject] ptrace ATTACH");
        return JINJ_ERR_ATTACH;
    }

    /* Wait for target to stop */
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("[jocky-inject] waitpid");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return JINJ_ERR_ATTACH;
    }

    if (!WIFSTOPPED(status)) {
        log_inj("ATTACH", "target did not stop as expected");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return JINJ_ERR_ATTACH;
    }

    ctx->attached = 1;
    log_inj_fmt("ATTACH", "attached — target stopped (signal %d)",
                WSTOPSIG(status));
    return JINJ_OK;
}

/*
 * jocky_detach
 * Restores original bytes if injection happened, then detaches.
 * Target resumes exactly where it was — no trace of our presence.
 */
int jocky_detach(jocky_inject_ctx_t *ctx) {
    if (!ctx->attached) return JINJ_OK;

    pid_t pid = ctx->target_pid;

    /* Restore original bytes if we injected */
    if (ctx->inject_addr && ctx->saved_len > 0) {
        log_inj("DETACH", "restoring original bytes");

        for (int i = 0; i < ctx->saved_len; i += 8) {
            long word = 0;
            int  copy = (ctx->saved_len - i < 8) ?
                         ctx->saved_len - i : 8;
            memcpy(&word, ctx->saved_bytes + i, copy);

            if (ptrace(PTRACE_POKEDATA, pid,
                       (void *)(ctx->inject_addr + i),
                       (void *)word) < 0) {
                log_inj("DETACH", "WARNING: byte restore failed");
            }
        }
        ctx->inject_addr = 0;
        ctx->saved_len   = 0;
    }

    /* Resume and detach */
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    ctx->attached = 0;
    log_inj_fmt("DETACH", "detached from pid=%d — target resumed", pid);
    return JINJ_OK;
}

/* ════════════════════════════════════════════════════════════════
 * INJECTION ENGINE
 * Injects a shellcode stub into the target process, executes it,
 * then restores original state.
 * Identical mechanism to how gdb sets breakpoints.
 * ════════════════════════════════════════════════════════════════ */

/*
 * jocky_inject_stub
 *
 * Finds a suitable executable region in the target,
 * writes our stub there, redirects execution to it,
 * waits for it to complete (SIGTRAP via int3),
 * reads the return value from RAX,
 * restores everything.
 */
int jocky_inject_stub(jocky_inject_ctx_t *ctx,
                       unsigned char *shellcode, size_t len,
                       unsigned long *out_ret) {
    if (!ctx->attached) return JINJ_ERR_ATTACH;
    if (len > 56) return JINJ_ERR_NOMEM; /* keep it small */

    pid_t pid = ctx->target_pid;

    /* Step 1: Save current register state */
    struct user_regs_struct regs_saved, regs_run;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs_saved) < 0) {
        perror("[jocky-inject] GETREGS");
        return JINJ_ERR_GETREGS;
    }
    log_inj_fmt("INJECT", "saved RIP=0x%llx RSP=0x%llx",
                (unsigned long long)regs_saved.rip,
                (unsigned long long)regs_saved.rsp);

    /* Step 2: Find an executable writable memory region
     * We prefer the text segment of the target (already executable).
     * We write there temporarily — restore immediately after.
     * RIP currently points to executable code — use that address. */
    unsigned long inject_addr = regs_saved.rip;
    ctx->inject_addr = inject_addr;

    log_inj_fmt("INJECT", "injection address=0x%lx", inject_addr);

    /* Step 3: Save original bytes at injection site */
    int words = (len + 7) / 8;
    ctx->saved_len = words * 8;
    if (ctx->saved_len > (int)sizeof(ctx->saved_bytes))
        ctx->saved_len = sizeof(ctx->saved_bytes);

    for (int i = 0; i < words; i++) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid,
                           (void *)(inject_addr + i*8), NULL);
        if (errno) {
            log_inj_fmt("INJECT", "PEEKDATA failed at 0x%lx",
                        inject_addr + i*8);
            return JINJ_ERR_PEEK;
        }
        memcpy(ctx->saved_bytes + i*8, &word,
               sizeof(word));
    }
    log_inj_fmt("INJECT", "saved %d bytes of original code",
                ctx->saved_len);

    /* Step 4: Append int3 (0xCC) breakpoint after shellcode
     * so we know when it finishes executing */
    unsigned char stub[64];
    memset(stub, 0x90, sizeof(stub)); /* NOP sled */
    memcpy(stub, shellcode, len);
    stub[len] = 0xCC;                 /* int3 — SIGTRAP on completion */

    /* Step 5: Write stub into target memory via PTRACE_POKEDATA */
    for (int i = 0; i < words; i++) {
        long word = 0;
        memcpy(&word, stub + i*8, sizeof(word));
        if (ptrace(PTRACE_POKEDATA, pid,
                   (void *)(inject_addr + i*8),
                   (void *)word) < 0) {
            log_inj("INJECT", "POKEDATA failed");
            return JINJ_ERR_POKE;
        }
    }
    log_inj_fmt("INJECT", "stub written (%zu bytes) to 0x%lx",
                len + 1, inject_addr);

    /* Step 6: Set RIP to our stub */
    memcpy(&regs_run, &regs_saved, sizeof(regs_run));
    regs_run.rip = inject_addr;

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs_run) < 0) {
        log_inj("INJECT", "SETREGS failed");
        return JINJ_ERR_SETREGS;
    }

    /* Step 7: Resume target — it will execute our stub */
    log_inj("INJECT", "resuming target to execute stub...");
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    /* Step 8: Wait for SIGTRAP (our int3 fired = stub completed) */
    int status;
    waitpid(pid, &status, 0);

    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        log_inj("INJECT", "stub execution complete (SIGTRAP received)");
    } else {
        log_inj_fmt("INJECT", "unexpected stop signal=%d", WSTOPSIG(status));
    }

    /* Step 9: Read return value from RAX */
    struct user_regs_struct regs_after;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs_after);
    if (out_ret) *out_ret = (unsigned long)regs_after.rax;
    log_inj_fmt("INJECT", "stub returned RAX=0x%llx",
                (unsigned long long)regs_after.rax);

    /* Step 10: Restore original registers (RIP back to where it was) */
    ptrace(PTRACE_SETREGS, pid, NULL, &regs_saved);

    /* Step 11: Restore original bytes */
    for (int i = 0; i < words; i++) {
        long word = 0;
        memcpy(&word, ctx->saved_bytes + i*8, sizeof(word));
        ptrace(PTRACE_POKEDATA, pid,
               (void *)(inject_addr + i*8),
               (void *)word);
    }
    ctx->inject_addr = 0;
    ctx->saved_len   = 0;

    log_inj("INJECT", "original code restored — target unchanged");
    return JINJ_OK;
}

/* ════════════════════════════════════════════════════════════════
 * HIGH-LEVEL FORENSIC FUNCTIONS
 * These combine the above primitives into useful forensic actions.
 * ════════════════════════════════════════════════════════════════ */

/*
 * jocky_inspect_process_memory
 * Reads a process's memory map and scans for IOCs.
 * Does NOT inject — purely read-only via /proc/PID/mem.
 * Requires ptrace_scope=0 or running as root.
 */
void jocky_inspect_process_memory(pid_t pid) {
    jocky_proc_t proc;

    printf("[jocky-inject] --- memory inspection pid=%d ---\n", pid);

    if (jocky_snapshot_process(pid, &proc) != JINJ_OK) {
        printf("[jocky-inject] ERROR: cannot snapshot process\n");
        return;
    }

    printf("[jocky-inject] name=%s\n",    proc.name);
    printf("[jocky-inject] exe=%s\n",     proc.exe);
    printf("[jocky-inject] cmdline=%s\n", proc.cmdline);
    printf("[jocky-inject] regions=%d\n", proc.region_count);

    /* Print interesting regions */
    for (int i = 0; i < proc.region_count; i++) {
        jocky_region_t *r = &proc.regions[i];
        unsigned long size = r->end - r->start;

        /* Highlight suspicious combinations */
        const char *flag = "";
        if (r->is_executable && r->is_writable)
            flag = " *** RWX — SUSPICIOUS ***";
        else if (r->is_executable && r->is_anonymous)
            flag = " *** exec+anon — possible injected code ***";

        if (r->is_executable || r->is_anonymous || r->path[0]) {
            printf("[jocky-inject] region 0x%lx-0x%lx %s sz=0x%lx path=%s%s\n",
                   r->start, r->end, r->perms, size,
                   r->path[0] ? r->path : "(anonymous)",
                   flag);
        }
    }

    /* IOC scan */
    printf("[jocky-inject] --- IOC scan ---\n");
    jocky_scan_result_t results;

    if (jocky_scan_for_iocs(pid, &proc, NULL, 0, &results) == JINJ_OK) {
        if (results.count == 0) {
            printf("[jocky-inject] no IOC matches found\n");
        } else {
            printf("[jocky-inject] FOUND %d IOC matches:\n", results.count);
            for (int i = 0; i < results.count; i++) {
                printf("[jocky-inject] IOC addr=0x%lx match=\"%s\" ctx=%s\n",
                       results.hits[i].addr,
                       results.hits[i].match,
                       results.hits[i].context);
            }
        }
    }

    printf("[jocky-inject] --- end memory inspection ---\n");
}

/*
 * jocky_stealth_inject_and_scan
 * The full stealth sequence:
 *   1. Attach to target
 *   2. Read its memory map
 *   3. Scan for IOCs
 *   4. Inject a minimal stub that calls getpid() (proof of injection)
 *   5. Detach cleanly
 * After step 5 the target is IDENTICAL to before we touched it.
 */
void jocky_stealth_inject_and_scan(pid_t target_pid) {
    printf("[jocky-inject] === stealth inject+scan on pid=%d ===\n",
           target_pid);

    /* Step A: Read memory map (no ptrace needed if /proc/mem accessible) */
    jocky_inspect_process_memory(target_pid);

    /* Step B: Full injection demo */
    printf("[jocky-inject] --- injection test ---\n");

    jocky_inject_ctx_t ctx;
    if (jocky_attach(&ctx, target_pid) != JINJ_OK) {
        printf("[jocky-inject] attach failed — need root or ptrace_scope=0\n");
        printf("[jocky-inject] try: echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope\n");
        return;
    }

    /*
     * Minimal x86-64 shellcode: call getpid() → return pid in RAX.
     *
     *   mov rax, 39      ; SYS_getpid = 39
     *   syscall
     *   (int3 appended by jocky_inject_stub)
     *
     * This is the SIMPLEST possible stub — just calls getpid()
     * and returns. Proves injection works end-to-end.
     * In a real JOCKY deployment this would be the forensic
     * collection stub that reads memory from inside the process.
     */
    unsigned char getpid_stub[] = {
        0x48, 0xC7, 0xC0, 0x27, 0x00, 0x00, 0x00,  /* mov rax, 39 (SYS_getpid) */
        0x0F, 0x05,                                  /* syscall                  */
    };

    unsigned long ret_val = 0;
    int rc = jocky_inject_stub(&ctx,
                                getpid_stub, sizeof(getpid_stub),
                                &ret_val);

    if (rc == JINJ_OK) {
        printf("[jocky-inject] INJECTION SUCCESS\n");
        printf("[jocky-inject] stub ran inside pid=%d\n", target_pid);
        printf("[jocky-inject] stub called getpid() → returned %lu\n", ret_val);
        printf("[jocky-inject] (matches target PID = proof of execution)\n");
    } else {
        printf("[jocky-inject] injection failed rc=%d\n", rc);
    }

    /* Step C: Detach — target is completely restored */
    jocky_detach(&ctx);

    printf("[jocky-inject] === complete — target unchanged ===\n");
}

/*
 * jocky_find_and_inject
 * Find a target process by name then inject.
 * This is the main entry point for stealth JOCKY operation.
 */
void jocky_find_and_inject(const char *target_name) {
    printf("[jocky-inject] looking for target process: %s\n", target_name);

    pid_t pid;
    int rc = jocky_find_target_process(target_name, &pid);

    if (rc != JINJ_OK) {
        printf("[jocky-inject] process '%s' not found\n", target_name);
        return;
    }

    printf("[jocky-inject] found target pid=%d name=%s\n", pid, target_name);
    jocky_stealth_inject_and_scan(pid);
}
