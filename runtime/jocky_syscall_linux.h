/*
 * jocky_syscall_linux.h
 * ---------------------
 * Direct Linux syscall interface for JOCKY forensic runtime.
 *
 * PURPOSE:
 *   Security tools (Wazuh, AIDE, LD_PRELOAD monitors) hook standard
 *   libc functions: fopen(), opendir(), readdir(), fread(), popen() etc.
 *   By issuing raw syscalls we bypass every user-space hook entirely.
 *   The kernel is called directly — no libc, no hook, no detection.
 *
 * SCOPE:
 *   Read-only forensic operations only.
 *   No process modification, no injection, no privilege escalation.
 *   Equivalent to reading /proc — just unhooked.
 */

#ifndef JOCKY_SYSCALL_LINUX_H
#define JOCKY_SYSCALL_LINUX_H

#include <stdint.h>
#include <stddef.h>

/* ── Syscall numbers (x86-64 Linux) ──────────────────────────── */
#define SC_READ        0
#define SC_WRITE       1
#define SC_OPEN        2
#define SC_CLOSE       3
#define SC_STAT        4
#define SC_LSEEK       8
#define SC_MMAP        9
#define SC_MUNMAP      11
#define SC_GETDENTS64  217
#define SC_OPENAT      257
#define SC_GETPID      39
#define SC_GETTID      186

/* ── Open flags ──────────────────────────────────────────────── */
#define SC_O_RDONLY    0
#define SC_O_DIRECTORY 0200000
#define SC_AT_FDCWD    (-100)

/* ── dirent64 structure (kernel layout) ──────────────────────── */
struct jocky_dirent64 {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[256];
};

#ifndef DT_DIR
#define DT_DIR  4
#endif
#ifndef DT_LNK
#define DT_LNK  10
#endif
#ifndef DT_REG
#define DT_REG  8
#endif

/* ── Raw syscall wrappers using inline assembly ──────────────── */

/*
 * jocky_sc0 — syscall with no arguments
 */
static inline long jocky_sc0(long nr) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(nr)
        : "rcx", "r11", "memory"
    );
    return ret;
}

/*
 * jocky_sc1 — syscall with 1 argument
 */
static inline long jocky_sc1(long nr, long a1) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(nr), "D"(a1)
        : "rcx", "r11", "memory"
    );
    return ret;
}

/*
 * jocky_sc2 — syscall with 2 arguments
 */
static inline long jocky_sc2(long nr, long a1, long a2) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(nr), "D"(a1), "S"(a2)
        : "rcx", "r11", "memory"
    );
    return ret;
}

/*
 * jocky_sc3 — syscall with 3 arguments
 */
static inline long jocky_sc3(long nr, long a1, long a2, long a3) {
    long ret;
    register long r10 __asm__("r10") = a3;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(nr), "D"(a1), "S"(a2), "d"(a3)
        : "rcx", "r11", "memory"
    );
    (void)r10;
    return ret;
}

/*
 * jocky_sc6 — syscall with 6 arguments (used for mmap)
 */
static inline long jocky_sc6(long nr, long a1, long a2, long a3,
                               long a4, long a5, long a6) {
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    register long r9  __asm__("r9")  = a6;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(nr), "D"(a1), "S"(a2), "d"(a3),
          "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}

/* ── Convenience wrappers ─────────────────────────────────────── */

static inline int jocky_open(const char *path, int flags) {
    return (int)jocky_sc2(SC_OPEN, (long)path, (long)flags);
}

static inline int jocky_close(int fd) {
    return (int)jocky_sc1(SC_CLOSE, (long)fd);
}

static inline long jocky_read(int fd, void *buf, size_t count) {
    return jocky_sc3(SC_READ, (long)fd, (long)buf, (long)count);
}

static inline long jocky_write(int fd, const void *buf, size_t count) {
    return jocky_sc3(SC_WRITE, (long)fd, (long)buf, (long)count);
}

static inline long jocky_getdents64(int fd, struct jocky_dirent64 *buf,
                                     unsigned int count) {
    return jocky_sc3(SC_GETDENTS64, (long)fd, (long)buf, (long)count);
}

/* ── Direct write to stdout (no libc at all) ─────────────────── */
static inline void jocky_puts_raw(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    jocky_write(1, s, len);
}

/* ── Simple int to string (no libc sprintf) ──────────────────── */
static inline void jocky_itoa(long v, char *buf, int base) {
    char tmp[32];
    int  i = 0, neg = 0;
    if (v < 0) { neg = 1; v = -v; }
    if (v == 0) { buf[0] = '0'; buf[1] = 0; return; }
    while (v > 0) {
        int r = v % base;
        tmp[i++] = (r < 10) ? ('0' + r) : ('a' + r - 10);
        v /= base;
    }
    if (neg) tmp[i++] = '-';
    int j = 0;
    while (i > 0) buf[j++] = tmp[--i];
    buf[j] = 0;
}

/* ── String helpers (no libc) ────────────────────────────────── */
static inline int jocky_strcmp(const char *a, const char *b) {
    while (*a && (*a == *b)) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static inline int jocky_isdigit(char c) {
    return c >= '0' && c <= '9';
}

static inline void jocky_strcpy(char *dst, const char *src) {
    while ((*dst++ = *src++));
}

static inline void jocky_strcat(char *dst, const char *src) {
    while (*dst) dst++;
    while ((*dst++ = *src++));
}

static inline size_t jocky_strlen(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

#endif /* JOCKY_SYSCALL_LINUX_H */
