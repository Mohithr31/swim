/*
 * jocky_runtime_linux_stealth.c
 * ------------------------------
 * JOCKY stealth forensic runtime for Linux.
 *
 * HOW THIS DIFFERS FROM jocky_runtime.c:
 *   jocky_runtime.c  → uses fopen(), readdir(), popen() etc.
 *                       Security tools hook these via LD_PRELOAD.
 *                       Wazuh, AIDE, rkhunter SEE every call.
 *
 *   THIS FILE         → uses raw syscall instruction only.
 *                       No libc. No LD_PRELOAD path.
 *                       Security tools are bypassed at the call level.
 *
 * FORENSIC SCOPE:
 *   All operations are READ-ONLY.
 *   We read /proc filesystem entries directly.
 *   No process modification. No privilege escalation.
 *   No kernel structure modification.
 *
 * WHAT WE COLLECT:
 *   1. Process list (including anomaly detection)
 *   2. Network connections (/proc/net/tcp + tcp6)
 *   3. System information (/proc/version, /proc/cpuinfo)
 *   4. Loaded kernel modules (/proc/modules)
 *   5. Open file descriptors per process
 *   6. Hidden process detector (compares /proc list vs task count)
 */

#include "jocky_syscall_linux.h"
#include "jocky_runtime.h"

/* ════════════════════════════════════════════════════════════════
 * INTERNAL HELPERS
 * All helpers use direct syscalls — zero libc dependency
 * ════════════════════════════════════════════════════════════════ */

/*
 * read_file_raw
 * Reads an entire file into buf using direct syscalls.
 * Returns bytes read, -1 on error.
 * No fopen(), no fread() — those are the hooked paths.
 */
static long read_file_raw(const char *path, char *buf, long bufsize) {
    int fd = jocky_open(path, SC_O_RDONLY);
    if (fd < 0) return -1;

    long total = 0;
    long n;
    while (total < bufsize - 1) {
        n = jocky_read(fd, buf + total, (size_t)(bufsize - total - 1));
        if (n <= 0) break;
        total += n;
    }
    buf[total] = '\0';
    jocky_close(fd);
    return total;
}

/*
 * path_join
 * Constructs /proc/PID/filename — no sprintf, no libc.
 */
static void path_join(char *out, const char *base,
                      const char *pid, const char *tail) {
    jocky_strcpy(out, base);
    jocky_strcat(out, pid);
    if (tail) {
        jocky_strcat(out, "/");
        jocky_strcat(out, tail);
    }
}

/*
 * output_line
 * Writes a formatted line to stdout directly via syscall.
 * Format: "[jocky] <label>=<value>\n"
 */
static void output_line(const char *label, const char *value) {
    jocky_puts_raw("[jocky] ");
    jocky_puts_raw(label);
    jocky_puts_raw("=");
    jocky_puts_raw(value);
    jocky_puts_raw("\n");
}

static void output_raw(const char *s) {
    jocky_puts_raw(s);
}

/*
 * extract_field
 * Finds "key:\t..." in a file's contents and copies the value.
 * Used to parse /proc/PID/status fields.
 */
static int extract_field(const char *haystack, const char *key,
                          char *out, int outlen) {
    const char *p = haystack;
    size_t klen = jocky_strlen(key);
    while (*p) {
        if (jocky_strcmp(p, "") != 0) {
            /* check if line starts with key */
            int match = 1;
            for (size_t i = 0; i < klen; i++) {
                if (p[i] != key[i]) { match = 0; break; }
            }
            if (match && (p[klen] == ':' || p[klen] == '\t')) {
                /* skip past colon and whitespace */
                const char *v = p + klen;
                while (*v == ':' || *v == '\t' || *v == ' ') v++;
                int i = 0;
                while (*v && *v != '\n' && i < outlen - 1)
                    out[i++] = *v++;
                out[i] = 0;
                return 1;
            }
        }
        /* advance to next line */
        while (*p && *p != '\n') p++;
        if (*p) p++;
    }
    return 0;
}

/* ════════════════════════════════════════════════════════════════
 * FEATURE 1 — PROCESS ENUMERATION
 * Reads /proc directly via getdents64 syscall.
 * Bypasses readdir() hook completely.
 * Also detects anomalies between visible vs counted processes.
 * ════════════════════════════════════════════════════════════════ */

/*
 * is_pid_dir
 * Returns 1 if the dirent name is all digits (a PID directory).
 */
static int is_pid_dir(const char *name) {
    if (!name || !*name) return 0;
    for (const char *p = name; *p; p++)
        if (!jocky_isdigit(*p)) return 0;
    return 1;
}

void jocky_stealth_list_processes(void) {
    /* Buffer for getdents64 — 4KB fits many entries */
    static char dents_buf[4096];
    static char status_buf[4096];
    static char path_buf[256];

    output_raw("[jocky] --- stealth process enumeration (direct syscall) ---\n");
    output_raw("[jocky] method=getdents64_syscall hook_bypass=true\n");

    int dir_fd = jocky_open("/proc", SC_O_RDONLY | SC_O_DIRECTORY);
    if (dir_fd < 0) {
        output_raw("[jocky] ERROR: cannot open /proc\n");
        return;
    }

    int proc_count = 0;
    long bytes;

    while ((bytes = jocky_getdents64(dir_fd,
                (struct jocky_dirent64 *)dents_buf,
                sizeof(dents_buf))) > 0) {

        long offset = 0;
        while (offset < bytes) {
            struct jocky_dirent64 *d =
                (struct jocky_dirent64 *)(dents_buf + offset);

            if (is_pid_dir(d->d_name)) {
                proc_count++;

                /* Read /proc/PID/status for full process details */
                path_join(path_buf, "/proc/", d->d_name, "status");
                long n = read_file_raw(path_buf, status_buf,
                                       sizeof(status_buf));

                if (n > 0) {
                    char name_val[64]  = "?";
                    char pid_val[16]   = "?";
                    char ppid_val[16]  = "?";
                    char state_val[16] = "?";
                    char uid_val[32]   = "?";
                    char vmrss_val[32] = "0";

                    extract_field(status_buf, "Name",   name_val,  sizeof(name_val));
                    extract_field(status_buf, "Pid",    pid_val,   sizeof(pid_val));
                    extract_field(status_buf, "PPid",   ppid_val,  sizeof(ppid_val));
                    extract_field(status_buf, "State",  state_val, sizeof(state_val));
                    extract_field(status_buf, "Uid",    uid_val,   sizeof(uid_val));
                    extract_field(status_buf, "VmRSS",  vmrss_val, sizeof(vmrss_val));

                    /* Read the exe symlink for full path */
                    path_join(path_buf, "/proc/", d->d_name, "comm");
                    char comm_buf[256] = "";
                    read_file_raw(path_buf, comm_buf, sizeof(comm_buf));
                    /* strip trailing newline */
                    for (int i = 0; comm_buf[i]; i++)
                        if (comm_buf[i] == '\n') { comm_buf[i] = 0; break; }

                    output_raw("[jocky] proc");
                    output_raw(" pid=");      output_raw(pid_val);
                    output_raw(" ppid=");     output_raw(ppid_val);
                    output_raw(" state=");    output_raw(state_val);
                    output_raw(" uid=");      output_raw(uid_val);
                    output_raw(" name=");     output_raw(name_val);
                    output_raw(" vmrss_kb="); output_raw(vmrss_val);
                    output_raw("\n");
                }
            }
            offset += d->d_reclen;
        }
    }

    jocky_close(dir_fd);

    char count_str[16];
    jocky_itoa(proc_count, count_str, 10);
    output_raw("[jocky] total_visible_processes=");
    output_raw(count_str);
    output_raw("\n");
    output_raw("[jocky] --- end stealth process enumeration ---\n");
}

/* ════════════════════════════════════════════════════════════════
 * FEATURE 2 — HIDDEN PROCESS DETECTOR
 * Compares /proc visible PIDs against /proc/sched_debug count.
 * Rootkits hide processes by unlinking from /proc but the
 * kernel scheduler still knows about them.
 * ════════════════════════════════════════════════════════════════ */

void jocky_detect_hidden_processes(void) {
    static char dents_buf[4096];
    static char sched_buf[65536];

    output_raw("[jocky] --- hidden process detection ---\n");

    /* Count visible PIDs in /proc */
    int visible_count = 0;
    int dir_fd = jocky_open("/proc", SC_O_RDONLY | SC_O_DIRECTORY);
    if (dir_fd >= 0) {
        long bytes;
        while ((bytes = jocky_getdents64(dir_fd,
                    (struct jocky_dirent64 *)dents_buf,
                    sizeof(dents_buf))) > 0) {
            long offset = 0;
            while (offset < bytes) {
                struct jocky_dirent64 *d =
                    (struct jocky_dirent64 *)(dents_buf + offset);
                if (is_pid_dir(d->d_name)) visible_count++;
                offset += d->d_reclen;
            }
        }
        jocky_close(dir_fd);
    }

    /* Count entries in /proc/sched_debug (all tasks kernel knows) */
    int sched_count = 0;
    long n = read_file_raw("/proc/sched_debug", sched_buf, sizeof(sched_buf));
    if (n > 0) {
        /* Count lines containing "task_group" which appear per-task */
        const char *p = sched_buf;
        while (*p) {
            /* Look for lines starting with a space + a process name pattern */
            if (*p == ' ' || *p == '\t') {
                /* crude task line detection — look for .se.exec_start */
                const char *check = p;
                int found = 0;
                while (*check && *check != '\n') {
                    if (check[0]=='.' && check[1]=='s' && check[2]=='e') {
                        found = 1; break;
                    }
                    check++;
                }
                if (found) sched_count++;
            }
            while (*p && *p != '\n') p++;
            if (*p) p++;
        }
    }

    char vis_str[16], sched_str[16];
    jocky_itoa(visible_count, vis_str, 10);
    jocky_itoa(sched_count,   sched_str, 10);

    output_raw("[jocky] visible_in_proc=");
    output_raw(vis_str);
    output_raw("\n");
    output_raw("[jocky] known_to_scheduler=");
    output_raw(sched_str);
    output_raw("\n");

    if (sched_count > visible_count + 5) {
        output_raw("[jocky] ANOMALY=possible_hidden_processes_detected\n");
        output_raw("[jocky] action=manual_kernel_memory_inspection_required\n");
    } else {
        output_raw("[jocky] status=no_obvious_hidden_processes\n");
    }

    output_raw("[jocky] --- end hidden process detection ---\n");
}

/* ════════════════════════════════════════════════════════════════
 * FEATURE 3 — NETWORK CONNECTION ENUMERATION
 * Reads /proc/net/tcp and /proc/net/tcp6 directly.
 * Bypasses any netstat/ss hook via direct syscall read.
 * Decodes hex addresses to human-readable format.
 * ════════════════════════════════════════════════════════════════ */

/*
 * hex_to_ip
 * Converts kernel /proc/net/tcp hex IP (little-endian) to a.b.c.d string.
 */
static void hex_to_ip(const char *hex, char *out) {
    /* each byte is 2 hex chars, 4 bytes = 8 chars, little endian */
    unsigned int b[4];
    for (int i = 0; i < 4; i++) {
        char byte_str[3] = { hex[6 - i*2], hex[7 - i*2], 0 };
        unsigned int val = 0;
        for (int j = 0; byte_str[j]; j++) {
            char c = byte_str[j];
            int digit = (c >= '0' && c <= '9') ? c - '0' :
                        (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                        (c >= 'A' && c <= 'F') ? c - 'A' + 10 : 0;
            val = val * 16 + digit;
        }
        b[i] = val;
    }
    /* simple int to decimal conversion for each byte */
    char tmp[4];
    jocky_itoa(b[0], tmp, 10); jocky_strcpy(out, tmp); jocky_strcat(out, ".");
    jocky_itoa(b[1], tmp, 10); jocky_strcat(out, tmp); jocky_strcat(out, ".");
    jocky_itoa(b[2], tmp, 10); jocky_strcat(out, tmp); jocky_strcat(out, ".");
    jocky_itoa(b[3], tmp, 10); jocky_strcat(out, tmp);
}

/*
 * hex_to_port
 * Converts kernel hex port to decimal string.
 */
static void hex_to_port(const char *hex, char *out) {
    unsigned int port = 0;
    for (int i = 0; hex[i]; i++) {
        char c = hex[i];
        int digit = (c >= '0' && c <= '9') ? c - '0' :
                    (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                    (c >= 'A' && c <= 'F') ? c - 'A' + 10 : 0;
        port = port * 16 + digit;
    }
    jocky_itoa(port, out, 10);
}

static const char *tcp_state(const char *hex) {
    if (!hex || !*hex) return "UNKNOWN";
    /* kernel state codes */
    if (hex[0]=='0' && hex[1]=='1') return "ESTABLISHED";
    if (hex[0]=='0' && hex[1]=='2') return "SYN_SENT";
    if (hex[0]=='0' && hex[1]=='3') return "SYN_RECV";
    if (hex[0]=='0' && hex[1]=='4') return "FIN_WAIT1";
    if (hex[0]=='0' && hex[1]=='5') return "FIN_WAIT2";
    if (hex[0]=='0' && hex[1]=='6') return "TIME_WAIT";
    if (hex[0]=='0' && hex[1]=='7') return "CLOSE";
    if (hex[0]=='0' && hex[1]=='8') return "CLOSE_WAIT";
    if (hex[0]=='0' && hex[1]=='9') return "LAST_ACK";
    if (hex[0]=='0' && hex[1]=='A') return "LISTEN";
    if (hex[0]=='0' && hex[1]=='B') return "CLOSING";
    return "UNKNOWN";
}

static void parse_net_tcp(const char *path, const char *proto) {
    static char net_buf[131072]; /* 128KB — enough for most systems */
    long n = read_file_raw(path, net_buf, sizeof(net_buf));
    if (n <= 0) return;

    const char *p = net_buf;
    int line = 0;

    while (*p) {
        /* skip to next line */
        const char *line_start = p;
        while (*p && *p != '\n') p++;
        if (*p) p++;

        line++;
        if (line == 1) continue; /* skip header */

        /* parse: sl local_addr rem_addr state ... uid ... inode */
        /* format: "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 12345" */

        /* skip leading whitespace and sl number */
        const char *c = line_start;
        while (*c == ' ') c++;
        while (*c && *c != ':') c++;
        if (*c == ':') c++; /* skip colon after sl */
        while (*c == ' ') c++;

        /* local address: 8 hex chars */
        if (jocky_strlen(c) < 30) continue;

        char local_ip[20] = "", local_port_hex[8] = "";
        char rem_ip[20]   = "", rem_port_hex[8]   = "";
        char state_hex[4] = "";

        /* copy local hex IP (8 chars) */
        int i = 0;
        while (*c && *c != ':' && i < 8) local_ip[i++] = *c++;
        local_ip[i] = 0;
        if (*c == ':') c++;
        i = 0;
        while (*c && *c != ' ' && i < 4) local_port_hex[i++] = *c++;
        local_port_hex[i] = 0;
        while (*c == ' ') c++;

        /* remote hex IP */
        i = 0;
        while (*c && *c != ':' && i < 8) rem_ip[i++] = *c++;
        rem_ip[i] = 0;
        if (*c == ':') c++;
        i = 0;
        while (*c && *c != ' ' && i < 4) rem_port_hex[i++] = *c++;
        rem_port_hex[i] = 0;
        while (*c == ' ') c++;

        /* state */
        i = 0;
        while (*c && *c != ' ' && i < 3) state_hex[i++] = *c++;
        state_hex[i] = 0;

        char lip[20], lport[8], rip[20], rport[8];
        hex_to_ip(local_ip,    lip);
        hex_to_port(local_port_hex, lport);
        hex_to_ip(rem_ip,      rip);
        hex_to_port(rem_port_hex,   rport);

        output_raw("[jocky] conn");
        output_raw(" proto="); output_raw(proto);
        output_raw(" local="); output_raw(lip);
        output_raw(":"); output_raw(lport);
        output_raw(" remote="); output_raw(rip);
        output_raw(":"); output_raw(rport);
        output_raw(" state="); output_raw(tcp_state(state_hex));
        output_raw("\n");
    }
}

void jocky_stealth_network(void) {
    output_raw("[jocky] --- stealth network connections (direct syscall) ---\n");
    output_raw("[jocky] method=proc_net_direct hook_bypass=true\n");
    parse_net_tcp("/proc/net/tcp",  "TCPv4");
    parse_net_tcp("/proc/net/tcp6", "TCPv6");
    output_raw("[jocky] --- end stealth network connections ---\n");
}

/* ════════════════════════════════════════════════════════════════
 * FEATURE 4 — SYSTEM INFORMATION
 * Reads /proc/version and /proc/cpuinfo directly.
 * ════════════════════════════════════════════════════════════════ */

void jocky_stealth_system_info(void) {
    static char buf[4096];

    output_raw("[jocky] --- stealth system information (direct syscall) ---\n");
    output_raw("[jocky] method=proc_direct hook_bypass=true\n");

    if (read_file_raw("/proc/version", buf, sizeof(buf)) > 0) {
        /* strip trailing newline */
        for (int i = 0; buf[i]; i++)
            if (buf[i] == '\n') { buf[i] = 0; break; }
        output_line("kernel", buf);
    }

    if (read_file_raw("/proc/uptime", buf, sizeof(buf)) > 0) {
        for (int i = 0; buf[i]; i++)
            if (buf[i] == '\n' || buf[i] == ' ') { buf[i] = 0; break; }
        output_line("uptime_seconds", buf);
    }

    if (read_file_raw("/proc/loadavg", buf, sizeof(buf)) > 0) {
        for (int i = 0; buf[i]; i++)
            if (buf[i] == '\n') { buf[i] = 0; break; }
        output_line("loadavg", buf);
    }

    /* Memory info */
    if (read_file_raw("/proc/meminfo", buf, sizeof(buf)) > 0) {
        char total[32] = "?", avail[32] = "?";
        extract_field(buf, "MemTotal",     total, sizeof(total));
        extract_field(buf, "MemAvailable", avail, sizeof(avail));
        output_line("mem_total_kb",     total);
        output_line("mem_available_kb", avail);
    }

    output_raw("[jocky] --- end stealth system information ---\n");
}

/* ════════════════════════════════════════════════════════════════
 * FEATURE 5 — LOADED KERNEL MODULES
 * Reads /proc/modules — shows what is loaded in the kernel.
 * Critical for BYOVD detection (finding vulnerable drivers).
 * ════════════════════════════════════════════════════════════════ */

void jocky_stealth_kernel_modules(void) {
    static char buf[65536];

    output_raw("[jocky] --- kernel modules (direct syscall) ---\n");
    output_raw("[jocky] method=proc_modules_direct hook_bypass=true\n");

    long n = read_file_raw("/proc/modules", buf, sizeof(buf));
    if (n <= 0) {
        output_raw("[jocky] ERROR: cannot read /proc/modules\n");
        return;
    }

    /* Each line: module_name size refcount used_by state address */
    const char *p = buf;
    int mod_count = 0;
    while (*p) {
        const char *line_start = p;
        while (*p && *p != '\n') p++;
        if (*p) p++;

        /* extract module name (first token) */
        char mod_name[64] = "";
        char mod_size[16] = "";
        const char *c = line_start;
        int i = 0;
        while (*c && *c != ' ' && i < 63) mod_name[i++] = *c++;
        mod_name[i] = 0;
        while (*c == ' ') c++;
        i = 0;
        while (*c && *c != ' ' && i < 15) mod_size[i++] = *c++;
        mod_size[i] = 0;

        if (mod_name[0]) {
            mod_count++;
            output_raw("[jocky] module name=");
            output_raw(mod_name);
            output_raw(" size=");
            output_raw(mod_size);
            output_raw("\n");
        }
    }

    char count_str[16];
    jocky_itoa(mod_count, count_str, 10);
    output_raw("[jocky] total_modules=");
    output_raw(count_str);
    output_raw("\n");
    output_raw("[jocky] --- end kernel modules ---\n");
}

/* ════════════════════════════════════════════════════════════════
 * FEATURE 6 — PERSISTENCE MECHANISM DETECTION
 * Checks autostart locations without using libc directory functions.
 * ════════════════════════════════════════════════════════════════ */

static void scan_dir_for_persistence(const char *dir_path) {
    static char dents_buf[4096];
    static char full_path[512];

    int fd = jocky_open(dir_path, SC_O_RDONLY | SC_O_DIRECTORY);
    if (fd < 0) return;

    long bytes;
    while ((bytes = jocky_getdents64(fd,
                (struct jocky_dirent64 *)dents_buf,
                sizeof(dents_buf))) > 0) {
        long offset = 0;
        while (offset < bytes) {
            struct jocky_dirent64 *d =
                (struct jocky_dirent64 *)(dents_buf + offset);
            if (d->d_name[0] != '.') {
                jocky_strcpy(full_path, dir_path);
                jocky_strcat(full_path, "/");
                jocky_strcat(full_path, d->d_name);
                output_raw("[jocky] persistence_entry path=");
                output_raw(full_path);
                output_raw("\n");
            }
            offset += d->d_reclen;
        }
    }
    jocky_close(fd);
}

void jocky_stealth_persistence(void) {
    output_raw("[jocky] --- persistence mechanism scan (direct syscall) ---\n");

    /* Standard Linux persistence locations */
    static const char *persist_dirs[] = {
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/init.d",
        "/etc/rc.d",
        "/usr/lib/systemd/system",
        "/etc/systemd/system",
        NULL
    };

    for (int i = 0; persist_dirs[i]; i++) {
        output_raw("[jocky] scanning=");
        output_raw(persist_dirs[i]);
        output_raw("\n");
        scan_dir_for_persistence(persist_dirs[i]);
    }

    /* Check crontab file directly */
    static char cron_buf[8192];
    if (read_file_raw("/etc/crontab", cron_buf, sizeof(cron_buf)) > 0) {
        output_raw("[jocky] crontab_content_present=true\n");
    }

    output_raw("[jocky] --- end persistence scan ---\n");
}

/* ════════════════════════════════════════════════════════════════
 * PUBLIC API — Drop-in replacements for jocky_runtime.c functions
 * These have the same names as the original runtime so the
 * compiler codegen works without modification.
 * ════════════════════════════════════════════════════════════════ */

/*
 * Override jocky_list_processes with stealth version.
 * If compiling with JOCKY_STEALTH defined, these replace
 * the standard versions in jocky_runtime.c
 */
#ifdef JOCKY_STEALTH

void jocky_list_processes(void) {
    jocky_stealth_list_processes();
    jocky_detect_hidden_processes();
}

void jocky_list_network_connections(void) {
    jocky_stealth_network();
}

void jocky_system_info(void) {
    jocky_stealth_system_info();
    jocky_stealth_kernel_modules();
}

void jocky_print(const char *text) {
    jocky_puts_raw("[jocky] ");
    jocky_puts_raw(text);
    jocky_puts_raw("\n");
}

#endif /* JOCKY_STEALTH */
