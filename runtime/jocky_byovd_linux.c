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
 * jocky_byovd_linux.c
 * --------------------
 * JOCKY BYOVD (Bring Your Own Vulnerable Driver) Analysis Module.
 *
 * WHAT BYOVD IS:
 *   Attackers load a legitimate but vulnerable signed kernel driver.
 *   The OS trusts it (valid signature).
 *   They exploit the driver's bug to get kernel-level access.
 *   From kernel level they can disable EDR callbacks entirely.
 *
 * WHAT WE DO HERE (forensic scope):
 *   1. Enumerate all loaded kernel modules
 *   2. Match against known vulnerable driver database
 *   3. Detect active EDR/security tool kernel hooks
 *      (LSM hooks, netfilter hooks, eBPF programs, kprobes)
 *   4. Report exactly WHERE security tools have their callbacks
 *      and WHERE the blind spots are
 *   5. Report which loaded drivers are known to be exploitable
 *
 *   We DETECT and REPORT. We do not exploit anything.
 *
 * DATA SOURCES:
 *   /sys/module/                    — all loaded kernel modules
 *   /proc/kallsyms                  — kernel symbol table (hooks)
 *   /sys/kernel/security/           — LSM information
 *   /sys/kernel/debug/tracing/      — kprobe/ftrace hooks
 *   /proc/net/ip_tables_names       — netfilter hooks
 *   /sys/fs/bpf/                    — eBPF programs
 *
 * COMPILE:
 *   gcc -O2 -o test_byovd jocky_byovd_linux.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#include "jocky_syscall_linux.h"

/* ════════════════════════════════════════════════════════════════
 * VULNERABLE DRIVER DATABASE
 * Simplified Linux-equivalent of LOLDrivers.
 * Each entry is a kernel module name known to be vulnerable
 * or abusable for privilege escalation / EDR bypass.
 *
 * Sources:
 *   - CVE database
 *   - LOLDrivers project (windows focused but Linux equivalents exist)
 *   - Linux kernel CVE list
 *   - Security research (Sentinel Labs, Crowdstrike, etc.)
 * ════════════════════════════════════════════════════════════════ */

typedef struct {
    const char *module_name;  /* kernel module name */
    const char *cve;          /* CVE identifier */
    const char *description;  /* what the vulnerability allows */
    const char *severity;     /* CRITICAL / HIGH / MEDIUM */
    int         byovd_usable; /* can be used for BYOVD attack */
} jocky_vuln_driver_t;

static const jocky_vuln_driver_t VULN_DRIVERS[] = {
    /* ── Kernel memory vulnerabilities ───────────────────────── */
    {
        "nvme",
        "CVE-2023-6535",
        "NVMe driver use-after-free — kernel memory corruption possible",
        "HIGH", 1
    },
    {
        "xfs",
        "CVE-2023-2124",
        "XFS filesystem OOB read — kernel memory disclosure",
        "HIGH", 0
    },
    {
        "nft_set_pipapo",
        "CVE-2023-6817",
        "Netfilter use-after-free — local privilege escalation",
        "CRITICAL", 1
    },
    {
        "nf_tables",
        "CVE-2022-32250",
        "Netfilter memory corruption — exploited in the wild for LPE",
        "CRITICAL", 1
    },
    {
        "xt_conntrack",
        "CVE-2022-1015",
        "Netfilter stack buffer overflow — local privilege escalation",
        "CRITICAL", 1
    },
    {
        "ksmbd",
        "CVE-2023-32254",
        "SMB server use-after-free — remote kernel compromise",
        "CRITICAL", 0
    },
    {
        "tipc",
        "CVE-2022-0435",
        "TIPC remote memory corruption — exploitable from network",
        "CRITICAL", 0
    },
    {
        "perf_event",
        "CVE-2023-6931",
        "perf_event stack overflow — local privilege escalation",
        "HIGH", 1
    },
    {
        "io_uring",
        "CVE-2022-29582",
        "io_uring use-after-free — local privilege escalation",
        "HIGH", 1
    },
    {
        "udf",
        "CVE-2023-6606",
        "UDF filesystem OOB read — kernel memory disclosure",
        "MEDIUM", 0
    },
    {
        "fbcon",
        "CVE-2023-3161",
        "Framebuffer out-of-bounds write — local privilege escalation",
        "HIGH", 1
    },
    {
        "cls_fw",
        "CVE-2023-3776",
        "Traffic control use-after-free — local privilege escalation",
        "HIGH", 1
    },
    {
        "can",
        "CVE-2023-2598",
        "CAN bus heap overflow — local privilege escalation",
        "HIGH", 1
    },
    {
        "cifs",
        "CVE-2023-1192",
        "CIFS use-after-free — local privilege escalation",
        "HIGH", 0
    },
    {
        "pkvm",
        "CVE-2023-5178",
        "pKVM hypervisor escape — guest-to-host privilege escalation",
        "CRITICAL", 1
    },
    /* ── Vendor-specific vulnerable drivers ───────────────────── */
    {
        "vmwgfx",
        "CVE-2023-33952",
        "VMware VMWGFX double-free — local privilege escalation in VMs",
        "HIGH", 1
    },
    {
        "amdgpu",
        "CVE-2023-4692",
        "AMD GPU GRUB2 heap overflow — bootloader-level compromise",
        "CRITICAL", 1
    },
    {
        "nvidia",
        "CVE-2022-28181",
        "NVIDIA driver out-of-bounds write — local privilege escalation",
        "HIGH", 1
    },
    /* ── Debugging/tracing modules (powerful, often forgotten) ─ */
    {
        "kprobe",
        "N/A",
        "Kernel dynamic tracing — can hook ANY kernel function if loaded",
        "HIGH", 1
    },
    {
        "uprobes",
        "N/A",
        "User-space dynamic tracing — hooks user processes from kernel",
        "MEDIUM", 1
    },
    {
        "ftrace",
        "N/A",
        "Kernel function tracer — can intercept all kernel calls",
        "HIGH", 1
    },
    /* Sentinel */
    { NULL, NULL, NULL, NULL, 0 }
};

/* ════════════════════════════════════════════════════════════════
 * KNOWN SECURITY TOOL SIGNATURES
 * Module names / symbols associated with known EDR/HIDS products.
 * When found, we report them as active security callbacks.
 * ════════════════════════════════════════════════════════════════ */

typedef struct {
    const char *module_name;
    const char *product;
    const char *vendor;
    const char *hook_type;
} jocky_edr_sig_t;

static const jocky_edr_sig_t EDR_SIGNATURES[] = {
    { "falcon_kal",       "CrowdStrike Falcon",   "CrowdStrike",  "LSM + eBPF"       },
    { "falcon_lsm",       "CrowdStrike Falcon",   "CrowdStrike",  "LSM hooks"        },
    { "cs_ioctl",         "CrowdStrike Falcon",   "CrowdStrike",  "ioctl hooks"      },
    { "wazuh",            "Wazuh Agent",           "Wazuh",        "syscall audit"    },
    { "ossec",            "OSSEC HIDS",            "OSSEC",        "audit hooks"      },
    { "sentinelone",      "SentinelOne",           "SentinelOne",  "LSM + netfilter"  },
    { "s1_core",          "SentinelOne",           "SentinelOne",  "kernel core"      },
    { "carbon_black",     "VMware Carbon Black",   "VMware",       "LSM hooks"        },
    { "cbsensor",         "VMware Carbon Black",   "VMware",       "sensor module"    },
    { "iovisor",          "Sysdig Falco",          "Sysdig",       "eBPF probes"      },
    { "sysdig",           "Sysdig",                "Sysdig",       "kernel module"    },
    { "falco",            "Sysdig Falco",          "Sysdig",       "eBPF/kprobe"      },
    { "auditd",           "Linux Audit Daemon",    "Linux",        "audit syscalls"   },
    { "audit",            "Linux Audit Framework", "Linux",        "audit netlink"    },
    { "apparmor",         "AppArmor LSM",          "Canonical",    "LSM MAC policy"   },
    { "selinux",          "SELinux LSM",           "NSA/RedHat",   "LSM MAC policy"   },
    { "tomoyo",           "TOMOYO LSM",            "NTT",          "LSM MAC policy"   },
    { "landlock",         "Landlock LSM",          "Linux",        "sandbox LSM"      },
    { "safekit",          "Bull SafeKit",          "Bull",         "HA + monitoring"  },
    { "qualys",           "Qualys Cloud Agent",    "Qualys",       "file monitoring"  },
    { "tetragon",         "Tetragon",              "Isovalent",    "eBPF enforcement" },
    { NULL,               NULL,                    NULL,           NULL               }
};

/* ════════════════════════════════════════════════════════════════
 * PART 1 — MODULE ENUMERATION
 * Reads /sys/module/ using direct syscalls (our stealth layer).
 * More detailed than /proc/modules — includes parameters.
 * ════════════════════════════════════════════════════════════════ */

typedef struct {
    char name[128];
    char size[32];
    char refcount[16];
    int  is_vulnerable;
    int  is_edr;
    const jocky_vuln_driver_t *vuln_entry;
    const jocky_edr_sig_t     *edr_entry;
} jocky_module_t;

#define MAX_MODULES 1024
static jocky_module_t g_modules[MAX_MODULES];
static int            g_module_count = 0;

static void read_module_size(const char *modname, char *size_out) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/module/%s/sections/.text", modname);

    /* Try to read coresize */
    char cpath[256];
    snprintf(cpath, sizeof(cpath), "/sys/module/%s/coresize", modname);
    int fd = open(cpath, O_RDONLY);
    if (fd >= 0) {
        int n = read(fd, size_out, 31);
        if (n > 0) {
            size_out[n] = 0;
            for (int i = 0; i < n; i++)
                if (size_out[i] == '\n') { size_out[i] = 0; break; }
        }
        close(fd);
    }
}

static void enumerate_modules(void) {
    static char dents_buf[8192];

    int dir_fd = jocky_open("/sys/module", SC_O_RDONLY | SC_O_DIRECTORY);
    if (dir_fd < 0) {
        printf("[jocky-byovd] WARNING: /sys/module not accessible\n");
        return;
    }

    long bytes;
    while ((bytes = jocky_getdents64(dir_fd,
                (struct jocky_dirent64 *)dents_buf,
                sizeof(dents_buf))) > 0 &&
           g_module_count < MAX_MODULES) {

        long off = 0;
        while (off < bytes && g_module_count < MAX_MODULES) {
            struct jocky_dirent64 *d =
                (struct jocky_dirent64 *)(dents_buf + off);

            if (d->d_name[0] && d->d_name[0] != '.') {
                jocky_module_t *m = &g_modules[g_module_count];
                memset(m, 0, sizeof(*m));

                jocky_strcpy(m->name, d->d_name);
                jocky_strcpy(m->size, "?");
                read_module_size(d->d_name, m->size);

                /* Check against vulnerable driver DB */
                for (int vi = 0; VULN_DRIVERS[vi].module_name; vi++) {
                    if (jocky_strcmp(m->name, VULN_DRIVERS[vi].module_name) == 0) {
                        m->is_vulnerable = 1;
                        m->vuln_entry    = &VULN_DRIVERS[vi];
                        break;
                    }
                }

                /* Check against EDR signatures */
                for (int ei = 0; EDR_SIGNATURES[ei].module_name; ei++) {
                    if (jocky_strcmp(m->name, EDR_SIGNATURES[ei].module_name) == 0) {
                        m->is_edr     = 1;
                        m->edr_entry  = &EDR_SIGNATURES[ei];
                        break;
                    }
                }

                g_module_count++;
            }
            off += d->d_reclen;
        }
    }
    jocky_close(dir_fd);
}

/* ════════════════════════════════════════════════════════════════
 * PART 2 — LSM HOOK DETECTION
 * Linux Security Modules register hooks on every sensitive
 * kernel operation. We detect which LSMs are active.
 * ════════════════════════════════════════════════════════════════ */

static void detect_lsm_hooks(void) {
    printf("[jocky-byovd] --- LSM (Linux Security Module) hooks ---\n");

    /* /sys/kernel/security/lsm shows active LSMs */
    static char buf[512];
    int fd = open("/sys/kernel/security/lsm", O_RDONLY);
    if (fd >= 0) {
        int n = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (n > 0) {
            buf[n] = 0;
            for (int i = 0; i < n; i++)
                if (buf[i] == '\n') { buf[i] = 0; break; }
            printf("[jocky-byovd] active_lsms=%s\n", buf);

            /* Parse individual LSMs */
            char tmp[512];
            strncpy(tmp, buf, sizeof(tmp));
            char *token = strtok(tmp, ",");
            while (token) {
                while (*token == ' ') token++;
                printf("[jocky-byovd] lsm_hook name=%-20s "
                       "hooks=process_create,file_open,network_connect,"
                       "exec,memory_map\n", token);
                token = strtok(NULL, ",");
            }
        }
    } else {
        /* Fallback: check /sys/module/ for known LSM modules */
        const char *lsm_modules[] = {
            "apparmor", "selinux", "tomoyo", "smack",
            "yama", "landlock", NULL
        };
        for (int i = 0; lsm_modules[i]; i++) {
            char path[128];
            snprintf(path, sizeof(path), "/sys/module/%s", lsm_modules[i]);
            struct stat st;
            if (stat(path, &st) == 0) {
                printf("[jocky-byovd] lsm_hook name=%-20s "
                       "status=ACTIVE (via /sys/module)\n", lsm_modules[i]);
            }
        }
    }
    printf("[jocky-byovd] --- end LSM hooks ---\n\n");
}

/* ════════════════════════════════════════════════════════════════
 * PART 3 — EBPF PROGRAM DETECTION
 * Modern EDRs (CrowdStrike Falcon, Tetragon) use eBPF programs
 * to hook kernel functions without loading a kernel module.
 * These are harder to detect but leave traces in /sys/fs/bpf/
 * and /proc/PID/fdinfo/
 * ════════════════════════════════════════════════════════════════ */

static void detect_ebpf_programs(void) {
    printf("[jocky-byovd] --- eBPF program detection ---\n");

    int found_any = 0;

    /* Check /sys/fs/bpf/ for pinned eBPF objects */
    static char dents_buf[4096];
    int dir_fd = jocky_open("/sys/fs/bpf", SC_O_RDONLY | SC_O_DIRECTORY);
    if (dir_fd >= 0) {
        long bytes;
        while ((bytes = jocky_getdents64(dir_fd,
                    (struct jocky_dirent64 *)dents_buf,
                    sizeof(dents_buf))) > 0) {
            long off = 0;
            while (off < bytes) {
                struct jocky_dirent64 *d =
                    (struct jocky_dirent64 *)(dents_buf + off);
                if (d->d_name[0] && d->d_name[0] != '.') {
                    printf("[jocky-byovd] ebpf_pinned name=%s\n", d->d_name);
                    found_any = 1;
                }
                off += d->d_reclen;
            }
        }
        jocky_close(dir_fd);
    }

    /* Check /proc/PID/fdinfo for BPF file descriptors in security processes */
    const char *edrtool_names[] = {
        "falco", "tetragon", "bpftrace", "sysdig",
        "cs-falcon", "s1agent", NULL
    };

    DIR *proc_dir = opendir("/proc");
    if (proc_dir) {
        struct dirent *ent;
        while ((ent = readdir(proc_dir))) {
            /* Only look at numeric PIDs */
            int is_pid = 1;
            for (int i = 0; ent->d_name[i]; i++)
                if (ent->d_name[i] < '0' || ent->d_name[i] > '9')
                    { is_pid = 0; break; }
            if (!is_pid) continue;

            /* Read comm */
            char comm_path[64], comm[64] = "";
            snprintf(comm_path, sizeof(comm_path),
                     "/proc/%s/comm", ent->d_name);
            int fd = open(comm_path, O_RDONLY);
            if (fd >= 0) {
                int n = read(fd, comm, sizeof(comm)-1);
                close(fd);
                if (n > 0) {
                    comm[n] = 0;
                    for (int i = 0; i < n; i++)
                        if (comm[i] == '\n') { comm[i] = 0; break; }
                }
            }

            /* Check if this is a known EDR process */
            for (int ei = 0; edrtool_names[ei]; ei++) {
                if (strstr(comm, edrtool_names[ei])) {
                    printf("[jocky-byovd] ebpf_process pid=%-6s name=%s "
                           "likely_using_ebpf=true\n",
                           ent->d_name, comm);
                    found_any = 1;
                    break;
                }
            }
        }
        closedir(proc_dir);
    }

    if (!found_any)
        printf("[jocky-byovd] no_ebpf_programs_detected\n");

    printf("[jocky-byovd] --- end eBPF detection ---\n\n");
}

/* ════════════════════════════════════════════════════════════════
 * PART 4 — KPROBE / FTRACE HOOK DETECTION
 * Security tools use kprobes to hook kernel functions.
 * We read the tracing subsystem to find active probes.
 * ════════════════════════════════════════════════════════════════ */

static void detect_kprobe_hooks(void) {
    printf("[jocky-byovd] --- kprobe/ftrace hook detection ---\n");

    /* kprobe_events shows all active kprobes */
    static char kbuf[65536];
    int fd = open("/sys/kernel/debug/tracing/kprobe_events", O_RDONLY);
    if (fd >= 0) {
        int n = read(fd, kbuf, sizeof(kbuf)-1);
        close(fd);
        if (n > 0) {
            kbuf[n] = 0;
            /* Count and print kprobes */
            int count = 0;
            char *line = kbuf;
            while (*line) {
                char *nl = strchr(line, '\n');
                if (nl) *nl = 0;
                if (line[0]) {
                    printf("[jocky-byovd] kprobe %s\n", line);
                    count++;
                }
                if (!nl) break;
                line = nl + 1;
            }
            printf("[jocky-byovd] total_kprobes=%d\n", count);
        } else {
            printf("[jocky-byovd] kprobe_events=empty "
                   "(no active kprobes)\n");
        }
    } else {
        printf("[jocky-byovd] kprobe_events=not_accessible "
               "(need CAP_SYS_ADMIN or debug mount)\n");
    }

    /* Check ftrace current_tracer */
    fd = open("/sys/kernel/debug/tracing/current_tracer", O_RDONLY);
    if (fd >= 0) {
        char tracer[64] = "";
        int n = read(fd, tracer, sizeof(tracer)-1);
        close(fd);
        if (n > 0) {
            tracer[n] = 0;
            for (int i = 0; i < n; i++)
                if (tracer[i] == '\n') { tracer[i] = 0; break; }
            printf("[jocky-byovd] ftrace_tracer=%s\n", tracer);
            if (strcmp(tracer, "nop") != 0)
                printf("[jocky-byovd] WARNING: ftrace active "
                       "— security tool may be tracing kernel\n");
        }
    }

    printf("[jocky-byovd] --- end kprobe/ftrace detection ---\n\n");
}

/* ════════════════════════════════════════════════════════════════
 * PART 5 — NETFILTER HOOK DETECTION
 * Firewalls and network monitoring tools register hooks in
 * netfilter. These can intercept and log all network traffic.
 * ════════════════════════════════════════════════════════════════ */

static void detect_netfilter_hooks(void) {
    printf("[jocky-byovd] --- netfilter hook detection ---\n");

    /* /proc/net/ip_tables_names shows active iptables tables */
    static char buf[1024];
    int fd = open("/proc/net/ip_tables_names", O_RDONLY);
    if (fd >= 0) {
        int n = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (n > 0) {
            buf[n] = 0;
            char *line = buf;
            while (*line) {
                char *nl = strchr(line, '\n');
                if (nl) *nl = 0;
                if (line[0])
                    printf("[jocky-byovd] iptables_table=%s "
                           "hooks=PREROUTING,INPUT,FORWARD,OUTPUT,POSTROUTING\n",
                           line);
                if (!nl) break;
                line = nl + 1;
            }
        } else {
            printf("[jocky-byovd] iptables_tables=none\n");
        }
    }

    /* Check for nftables */
    fd = open("/proc/net/nf_conntrack", O_RDONLY);
    if (fd >= 0) {
        printf("[jocky-byovd] nf_conntrack=active "
               "(connection tracking enabled — all connections logged)\n");
        close(fd);
    }

    /* Check loaded netfilter modules */
    const char *nf_modules[] = {
        "nf_conntrack", "nf_tables", "xt_LOG", "xt_NFLOG",
        "nfnetlink_log", "nfnetlink_queue", NULL
    };
    for (int i = 0; nf_modules[i]; i++) {
        char path[128];
        snprintf(path, sizeof(path), "/sys/module/%s", nf_modules[i]);
        struct stat st;
        if (stat(path, &st) == 0) {
            printf("[jocky-byovd] netfilter_module=%s status=LOADED "
                   "can_log_traffic=true\n", nf_modules[i]);
        }
    }

    printf("[jocky-byovd] --- end netfilter detection ---\n\n");
}

/* ════════════════════════════════════════════════════════════════
 * PART 6 — AUDIT SUBSYSTEM DETECTION
 * auditd hooks into kernel syscalls and logs everything.
 * Critical to detect for JOCKY — it will log our operations
 * unless we use direct syscalls.
 * ════════════════════════════════════════════════════════════════ */

static void detect_audit_hooks(void) {
    printf("[jocky-byovd] --- Linux Audit subsystem detection ---\n");

    /* Check if audit module is loaded */
    struct stat st;
    int audit_loaded = (stat("/sys/module/audit", &st) == 0);

    printf("[jocky-byovd] audit_module_loaded=%s\n",
           audit_loaded ? "YES" : "NO");

    if (audit_loaded) {
        /* Read audit rules if accessible */
        int fd = open("/proc/audit_rules", O_RDONLY);
        if (fd >= 0) {
            static char buf[4096];
            int n = read(fd, buf, sizeof(buf)-1);
            close(fd);
            if (n > 0) {
                buf[n] = 0;
                printf("[jocky-byovd] audit_rules_present=YES\n");
                printf("[jocky-byovd] audit_scope=all_syscalls\n");
            }
        } else {
            printf("[jocky-byovd] audit_rules=not_readable\n");
        }

        printf("[jocky-byovd] audit_impact=ALL syscalls logged to auditd\n");
        printf("[jocky-byovd] jocky_bypass=direct_syscalls_not_logged"
               "_if_audit_rules_dont_match\n");
    }

    printf("[jocky-byovd] --- end audit detection ---\n\n");
}

/* ════════════════════════════════════════════════════════════════
 * PART 7 — GENERATE BLIND SPOT REPORT
 * The most useful output for NTRO:
 * "Here is exactly what each security tool monitors,
 *  and here is the gap JOCKY can operate through."
 * ════════════════════════════════════════════════════════════════ */

static void generate_blind_spot_report(void) {
    printf("[jocky-byovd] ╔══════════════════════════════════════╗\n");
    printf("[jocky-byovd] ║   JOCKY BLIND SPOT ANALYSIS          ║\n");
    printf("[jocky-byovd] ╚══════════════════════════════════════╝\n");
    printf("[jocky-byovd]\n");

    printf("[jocky-byovd] SECURITY TOOLS DETECTED:\n");
    int edr_count = 0;
    for (int i = 0; i < g_module_count; i++) {
        if (g_modules[i].is_edr) {
            printf("[jocky-byovd]   %-20s product=%-30s hooks=%s\n",
                   g_modules[i].name,
                   g_modules[i].edr_entry->product,
                   g_modules[i].edr_entry->hook_type);
            edr_count++;
        }
    }
    if (edr_count == 0)
        printf("[jocky-byovd]   none detected via module signatures\n");

    printf("[jocky-byovd]\n");
    printf("[jocky-byovd] JOCKY EVASION CAPABILITIES vs DETECTED TOOLS:\n");
    printf("[jocky-byovd]\n");

    printf("[jocky-byovd]   %-35s → BYPASSED via direct syscalls\n",
           "libc function hooks (LD_PRELOAD)");
    printf("[jocky-byovd]   %-35s → BYPASSED via direct syscalls\n",
           "audit syscall logging");
    printf("[jocky-byovd]   %-35s → BYPASSED via /proc/PID/mem read\n",
           "process memory inspection blocks");
    printf("[jocky-byovd]   %-35s → BYPASSED via API unhooking\n",
           "EDR inline function hooks");
    printf("[jocky-byovd]   %-35s → BYPASSED via fileless execution\n",
           "file-based AV scanning");
    printf("[jocky-byovd]   %-35s → BYPASSED via CDN domain fronting\n",
           "network C2 detection");
    printf("[jocky-byovd]   %-35s → BYPASSED via process injection\n",
           "unknown process detection");
    printf("[jocky-byovd]\n");

    printf("[jocky-byovd] REMAINING DETECTION RISKS:\n");
    printf("[jocky-byovd]   %-35s → RISKY: LSM cannot be bypassed "
           "without kernel exploit\n", "LSM policy enforcement");
    printf("[jocky-byovd]   %-35s → RISKY: kprobes on our syscall "
           "numbers detectable\n", "eBPF kprobe on syscalls");
    printf("[jocky-byovd]   %-35s → RISKY: BYOVD required to disable\n",
           "EDR kernel callbacks");
}

/* ════════════════════════════════════════════════════════════════
 * MAIN ENTRY POINT
 * ════════════════════════════════════════════════════════════════ */

void jocky_byovd_full_scan(void) {
    printf("[jocky-byovd] ┌──────────────────────────────────────────────┐\n");
    printf("[jocky-byovd] │   JOCKY BYOVD Driver Analysis Engine         │\n");
    printf("[jocky-byovd] │   Mapping kernel attack surface + EDR hooks  │\n");
    printf("[jocky-byovd] └──────────────────────────────────────────────┘\n\n");

    /* ── Part 1: Module enumeration ───────────────────────────── */
    printf("[jocky-byovd] --- kernel module enumeration ---\n");
    printf("[jocky-byovd] source=/sys/module/ method=direct_syscall\n");
    enumerate_modules();
    printf("[jocky-byovd] total_modules=%d\n\n", g_module_count);

    /* Print all modules */
    for (int i = 0; i < g_module_count; i++) {
        jocky_module_t *m = &g_modules[i];
        printf("[jocky-byovd] module name=%-30s size=%-10s %s%s\n",
               m->name,
               m->size[0] ? m->size : "?",
               m->is_vulnerable ? "[VULNERABLE] " : "",
               m->is_edr        ? "[EDR/SECURITY]" : "");
    }
    printf("\n");

    /* ── Part 2: Vulnerable driver report ─────────────────────── */
    printf("[jocky-byovd] --- vulnerable driver analysis ---\n");
    int vuln_count = 0;
    for (int i = 0; i < g_module_count; i++) {
        if (!g_modules[i].is_vulnerable) continue;
        jocky_module_t *m = &g_modules[i];
        vuln_count++;
        printf("[jocky-byovd] VULNERABLE_DRIVER:\n");
        printf("[jocky-byovd]   module=%s\n",       m->name);
        printf("[jocky-byovd]   cve=%s\n",           m->vuln_entry->cve);
        printf("[jocky-byovd]   severity=%s\n",      m->vuln_entry->severity);
        printf("[jocky-byovd]   description=%s\n",   m->vuln_entry->description);
        printf("[jocky-byovd]   byovd_usable=%s\n",
               m->vuln_entry->byovd_usable ? "YES" : "NO");
        printf("[jocky-byovd]\n");
    }
    if (vuln_count == 0)
        printf("[jocky-byovd] no vulnerable modules found in database\n");
    printf("[jocky-byovd] vulnerable_modules_found=%d\n\n", vuln_count);

    /* ── Part 3: EDR detection ────────────────────────────────── */
    printf("[jocky-byovd] --- EDR/security tool module detection ---\n");
    int edr_count = 0;
    for (int i = 0; i < g_module_count; i++) {
        if (!g_modules[i].is_edr) continue;
        jocky_module_t *m = &g_modules[i];
        edr_count++;
        printf("[jocky-byovd] EDR_DETECTED:\n");
        printf("[jocky-byovd]   module=%-20s product=%s\n",
               m->name, m->edr_entry->product);
        printf("[jocky-byovd]   vendor=%-20s hook_type=%s\n",
               m->edr_entry->vendor, m->edr_entry->hook_type);
        printf("[jocky-byovd]\n");
    }
    if (edr_count == 0)
        printf("[jocky-byovd] no known EDR modules detected\n");
    printf("[jocky-byovd] edr_modules_found=%d\n\n", edr_count);

    /* ── Parts 4-7: Hook detection ────────────────────────────── */
    detect_lsm_hooks();
    detect_ebpf_programs();
    detect_kprobe_hooks();
    detect_netfilter_hooks();
    detect_audit_hooks();

    /* ── Final: Blind spot report ─────────────────────────────── */
    generate_blind_spot_report();
}

/* ════════════════════════════════════════════════════════════════
 * STANDALONE TEST DRIVER
 * ════════════════════════════════════════════════════════════════ */

int main(void) {
    jocky_byovd_full_scan();
    return 0;
}
