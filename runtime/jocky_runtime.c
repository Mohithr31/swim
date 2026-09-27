#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <ctype.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <time.h>
#include <openssl/evp.h>
#include "jocky_runtime.h"

void jocky_print(const char *text) { printf("[jocky] %s\n", text); }

static int is_pid_dir(const char *name) {
    if (!name || !*name) return 0;
    for (const char *p = name; *p; ++p) if (!isdigit((unsigned char)*p)) return 0;
    return 1;
}

void jocky_system_info(void) {
    FILE *f = fopen("/etc/os-release", "r");
    printf("[jocky] --- system information ---\n");
    char host[256] = {0}; if (gethostname(host, sizeof(host)-1) == 0) printf("[jocky] hostname=%s\n", host);
    printf("[jocky] kernel=%s\n", "linux");
    char line[512];
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (!strncmp(line, "PRETTY_NAME=", 12)) { line[strcspn(line, "\r\n")] = 0; printf("[jocky] %s\n", line); break; }
        }
        fclose(f);
    }
    printf("[jocky] --- end system information ---\n");
}

void jocky_list_processes(void) {
    DIR *proc = opendir("/proc");
    if (!proc) { fprintf(stderr, "[jocky] error: could not open /proc: %s\n", strerror(errno)); return; }
    printf("[jocky] --- process enumeration start ---\n");
    struct dirent *entry; int count = 0;
    while ((entry = readdir(proc)) != NULL) {
        if (!is_pid_dir(entry->d_name)) continue;
        char path[300]; snprintf(path, sizeof(path), "/proc/%s/comm", entry->d_name);
        FILE *f = fopen(path, "r"); if (!f) continue;
        char comm[256] = {0};
        if (fgets(comm, sizeof(comm), f)) { comm[strcspn(comm, "\r\n")] = 0; printf("[jocky] pid=%-7s comm=%s\n", entry->d_name, comm); count++; }
        fclose(f);
    }
    printf("[jocky] --- %d processes enumerated ---\n", count); closedir(proc);
}

void jocky_list_users(void) {
    FILE *f = fopen("/etc/passwd", "r");
    if (!f) { fprintf(stderr, "[jocky] error: cannot read /etc/passwd: %s\n", strerror(errno)); return; }
    printf("[jocky] --- local users ---\n");
    char line[1024]; int count = 0;
    while (fgets(line, sizeof(line), f)) {
        char copy[1024]; strncpy(copy, line, sizeof(copy)); copy[sizeof(copy)-1] = 0;
        char *name = strtok(copy, ":"), *x = strtok(NULL, ":");
        char *uid = strtok(NULL, ":"), *gid = strtok(NULL, ":");
        (void)x;
        strtok(NULL, ":");
        char *home = strtok(NULL, ":");
        if (name && uid && gid) { printf("[jocky] user=%s uid=%s gid=%s home=%s\n", name, uid, gid, home ? home : ""); count++; }
    }
    printf("[jocky] --- %d users enumerated ---\n", count); fclose(f);
}

static void print_proc_net(const char *path, const char *proto) {
    FILE *f = fopen(path, "r"); if (!f) return;
    char line[1024]; int first = 1;
    while (fgets(line, sizeof(line), f)) {
        if (first) { first = 0; continue; }
        char local[64] = {0}, remote[64] = {0}; unsigned state = 0;
        if (sscanf(line, "%*d: %63s %63s %2x", local, remote, &state) >= 3)
            printf("[jocky] proto=%s local=%s remote=%s state=%02x\n", proto, local, remote, state);
    }
    fclose(f);
}

void jocky_list_network_connections(void) {
    printf("[jocky] --- network connection snapshot ---\n");
    print_proc_net("/proc/net/tcp", "tcp");
    print_proc_net("/proc/net/udp", "udp");
    printf("[jocky] --- end network snapshot ---\n");
}

void jocky_file_info(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) { fprintf(stderr, "[jocky] file_info: %s: %s\n", path, strerror(errno)); return; }
    printf("[jocky] --- file information ---\n");
    printf("[jocky] path=%s\n", path);
    printf("[jocky] size=%lld\n", (long long)st.st_size);
    printf("[jocky] mode=%o\n", (unsigned)(st.st_mode & 07777));
    printf("[jocky] uid=%u gid=%u\n", (unsigned)st.st_uid, (unsigned)st.st_gid);
    printf("[jocky] mtime=%lld\n", (long long)st.st_mtime);
    printf("[jocky] inode=%lld\n", (long long)st.st_ino);
    printf("[jocky] --- end file information ---\n");
}

void jocky_sha256_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "[jocky] sha256: %s: %s\n", path, strerror(errno)); return; }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); unsigned char buf[8192], digest[EVP_MAX_MD_SIZE]; unsigned int len = 0; size_t n;
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) { fprintf(stderr, "[jocky] sha256: initialization failed\n"); if (ctx) EVP_MD_CTX_free(ctx); fclose(f); return; }
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) EVP_DigestUpdate(ctx, buf, n);
    if (ferror(f) || EVP_DigestFinal_ex(ctx, digest, &len) != 1) { fprintf(stderr, "[jocky] sha256: read/hash failed\n"); EVP_MD_CTX_free(ctx); fclose(f); return; }
    printf("[jocky] sha256 path=%s hash=", path);
    for (unsigned int i = 0; i < len; ++i) printf("%02x", digest[i]);
    printf("\n"); EVP_MD_CTX_free(ctx); fclose(f);
}

void jocky_collect_files(const char *path) {
    DIR *d = opendir(path); if (!d) { fprintf(stderr,"[jocky] collect_files: %s: %s\n",path,strerror(errno)); return; }
    printf("[jocky] --- filesystem metadata: %s ---\n", path);
    struct dirent *e; while ((e=readdir(d))) {
        if (!strcmp(e->d_name,".") || !strcmp(e->d_name,"..")) continue;
        char p[4096]; snprintf(p,sizeof(p),"%s/%s",path,e->d_name); struct stat st;
        if (lstat(p,&st)==0) printf("[jocky] type=%s size=%lld mode=%o mtime=%lld path=%s\n",S_ISDIR(st.st_mode)?"dir":S_ISREG(st.st_mode)?"file":"other",(long long)st.st_size,(unsigned)(st.st_mode&07777),(long long)st.st_mtime,p);
    } closedir(d);
}

static void jocky_cmd_output(const char *label, const char *cmd) {
    printf("[jocky] --- %s ---\n", label); FILE *f=popen(cmd,"r"); if(!f){fprintf(stderr,"[jocky] command unavailable: %s\n",cmd);return;} char b[1024]; int n=0; while(fgets(b,sizeof(b),f)&&n++<1000) fputs(b,stdout); pclose(f);
}
void jocky_collect_services(void) { jocky_cmd_output("services", "systemctl list-units --type=service --no-pager --no-legend 2>/dev/null || true"); }
void jocky_collect_logs(void) { jocky_cmd_output("recent logs", "journalctl --no-pager -n 200 2>/dev/null || true"); }
void jocky_collect_mounts(void) { jocky_cmd_output("mounts", "findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null || mount"); }
void jocky_collect_software(void) { jocky_cmd_output("software", "dpkg-query -W -f='${Package}\\t${Version}\\n' 2>/dev/null || rpm -qa 2>/dev/null || true"); }

void jocky_collect_disk_usage(void) { jocky_cmd_output("disk usage", "df -hT"); }
void jocky_collect_network_config(void) { jocky_cmd_output("network configuration", "ip addr 2>/dev/null; echo ---; ip route 2>/dev/null; echo ---; cat /etc/resolv.conf 2>/dev/null || true"); }
void jocky_collect_scheduled_tasks(void) { jocky_cmd_output("scheduled tasks", "systemctl list-timers --all --no-pager 2>/dev/null; echo ---; find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly -maxdepth 1 -type f -print 2>/dev/null || true"); }
void jocky_collect_environment(void) { jocky_cmd_output("environment metadata", "env | grep -E -vi '(pass|token|secret|key|credential)' | sort"); }

/* Safe native hooks for operations whose richer collection is performed by
 * the Python forensic collectors. They deliberately collect only metadata
 * and do not modify security controls or execute untrusted input. */
void jocky_collect_drivers(void) { jocky_cmd_output("drivers", "lsmod 2>/dev/null || cat /proc/modules 2>/dev/null || true"); }
void jocky_collect_browser(void) { jocky_cmd_output("browser metadata", "printf '%s\\n' 'Browser artifact collection is handled by the JOCKY Python collector.'"); }
void jocky_collect_memory(void) { jocky_cmd_output("memory metadata", "free -h 2>/dev/null || true"); }
void jocky_collect_registry(void) { jocky_cmd_output("registry metadata", "printf '%s\\n' 'Registry collection is Windows-specific and handled by the Windows collector.'"); }
void jocky_collect_live_events(void) { jocky_cmd_output("live events", "journalctl --no-pager -n 100 2>/dev/null || true"); }
void jocky_collect_security_telemetry(void) { jocky_cmd_output("security telemetry", "printf '%s\\n' 'Read-only security telemetry hook.'"); }
void jocky_collect_location(void) { jocky_cmd_output("location metadata", "hostname 2>/dev/null || true"); }
void jocky_collect_email(void) { jocky_cmd_output("email metadata", "printf '%s\\n' 'Email analysis is handled by the read-only Python collector.'"); }
void jocky_collect_recovery(void) { jocky_cmd_output("recovery metadata", "printf '%s\\n' 'Recovery analysis is handled by the JOCKY forensic collector.'"); }
void jocky_collect_offline(void) { jocky_cmd_output("offline metadata", "printf '%s\\n' 'Offline forensic analysis is handled by the JOCKY forensic collector.'"); }
void jocky_collect_removable_media(void) { jocky_cmd_output("removable media", "printf '%s\\n' 'Removable media analysis is handled by the JOCKY forensic collector.'"); }

/* DSL aliases used by the LLVM Module backend. */
void jocky_collect_system(void) { jocky_system_info(); }
void jocky_collect_processes(void) { jocky_list_processes(); }
void jocky_collect_network(void) { jocky_list_network_connections(); }
void jocky_collect_users(void) { jocky_list_users(); }
void jocky_collect_filesystem(void) { jocky_cmd_output("filesystem", "find . -maxdepth 1 -type f -printf '%p\\n' 2>/dev/null | head -100"); }
