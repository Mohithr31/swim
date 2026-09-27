#ifndef JOCKY_RUNTIME_H
#define JOCKY_RUNTIME_H

#ifdef _WIN32
#define JOCKY_RET int
#else
#define JOCKY_RET void
#endif

void jocky_print(const char *text);
void jocky_system_info(void);
void jocky_list_processes(void);
void jocky_list_users(void);
void jocky_list_network_connections(void);
void jocky_file_info(const char *path);
void jocky_sha256_file(const char *path);
void jocky_collect_files(const char *path);

JOCKY_RET jocky_collect_system(void);
JOCKY_RET jocky_collect_processes(void);
JOCKY_RET jocky_collect_network(void);
JOCKY_RET jocky_collect_users(void);
JOCKY_RET jocky_collect_logs(void);
JOCKY_RET jocky_collect_filesystem(void);
JOCKY_RET jocky_collect_services(void);
JOCKY_RET jocky_collect_software(void);
JOCKY_RET jocky_collect_scheduled_tasks(void);
JOCKY_RET jocky_collect_environment(void);
JOCKY_RET jocky_collect_mounts(void);
JOCKY_RET jocky_collect_disk_usage(void);
JOCKY_RET jocky_collect_network_config(void);

void jocky_collect_drivers(void);
void jocky_collect_browser(void);
void jocky_collect_memory(void);
void jocky_collect_registry(void);
void jocky_collect_live_events(void);
void jocky_collect_security_telemetry(void);
void jocky_collect_location(void);
void jocky_collect_email(void);
void jocky_collect_recovery(void);
void jocky_collect_offline(void);
void jocky_collect_removable_media(void);

#undef JOCKY_RET
#endif
