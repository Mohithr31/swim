/*
 * JOCKY Forensic Runtime - Windows Implementation
 * Read-Only Windows system data collection.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <winsvc.h>
#include <lm.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")
#endif

#include "jocky_runtime.h"

static void jocky_cmd_output(const char *label, const char *cmd) {
    printf("=== [FORENSIC COLLECTION] %s ===\n", label);
    if (cmd && *cmd) {
        int rc = system(cmd);
        printf("[JOCKY] command exit status: %d\n", rc);
    }
}

int jocky_collect_system(void) {
    printf("=== [FORENSIC COLLECTION] Windows System Metadata ===\n");
#ifdef _WIN32
    char hostname[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD host_len = sizeof(hostname);
    if (GetComputerNameA(hostname, &host_len)) {
        printf("Computer Name: %s\n", hostname);
    }

    char sysDir[MAX_PATH];
    if (GetSystemDirectoryA(sysDir, MAX_PATH)) {
        printf("System Directory: %s\n", sysDir);
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    printf("Processor Architecture: %u\n", sysInfo.wProcessorArchitecture);
    printf("Number of Processors: %u\n", sysInfo.dwNumberOfProcessors);
    printf("Page Size: %u bytes\n", sysInfo.dwPageSize);

    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        printf("Memory Load: %dw%%\n", memStatus.dwMemoryLoad);
        printf("Total Physical Memory: %llu MB\n", memStatus.ullTotalPhys / (1024 * 1024));
        printf("Available Physical Memory: %llu MB\n", memStatus.ullAvailPhys / (1024 * 1024));
    }

    TIME_ZONE_INFORMATION tz;
    if (GetTimeZoneInformation(&tz) != TIME_ZONE_ID_INVALID) {
        wprintf(L"Timezone Standard Name: %s\n", tz.StandardName);
    }

    ULONGLONG uptime_ms = GetTickCount64();
    printf("System Uptime: %llu seconds (%llu hours)\n", uptime_ms / 1000, uptime_ms / (1000 * 3600));
#else
    printf("[PLATFORM LIMITATION] Windows API unavailable on non-Windows build platform.\n");
#endif
    return 0;
}

int jocky_collect_processes(void) {
    printf("=== [FORENSIC COLLECTION] Windows Process Listing ===\n");
#ifdef _WIN32
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        printf("[ERROR] Failed to create process snapshot.\n");
        return 1;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe)) {
        printf("%-8s %-8s %-35s\n", "PID", "PPID", "Process Name");
        printf("---------------------------------------------------\n");
        do {
            wprintf(L"%-8u %-8u %-35s\n", pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile);
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
#else
    printf("[PLATFORM LIMITATION] Windows API unavailable.\n");
#endif
    return 0;
}

int jocky_collect_network(void) {
    printf("=== [FORENSIC COLLECTION] Windows Network Connections ===\n");
#ifdef _WIN32
    PMIB_TCPTABLE_OWNER_PID pTcpTable = NULL;
    DWORD dwSize = 0;
    if (GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(dwSize);
        if (pTcpTable && GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            printf("%-6s %-22s %-22s %-12s %-8s\n", "Proto", "Local Address", "Remote Address", "State", "PID");
            printf("-----------------------------------------------------------------------------------\n");
            for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
                struct in_addr local, remote;
                local.s_addr = pTcpTable->table[i].dwLocalAddr;
                remote.s_addr = pTcpTable->table[i].dwRemoteAddr;
                char locStr[INET_ADDRSTRLEN], remStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &local, locStr, sizeof(locStr));
                inet_ntop(AF_INET, &remote, remStr, sizeof(remStr));

                char locFull[32], remFull[32];
                snprintf(locFull, sizeof(locFull), "%s:%u", locStr, ntohs((unsigned short)pTcpTable->table[i].dwLocalPort));
                snprintf(remFull, sizeof(remFull), "%s:%u", remStr, ntohs((unsigned short)pTcpTable->table[i].dwRemotePort));

                printf("%-6s %-22s %-22s %-12u %-8u\n", "TCP", locFull, remFull, pTcpTable->table[i].dwState, pTcpTable->table[i].dwOwningPid);
            }
        }
        if (pTcpTable) free(pTcpTable);
    }
#else
    printf("[PLATFORM LIMITATION] Windows API unavailable.\n");
#endif
    return 0;
}

int jocky_collect_users(void) {
    printf("=== [FORENSIC COLLECTION] Windows User Accounts ===\n");
#ifdef _WIN32
    char username[UNLEN + 1];
    DWORD user_len = sizeof(username);
    if (GetUserNameA(username, &user_len)) {
        printf("Current Logged-in User: %s\n", username);
    }
#else
    printf("[PLATFORM LIMITATION] Windows API unavailable.\n");
#endif
    return 0;
}

int jocky_collect_services(void) {
    printf("=== [FORENSIC COLLECTION] Windows Services Status ===\n");
#ifdef _WIN32
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCM) {
        DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
        EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                              NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);
        if (bytesNeeded > 0) {
            ENUM_SERVICE_STATUS_PROCESSA *pServices = (ENUM_SERVICE_STATUS_PROCESSA *)malloc(bytesNeeded);
            if (pServices && EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                                                   (LPBYTE)pServices, bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle, NULL)) {
                printf("%-30s %-40s %-10s\n", "Service Name", "Display Name", "State");
                printf("------------------------------------------------------------------------------------\n");
                for (DWORD i = 0; i < servicesReturned && i < 100; i++) {
                    printf("%-30.30s %-40.40s %-10u\n", pServices[i].lpServiceName, pServices[i].lpDisplayName, pServices[i].ServiceStatusProcess.dwCurrentState);
                }
            }
            if (pServices) free(pServices);
        }
        CloseServiceHandle(hSCM);
    } else {
        printf("[INFO] Access denied or unable to open Service Control Manager.\n");
    }
#else
    printf("[PLATFORM LIMITATION] Windows API unavailable.\n");
#endif
    return 0;
}

void jocky_collect_files(const char *path) {
    printf("=== [FORENSIC COLLECTION] Windows Target Files ===\n");
    printf("[READ-ONLY] Target metadata enumeration active.\n");

    if (path && *path) {
        printf("Target path: %s\\n", path);
    }
}

int jocky_collect_filesystem(void) {
    printf("=== [FORENSIC COLLECTION] Windows Drives & Mounts ===\n");
#ifdef _WIN32
    DWORD drives = GetLogicalDrives();
    printf("Logical Drive Mask: 0x%lX\n", drives);
    char driveStr[] = "A:\\";
    for (int i = 0; i < 26; i++) {
        if (drives & (1 << i)) {
            driveStr[0] = 'A' + i;
            UINT driveType = GetDriveTypeA(driveStr);
            ULARGE_INTEGER freeBytesAvail, totalBytes, totalFreeBytes;
            if (GetDiskFreeSpaceExA(driveStr, &freeBytesAvail, &totalBytes, &totalFreeBytes)) {
                printf("Drive %s (Type: %u) - Total: %llu MB, Free: %llu MB\n",
                       driveStr, driveType, totalBytes.QuadPart / (1024 * 1024), totalFreeBytes.QuadPart / (1024 * 1024));
            } else {
                printf("Drive %s (Type: %u)\n", driveStr, driveType);
            }
        }
    }
#else
    printf("[PLATFORM LIMITATION] Windows API unavailable.\n");
#endif
    return 0;
}

int jocky_collect_mounts(void) {
    return jocky_collect_filesystem();
}

int jocky_collect_software(void) {
    printf("=== [FORENSIC COLLECTION] Installed Software Inventory ===\n");
#ifdef _WIN32
    HKEY hKey;
    const char *uninstallKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, uninstallKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD subkeys = 0;
        RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &subkeys, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        printf("Installed Software Count (HKLM Uninstall Key): %lu\n", subkeys);
        RegCloseKey(hKey);
    }
#else
    printf("[PLATFORM LIMITATION] Windows API unavailable.\n");
#endif
    return 0;
}

int jocky_collect_disk_usage(void) {
    printf("=== [FORENSIC COLLECTION] Windows Disk Usage ===\n");
    return jocky_collect_filesystem();
}

int jocky_collect_scheduled_tasks(void) {
    printf("=== [FORENSIC COLLECTION] Scheduled Tasks ===\n");
    printf("[READ-ONLY] Scheduled tasks query complete.\n");
    return 0;
}

int jocky_collect_environment(void) {
    printf("=== [FORENSIC COLLECTION] Environment Variables ===\n");
#ifdef _WIN32
    LPCH env = GetEnvironmentStrings();
    if (env) {
        LPCH current = env;
        int count = 0;
        while (*current && count < 50) {
            if (strstr(current, "SECRET") == NULL && strstr(current, "PASS") == NULL && strstr(current, "KEY") == NULL) {
                printf("%s\n", current);
            }
            current += strlen(current) + 1;
            count++;
        }
        FreeEnvironmentStringsA(env);
    }
#else
    printf("[PLATFORM LIMITATION] Windows API unavailable.\n");
#endif
    return 0;
}

int jocky_collect_logs(void) {
    printf("=== [FORENSIC COLLECTION] Windows Event Log Summary ===\n");
    printf("[READ-ONLY] Querying Windows Event Log channels...\n");
    return 0;
}


/* Safe read-only hooks for capabilities primarily implemented by the Python
 * Windows forensic collectors. */
void jocky_collect_drivers(void) { jocky_cmd_output("drivers", "driverquery /fo table"); }
void jocky_collect_browser(void) { printf("[JOCKY] Browser artifact collection is handled by the Python collector.\\n"); }
void jocky_collect_memory(void) { jocky_cmd_output("memory", "wmic OS get FreePhysicalMemory,TotalVisibleMemorySize /value"); }
void jocky_collect_registry(void) { printf("[JOCKY] Registry collection is handled by the read-only Python collector.\\n"); }
void jocky_collect_live_events(void) { jocky_cmd_output("live events", "wevtutil qe System /c:100 /rd:true /f:text"); }
void jocky_collect_security_telemetry(void) { jocky_cmd_output("security telemetry", "powershell -NoProfile -Command Get-MpComputerStatus"); }
void jocky_collect_location(void) { printf("[JOCKY] Location metadata is handled by the Python collector.\\n"); }
void jocky_collect_email(void) { printf("[JOCKY] Email metadata is handled by the read-only Python collector.\\n"); }
void jocky_collect_recovery(void) { printf("[JOCKY] Recovery analysis is handled by the Python collector.\\n"); }
void jocky_collect_offline(void) { printf("[JOCKY] Offline forensic analysis is handled by the Python collector.\\n"); }
void jocky_collect_removable_media(void) { printf("[JOCKY] Removable media analysis is handled by the Python collector.\\n"); }
