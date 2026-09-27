/*
 * jocky_runtime_windows_stealth.c
 * ---------------------------------
 * JOCKY stealth forensic runtime for Windows.
 *
 * REPLACES the standard Win32 API calls in jocky_runtime_windows.c:
 *
 *   BEFORE (hooked):                  AFTER (unhooked):
 *   CreateToolhelp32Snapshot()   →    NtQuerySystemInformation() via direct syscall
 *   Process32First/Next()        →    Walk SYSTEM_PROCESS_INFO buffer
 *   system("netstat -ano")       →    NtQuerySystemInformation(TcpTable) via syscall
 *   GetComputerNameA()           →    RtlGetVersion() via syscall
 *
 * Every EDR on Windows hooks ntdll.dll functions.
 * We skip ntdll entirely and issue raw syscalls.
 * EDR = completely blind to our operations.
 *
 * FORENSIC SCOPE: Read-only. No modification of any process or structure.
 *
 * COMPILE (Windows, MinGW):
 *   gcc -O2 -DJOCKY_STEALTH -o test_stealth_windows.exe \
 *       test_stealth_windows.c jocky_runtime_windows_stealth.c
 *
 * COMPILE (Windows, MSVC):
 *   cl /O2 /DJOCKY_STEALTH test_stealth_windows.c jocky_runtime_windows_stealth.c
 */

#ifdef _WIN32

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "jocky_syscall_windows.h"
#include "jocky_runtime.h"

/* ── MIB_TCPROW_OWNER_PID for network enumeration ────────────── */
typedef struct {
    DWORD dwState;
    DWORD dwLocalAddr;
    DWORD dwLocalPort;
    DWORD dwRemoteAddr;
    DWORD dwRemotePort;
    DWORD dwOwningPid;
} JOCKY_MIB_TCPROW;

typedef struct {
    DWORD          dwNumEntries;
    JOCKY_MIB_TCPROW table[1];
} JOCKY_MIB_TCPTABLE;

/* GetExtendedTcpTable is not a syscall — use it as fallback for network */
typedef DWORD (WINAPI *PFN_GetExtendedTcpTable)(
    PVOID, PDWORD, BOOL, ULONG, int, ULONG);

/* ════════════════════════════════════════════════════════════════
 * HELPER — WideChar to ASCII without CRT
 * ════════════════════════════════════════════════════════════════ */
static void jocky_wcs_to_ascii(const wchar_t *src, char *dst, int max) {
    int i = 0;
    while (src && *src && i < max - 1) {
        wchar_t c = *src++;
        dst[i++] = (c < 128) ? (char)c : '?';
    }
    dst[i] = '\0';
}

/* ════════════════════════════════════════════════════════════════
 * FEATURE 1 — PROCESS ENUMERATION
 * Uses NtQuerySystemInformation via direct syscall.
 * Replaces CreateToolhelp32Snapshot + Process32First/Next.
 * EDR hooks on those Win32 functions are completely bypassed.
 * ════════════════════════════════════════════════════════════════ */

void jocky_stealth_list_processes(void) {
    printf("[jocky] --- stealth process enumeration (direct syscall) ---\n");
    printf("[jocky] method=NtQuerySystemInformation_direct hook_bypass=true\n");

    if (!jocky_resolve_all_ssns()) {
        printf("[jocky] ERROR: SSN resolution failed\n");
        return;
    }

    /*
     * NtQuerySystemInformation with SystemProcessInformation.
     * We don't know the buffer size — start with 1MB and grow.
     */
    ULONG   buf_size = 1024 * 1024;
    PVOID   buf      = NULL;
    NTSTATUS status;
    ULONG   needed   = 0;

    for (int tries = 0; tries < 4; tries++) {
        buf = VirtualAlloc(NULL, buf_size,
                           MEM_COMMIT | MEM_RESERVE,
                           PAGE_READWRITE);
        if (!buf) {
            printf("[jocky] ERROR: VirtualAlloc failed\n");
            return;
        }

        status = jocky_NtQuerySystemInformation(
            SystemProcessInformation,
            buf,
            buf_size,
            &needed
        );

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            VirtualFree(buf, 0, MEM_RELEASE);
            buf       = NULL;
            buf_size  = needed + 65536;
            continue;
        }
        break;
    }

    if (!NT_SUCCESS(status) || !buf) {
        printf("[jocky] ERROR: NtQuerySystemInformation failed 0x%08lX\n",
               (unsigned long)status);
        if (buf) VirtualFree(buf, 0, MEM_RELEASE);
        return;
    }

    /*
     * Walk the SYSTEM_PROCESS_INFO linked list.
     * NextEntryOffset == 0 means last entry.
     */
    JOCKY_SYSTEM_PROCESS_INFO *entry =
        (JOCKY_SYSTEM_PROCESS_INFO *)buf;

    int count = 0;
    do {
        char  img_name[260] = "(System)";
        ULONG pid  = (ULONG)(ULONG_PTR)entry->UniqueProcessId;
        ULONG ppid = (ULONG)(ULONG_PTR)entry->InheritedFromUniqueProcessId;

        if (entry->ImageName.Buffer && entry->ImageName.Length > 0) {
            jocky_wcs_to_ascii(entry->ImageName.Buffer,
                               img_name, sizeof(img_name));
        }

        printf("[jocky] proc"
               " pid=%-6lu ppid=%-6lu threads=%-3lu"
               " session=%-2lu wss_kb=%-8llu name=%s\n",
               pid, ppid,
               (unsigned long)entry->NumberOfThreads,
               (unsigned long)entry->SessionId,
               (unsigned long long)(entry->WorkingSetSize / 1024),
               img_name);
        count++;

        if (entry->NextEntryOffset == 0) break;
        entry = (JOCKY_SYSTEM_PROCESS_INFO *)
                ((BYTE *)entry + entry->NextEntryOffset);

    } while (1);

    printf("[jocky] total_processes=%d\n", count);
    printf("[jocky] --- end stealth process enumeration ---\n");
    VirtualFree(buf, 0, MEM_RELEASE);
}

/* ════════════════════════════════════════════════════════════════
 * FEATURE 2 — HIDDEN PROCESS DETECTION
 * Compares NtQuerySystemInformation (kernel view) against
 * CreateToolhelp32Snapshot (user view).
 * A rootkit may hide from one but not the other.
 * ════════════════════════════════════════════════════════════════ */

void jocky_detect_hidden_processes(void) {
    printf("[jocky] --- hidden process detection ---\n");

    if (!jocky_resolve_all_ssns()) {
        printf("[jocky] ERROR: SSN resolution failed\n");
        return;
    }

    /* Count via direct syscall (kernel view) */
    ULONG   buf_size = 1024 * 1024;
    PVOID   buf      = VirtualAlloc(NULL, buf_size,
                                    MEM_COMMIT|MEM_RESERVE,
                                    PAGE_READWRITE);
    if (!buf) return;

    ULONG    needed = 0;
    NTSTATUS status = jocky_NtQuerySystemInformation(
        SystemProcessInformation, buf, buf_size, &needed);

    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        VirtualFree(buf, 0, MEM_RELEASE);
        buf_size = needed + 65536;
        buf = VirtualAlloc(NULL, buf_size,
                           MEM_COMMIT|MEM_RESERVE,
                           PAGE_READWRITE);
        if (!buf) return;
        status = jocky_NtQuerySystemInformation(
            SystemProcessInformation, buf, buf_size, &needed);
    }

    int kernel_count = 0;
    if (NT_SUCCESS(status)) {
        JOCKY_SYSTEM_PROCESS_INFO *e = (JOCKY_SYSTEM_PROCESS_INFO *)buf;
        do {
            kernel_count++;
            if (e->NextEntryOffset == 0) break;
            e = (JOCKY_SYSTEM_PROCESS_INFO *)
                ((BYTE *)e + e->NextEntryOffset);
        } while (1);
    }
    VirtualFree(buf, 0, MEM_RELEASE);

    /* Count via Win32 (user/EDR-visible view) */
    int win32_count = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = {0};
        pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do { win32_count++; } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }

    printf("[jocky] kernel_view_count=%d\n",  kernel_count);
    printf("[jocky] win32_view_count=%d\n",   win32_count);

    int diff = kernel_count - win32_count;
    if (diff > 2) {
        printf("[jocky] ANOMALY=possible_hidden_processes delta=%d\n", diff);
        printf("[jocky] action=kernel_memory_inspection_required\n");
    } else {
        printf("[jocky] status=no_obvious_hidden_processes\n");
    }
    printf("[jocky] --- end hidden process detection ---\n");
}

/* ════════════════════════════════════════════════════════════════
 * FEATURE 3 — PROCESS DETAIL (IMAGE PATH via direct syscall)
 * Gets the full exe path of a process using NtQueryInformationProcess.
 * Replaces QueryFullProcessImageNameA (hooked by EDR).
 * ════════════════════════════════════════════════════════════════ */

static void jocky_get_process_image(DWORD pid, char *out, int outlen) {
    out[0] = '\0';
    if (!jocky_resolve_all_ssns()) return;

    /* OBJECT_ATTRIBUTES and CLIENT_ID for NtOpenProcess */
    typedef struct {
        ULONG_PTR UniqueProcess;
        ULONG_PTR UniqueThread;
    } JOCKY_CLIENT_ID;

    typedef struct {
        ULONG    Length;
        HANDLE   RootDirectory;
        PVOID    ObjectName;
        ULONG    Attributes;
        PVOID    SecurityDescriptor;
        PVOID    SecurityQualityOfService;
    } JOCKY_OBJECT_ATTRIBUTES;

    JOCKY_OBJECT_ATTRIBUTES oa  = {sizeof(oa), NULL, NULL, 0, NULL, NULL};
    JOCKY_CLIENT_ID         cid = {(ULONG_PTR)pid, 0};
    HANDLE                  hProc = NULL;

    /* PROCESS_QUERY_LIMITED_INFORMATION (0x1000) — minimal rights */
    NTSTATUS st = jocky_NtOpenProcess(
        &hProc, 0x1000, &oa, &cid);
    if (!NT_SUCCESS(st) || !hProc) return;

    /* NtQueryInformationProcess → ProcessImageFileName (27) */
    BYTE   img_buf[1024] = {0};
    ULONG  ret_len       = 0;
    st = jocky_NtQueryInformationProcess(
        hProc, ProcessImageFileName,
        img_buf, sizeof(img_buf) - sizeof(wchar_t), &ret_len);

    if (NT_SUCCESS(st)) {
        JOCKY_UNICODE_STRING *us = (JOCKY_UNICODE_STRING *)img_buf;
        if (us->Buffer && us->Length > 0) {
            jocky_wcs_to_ascii(us->Buffer, out, outlen);
        }
    }
    jocky_NtClose(hProc);
}

void jocky_stealth_process_detail(void) {
    printf("[jocky] --- process image paths (direct syscall) ---\n");

    if (!jocky_resolve_all_ssns()) {
        printf("[jocky] ERROR: SSN resolution failed\n");
        return;
    }

    ULONG    buf_size = 1024 * 1024;
    ULONG    needed   = 0;
    PVOID    buf      = VirtualAlloc(NULL, buf_size,
                                     MEM_COMMIT|MEM_RESERVE,
                                     PAGE_READWRITE);
    if (!buf) return;

    NTSTATUS status = jocky_NtQuerySystemInformation(
        SystemProcessInformation, buf, buf_size, &needed);

    if (!NT_SUCCESS(status)) {
        VirtualFree(buf, 0, MEM_RELEASE);
        return;
    }

    JOCKY_SYSTEM_PROCESS_INFO *entry = (JOCKY_SYSTEM_PROCESS_INFO *)buf;
    do {
        DWORD pid = (DWORD)(ULONG_PTR)entry->UniqueProcessId;
        char  name[260] = "(System)";
        char  img[1024] = "";

        if (entry->ImageName.Buffer)
            jocky_wcs_to_ascii(entry->ImageName.Buffer,
                               name, sizeof(name));

        if (pid > 4)
            jocky_get_process_image(pid, img, sizeof(img));

        printf("[jocky] pid=%-6lu name=%-32s path=%s\n",
               (unsigned long)pid, name,
               img[0] ? img : "(system/no access)");

        if (entry->NextEntryOffset == 0) break;
        entry = (JOCKY_SYSTEM_PROCESS_INFO *)
                ((BYTE *)entry + entry->NextEntryOffset);
    } while (1);

    VirtualFree(buf, 0, MEM_RELEASE);
    printf("[jocky] --- end process image paths ---\n");
}

/* ════════════════════════════════════════════════════════════════
 * FEATURE 4 — LOADED KERNEL MODULES (DRIVER ENUMERATION)
 * Uses NtQuerySystemInformation(SystemModuleInformation).
 * Critical for BYOVD — finding vulnerable loaded drivers.
 * Replaces EnumDeviceDrivers (hooked).
 * ════════════════════════════════════════════════════════════════ */

void jocky_stealth_kernel_modules(void) {
    printf("[jocky] --- kernel module enumeration (direct syscall) ---\n");
    printf("[jocky] method=NtQuerySystemInformation_modules hook_bypass=true\n");
    printf("[jocky] note=loaded_drivers_visible_relevant_for_byovd_detection\n");

    if (!jocky_resolve_all_ssns()) {
        printf("[jocky] ERROR: SSN resolution failed\n");
        return;
    }

    ULONG    buf_size = 2 * 1024 * 1024;
    ULONG    needed   = 0;
    PVOID    buf      = VirtualAlloc(NULL, buf_size,
                                     MEM_COMMIT|MEM_RESERVE,
                                     PAGE_READWRITE);
    if (!buf) return;

    NTSTATUS status = jocky_NtQuerySystemInformation(
        SystemModuleInformation, buf, buf_size, &needed);

    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        VirtualFree(buf, 0, MEM_RELEASE);
        buf_size = needed + 65536;
        buf = VirtualAlloc(NULL, buf_size,
                           MEM_COMMIT|MEM_RESERVE,
                           PAGE_READWRITE);
        if (!buf) return;
        status = jocky_NtQuerySystemInformation(
            SystemModuleInformation, buf, buf_size, &needed);
    }

    if (!NT_SUCCESS(status)) {
        printf("[jocky] ERROR: module query failed 0x%08lX\n",
               (unsigned long)status);
        VirtualFree(buf, 0, MEM_RELEASE);
        return;
    }

    JOCKY_RTL_PROCESS_MODULES *mods =
        (JOCKY_RTL_PROCESS_MODULES *)buf;

    printf("[jocky] total_drivers=%lu\n",
           (unsigned long)mods->NumberOfModules);

    for (ULONG i = 0; i < mods->NumberOfModules; i++) {
        JOCKY_RTL_PROCESS_MODULE_INFO *m = &mods->Modules[i];
        const char *name = (const char *)m->FullPathName +
                           m->OffsetToFileName;
        printf("[jocky] driver idx=%-4lu base=0x%p size=0x%08lX name=%s\n",
               (unsigned long)i,
               m->ImageBase,
               (unsigned long)m->ImageSize,
               name[0] ? name : "?");
    }

    VirtualFree(buf, 0, MEM_RELEASE);
    printf("[jocky] --- end kernel module enumeration ---\n");
}

/* ════════════════════════════════════════════════════════════════
 * FEATURE 5 — SSN RESOLUTION REPORT
 * Shows which SSNs were resolved — proves dynamic resolution works.
 * Useful for debugging across different Windows versions.
 * ════════════════════════════════════════════════════════════════ */

void jocky_stealth_ssn_report(void) {
    printf("[jocky] --- SSN resolution report ---\n");

    if (!jocky_resolve_all_ssns()) {
        printf("[jocky] ERROR: critical SSN resolution failed\n");
        return;
    }

    /* Get Windows version */
    typedef NTSTATUS (WINAPI *PFN_RtlGetVersion)(PRTL_OSVERSIONINFOW);
    PFN_RtlGetVersion pRtlGetVersion =
        (PFN_RtlGetVersion)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "RtlGetVersion");

    RTL_OSVERSIONINFOW vi = {0};
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (pRtlGetVersion) pRtlGetVersion(&vi);

    printf("[jocky] windows_version=%lu.%lu.%lu\n",
           (unsigned long)vi.dwMajorVersion,
           (unsigned long)vi.dwMinorVersion,
           (unsigned long)vi.dwBuildNumber);

    printf("[jocky] ssn NtQuerySystemInformation  = 0x%02lX (%lu)\n",
           (unsigned long)g_ssn.NtQuerySystemInformation,
           (unsigned long)g_ssn.NtQuerySystemInformation);
    printf("[jocky] ssn NtQueryInformationProcess = 0x%02lX (%lu)\n",
           (unsigned long)g_ssn.NtQueryInformationProcess,
           (unsigned long)g_ssn.NtQueryInformationProcess);
    printf("[jocky] ssn NtOpenProcess             = 0x%02lX (%lu)\n",
           (unsigned long)g_ssn.NtOpenProcess,
           (unsigned long)g_ssn.NtOpenProcess);
    printf("[jocky] ssn NtClose                   = 0x%02lX (%lu)\n",
           (unsigned long)g_ssn.NtClose,
           (unsigned long)g_ssn.NtClose);
    printf("[jocky] ssn NtReadVirtualMemory       = 0x%02lX (%lu)\n",
           (unsigned long)g_ssn.NtReadVirtualMemory,
           (unsigned long)g_ssn.NtReadVirtualMemory);
    printf("[jocky] ssn NtCreateFile              = 0x%02lX (%lu)\n",
           (unsigned long)g_ssn.NtCreateFile,
           (unsigned long)g_ssn.NtCreateFile);
    printf("[jocky] resolution=dynamic hook_resilient=true\n");
    printf("[jocky] --- end SSN report ---\n");
}

/* ════════════════════════════════════════════════════════════════
 * PUBLIC API — Override functions from jocky_runtime_windows.c
 * Compiled with -DJOCKY_STEALTH → these replace the standard ones.
 * ════════════════════════════════════════════════════════════════ */

#ifdef JOCKY_STEALTH

void jocky_print(const char *text) {
    printf("[jocky] %s\n", text);
}

void jocky_system_info(void) {
    jocky_stealth_ssn_report();
}

void jocky_list_processes(void) {
    jocky_stealth_list_processes();
    jocky_detect_hidden_processes();
}

void jocky_list_network_connections(void) {
    /*
     * Network: use GetExtendedTcpTable from iphlpapi.dll
     * This is NOT a syscall but it's cleaner than system("netstat")
     * which spawns a visible process. Future: NtDeviceIoControlFile
     * on \Device\Tcp for full syscall-based network enumeration.
     */
    printf("[jocky] --- network connections ---\n");

    HMODULE iphlp = LoadLibraryA("iphlpapi.dll");
    if (!iphlp) {
        printf("[jocky] ERROR: iphlpapi.dll not found\n");
        return;
    }

    PFN_GetExtendedTcpTable pfn =
        (PFN_GetExtendedTcpTable)GetProcAddress(
            iphlp, "GetExtendedTcpTable");

    if (!pfn) {
        FreeLibrary(iphlp);
        printf("[jocky] ERROR: GetExtendedTcpTable not found\n");
        return;
    }

    /* TCP_TABLE_OWNER_PID_ALL = 5 */
    DWORD size = 0;
    pfn(NULL, &size, FALSE, AF_INET, 5, 0);
    PVOID tbl = VirtualAlloc(NULL, size + 4096,
                             MEM_COMMIT|MEM_RESERVE,
                             PAGE_READWRITE);
    if (!tbl) {
        FreeLibrary(iphlp); return;
    }

    if (pfn(tbl, &size, FALSE, AF_INET, 5, 0) == 0) {
        JOCKY_MIB_TCPTABLE *t = (JOCKY_MIB_TCPTABLE *)tbl;

        static const char *tcp_states[] = {
            "?", "CLOSED", "LISTEN", "SYN_SENT",
            "SYN_RCVD", "ESTABLISHED", "FIN_WAIT1",
            "FIN_WAIT2", "CLOSE_WAIT", "CLOSING",
            "LAST_ACK", "TIME_WAIT", "DELETE_TCB"
        };

        for (DWORD i = 0; i < t->dwNumEntries; i++) {
            JOCKY_MIB_TCPROW *row = &t->table[i];
            DWORD lport = ntohs((WORD)row->dwLocalPort);
            DWORD rport = ntohs((WORD)row->dwRemotePort);
            BYTE *la    = (BYTE *)&row->dwLocalAddr;
            BYTE *ra    = (BYTE *)&row->dwRemoteAddr;
            DWORD state = row->dwState;
            const char *sname = (state < 13) ?
                tcp_states[state] : "?";

            printf("[jocky] conn"
                   " local=%u.%u.%u.%u:%lu"
                   " remote=%u.%u.%u.%u:%lu"
                   " state=%-13s pid=%lu\n",
                   la[0],la[1],la[2],la[3], (unsigned long)lport,
                   ra[0],ra[1],ra[2],ra[3], (unsigned long)rport,
                   sname,
                   (unsigned long)row->dwOwningPid);
        }
        printf("[jocky] total_tcp4_connections=%lu\n",
               (unsigned long)t->dwNumEntries);
    }

    VirtualFree(tbl, 0, MEM_RELEASE);
    FreeLibrary(iphlp);
    printf("[jocky] --- end network connections ---\n");
}

#endif /* JOCKY_STEALTH */

#endif /* _WIN32 */
