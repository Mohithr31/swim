/*
 * jocky_syscall_windows.h
 * ------------------------
 * Windows direct syscall interface for JOCKY forensic runtime.
 *
 * WHY THIS EXISTS:
 *   The existing jocky_runtime_windows.c uses:
 *     CreateToolhelp32Snapshot()   <- EDR hook here
 *     Process32First/Next()        <- EDR hook here
 *     netstat (system call)        <- EDR hook + process creation alert
 *     GetComputerNameA()           <- EDR hook here
 *
 *   Every one of those calls passes through ntdll.dll where
 *   CrowdStrike, SentinelOne, Wazuh etc. install their hooks.
 *   The EDR intercepts the call, inspects it, logs it, blocks it.
 *
 * HOW DIRECT SYSCALLS WORK ON WINDOWS x64:
 *
 *   Normal path:
 *     Your code → kernel32.dll → ntdll.dll → syscall
 *                                  ↑ EDR hook lives here
 *
 *   Direct syscall path:
 *     Your code → syscall instruction directly
 *                  EDR never sees it
 *
 *   The syscall instruction needs a number (SSN — System Service Number).
 *   SSN tells the kernel WHICH operation to perform.
 *   SSN for NtQuerySystemInformation might be 0x36 on Windows 10 22H2
 *   but 0x37 on Windows 11 — it changes between versions.
 *
 * DYNAMIC SSN RESOLUTION (our approach):
 *   Instead of hardcoding SSNs (which break across Windows versions),
 *   we READ the SSN directly from ntdll.dll on disk.
 *   We parse ntdll's export table, find each NT function,
 *   read its first 5 bytes: "mov eax, SSN" → extract SSN.
 *   This works on every Windows version automatically.
 *
 * FORENSIC SCOPE:
 *   All syscalls here perform READ-ONLY operations.
 *   No process modification. No code injection. No privilege escalation.
 *   We read what the kernel knows — same as Task Manager, just unhooked.
 */

#ifndef JOCKY_SYSCALL_WINDOWS_H
#define JOCKY_SYSCALL_WINDOWS_H

#ifdef _WIN32

#include <windows.h>
#include <stdint.h>

/* ── Windows NT type definitions ─────────────────────────────── */
typedef LONG   NTSTATUS;
typedef ULONG  ACCESS_MASK;

#define NT_SUCCESS(s)        ((NTSTATUS)(s) >= 0)
#define STATUS_SUCCESS       ((NTSTATUS)0x00000000)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)

/* ── NtQuerySystemInformation classes ────────────────────────── */
#define SystemProcessInformation        5
#define SystemModuleInformation         11
#define SystemHandleInformation         16

/* ── NtQueryInformationProcess classes ───────────────────────── */
#define ProcessBasicInformation         0
#define ProcessImageFileName            27
#define ProcessCommandLineInformation   60

/* ── Unicode string (kernel format) ──────────────────────────── */
typedef struct _JOCKY_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} JOCKY_UNICODE_STRING;

/* ── System process information block ───────────────────────── */
typedef struct _JOCKY_SYSTEM_THREAD_INFO {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG         WaitTime;
    PVOID         StartAddress;
    PVOID         UniqueProcess;
    PVOID         UniqueThread;
    LONG          Priority;
    LONG          BasePriority;
    ULONG         ContextSwitches;
    ULONG         ThreadState;
    ULONG         WaitReason;
} JOCKY_SYSTEM_THREAD_INFO;

typedef struct _JOCKY_SYSTEM_PROCESS_INFO {
    ULONG                    NextEntryOffset;
    ULONG                    NumberOfThreads;
    LARGE_INTEGER            WorkingSetPrivateSize;
    ULONG                    HardFaultCount;
    ULONG                    NumberOfThreadsHighWatermark;
    ULONGLONG                CycleTime;
    LARGE_INTEGER            CreateTime;
    LARGE_INTEGER            UserTime;
    LARGE_INTEGER            KernelTime;
    JOCKY_UNICODE_STRING     ImageName;
    LONG                     BasePriority;
    HANDLE                   UniqueProcessId;
    HANDLE                   InheritedFromUniqueProcessId;
    ULONG                    HandleCount;
    ULONG                    SessionId;
    ULONG_PTR                UniqueProcessKey;
    SIZE_T                   PeakVirtualSize;
    SIZE_T                   VirtualSize;
    ULONG                    PageFaultCount;
    SIZE_T                   PeakWorkingSetSize;
    SIZE_T                   WorkingSetSize;
    SIZE_T                   QuotaPeakPagedPoolUsage;
    SIZE_T                   QuotaPagedPoolUsage;
    SIZE_T                   QuotaPeakNonPagedPoolUsage;
    SIZE_T                   QuotaNonPagedPoolUsage;
    SIZE_T                   PagefileUsage;
    SIZE_T                   PeakPagefileUsage;
    SIZE_T                   PrivatePageCount;
    LARGE_INTEGER            ReadOperationCount;
    LARGE_INTEGER            WriteOperationCount;
    LARGE_INTEGER            OtherOperationCount;
    LARGE_INTEGER            ReadTransferCount;
    LARGE_INTEGER            WriteTransferCount;
    LARGE_INTEGER            OtherTransferCount;
    JOCKY_SYSTEM_THREAD_INFO Threads[1];
} JOCKY_SYSTEM_PROCESS_INFO;

/* ── Process basic information ───────────────────────────────── */
typedef struct _JOCKY_PROCESS_BASIC_INFO {
    NTSTATUS  ExitStatus;
    PVOID     PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} JOCKY_PROCESS_BASIC_INFO;

/* ── RTL_PROCESS_MODULES for driver enumeration ──────────────── */
typedef struct _JOCKY_RTL_PROCESS_MODULE_INFO {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} JOCKY_RTL_PROCESS_MODULE_INFO;

typedef struct _JOCKY_RTL_PROCESS_MODULES {
    ULONG                          NumberOfModules;
    JOCKY_RTL_PROCESS_MODULE_INFO  Modules[1];
} JOCKY_RTL_PROCESS_MODULES;

/* ════════════════════════════════════════════════════════════════
 * DYNAMIC SSN RESOLUTION
 * Reads SSNs from ntdll.dll on disk — no hardcoded version tables
 * ════════════════════════════════════════════════════════════════ */

/*
 * jocky_resolve_ssn
 *
 * Finds the System Service Number for a given NT function
 * by reading its first bytes from ntdll.dll's loaded image.
 *
 * On x64 Windows, every NT syscall stub looks like:
 *   mov r10, rcx        ; 4C 8B D1
 *   mov eax, SSN        ; B8 XX XX 00 00   ← SSN is bytes 1-4
 *   syscall             ; 0F 05
 *   ret                 ; C3
 *
 * We find the function in ntdll's export table,
 * read byte index 4 (the SSN low byte),
 * and that's our syscall number.
 *
 * Returns -1 if function not found.
 */
static DWORD jocky_resolve_ssn(const char *func_name) {
    /* Get ntdll base — it is always loaded */
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return (DWORD)-1;

    /* Parse ntdll export table */
    PIMAGE_DOS_HEADER dos =
        (PIMAGE_DOS_HEADER)(ULONG_PTR)ntdll;
    PIMAGE_NT_HEADERS nt =
        (PIMAGE_NT_HEADERS)((ULONG_PTR)ntdll + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports =
        (PIMAGE_EXPORT_DIRECTORY)(
            (ULONG_PTR)ntdll +
            nt->OptionalHeader
              .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
              .VirtualAddress
        );

    DWORD  *names    = (DWORD *)((ULONG_PTR)ntdll + exports->AddressOfNames);
    WORD   *ordinals = (WORD  *)((ULONG_PTR)ntdll + exports->AddressOfNameOrdinals);
    DWORD  *funcs    = (DWORD *)((ULONG_PTR)ntdll + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char *name = (const char *)((ULONG_PTR)ntdll + names[i]);
        if (strcmp(name, func_name) != 0) continue;

        /* Found — get function address */
        DWORD rva  = funcs[ordinals[i]];
        BYTE *stub = (BYTE *)((ULONG_PTR)ntdll + rva);

        /*
         * Verify stub signature: 4C 8B D1 B8 XX XX 00 00
         * If EDR has hooked this function, the first byte is JMP (0xE9)
         * In that case we still extract SSN by checking offset 4 of
         * the original stub — or fall back to ordinal-based SSN.
         */
        if (stub[0] == 0x4C && stub[1] == 0x8B &&
            stub[2] == 0xD1 && stub[3] == 0xB8) {
            /* Clean stub — read SSN directly */
            return *(DWORD *)(stub + 4);
        }

        /*
         * If hooked (stub starts with JMP):
         * Use ordinal-based fallback.
         * Sort all Nt* exports by address and use the index
         * as a proxy for SSN — accurate on most Windows versions.
         * This is the "Halo's Gate" fallback technique.
         */
        if (stub[0] == 0xE9) {
            /* Walk neighbouring exports to find unhoooked stub nearby */
            for (int delta = 1; delta <= 32; delta++) {
                /* check stub + delta*stub_size */
                if (i + delta < exports->NumberOfNames) {
                    DWORD  next_rva  = funcs[ordinals[i + delta]];
                    BYTE  *next_stub = (BYTE *)((ULONG_PTR)ntdll + next_rva);
                    if (next_stub[0] == 0x4C && next_stub[1] == 0x8B &&
                        next_stub[2] == 0xD1 && next_stub[3] == 0xB8) {
                        DWORD next_ssn = *(DWORD *)(next_stub + 4);
                        return next_ssn - delta;  /* walk back to ours */
                    }
                }
                if (i >= (DWORD)delta) {
                    DWORD  prev_rva  = funcs[ordinals[i - delta]];
                    BYTE  *prev_stub = (BYTE *)((ULONG_PTR)ntdll + prev_rva);
                    if (prev_stub[0] == 0x4C && prev_stub[1] == 0x8B &&
                        prev_stub[2] == 0xD1 && prev_stub[3] == 0xB8) {
                        DWORD prev_ssn = *(DWORD *)(prev_stub + 4);
                        return prev_ssn + delta;
                    }
                }
            }
        }

        return (DWORD)-1;
    }
    return (DWORD)-1;
}

/* ── SSN cache — resolve once, use many times ────────────────── */
typedef struct {
    DWORD NtQuerySystemInformation;
    DWORD NtQueryInformationProcess;
    DWORD NtOpenProcess;
    DWORD NtClose;
    DWORD NtReadVirtualMemory;
    DWORD NtAllocateVirtualMemory;
    DWORD NtFreeVirtualMemory;
    DWORD NtCreateFile;
    DWORD NtReadFile;
    DWORD NtQueryVolumeInformationFile;
    int   resolved;
} JOCKY_SSN_TABLE;

static JOCKY_SSN_TABLE g_ssn = {0};

static int jocky_resolve_all_ssns(void) {
    if (g_ssn.resolved) return 1;

    g_ssn.NtQuerySystemInformation  = jocky_resolve_ssn("NtQuerySystemInformation");
    g_ssn.NtQueryInformationProcess = jocky_resolve_ssn("NtQueryInformationProcess");
    g_ssn.NtOpenProcess             = jocky_resolve_ssn("NtOpenProcess");
    g_ssn.NtClose                   = jocky_resolve_ssn("NtClose");
    g_ssn.NtReadVirtualMemory       = jocky_resolve_ssn("NtReadVirtualMemory");
    g_ssn.NtAllocateVirtualMemory   = jocky_resolve_ssn("NtAllocateVirtualMemory");
    g_ssn.NtFreeVirtualMemory       = jocky_resolve_ssn("NtFreeVirtualMemory");
    g_ssn.NtCreateFile              = jocky_resolve_ssn("NtCreateFile");
    g_ssn.NtReadFile                = jocky_resolve_ssn("NtReadFile");

    if (g_ssn.NtQuerySystemInformation == (DWORD)-1 ||
        g_ssn.NtOpenProcess            == (DWORD)-1) {
        return 0;  /* critical SSNs missing */
    }
    g_ssn.resolved = 1;
    return 1;
}

/* ════════════════════════════════════════════════════════════════
 * SYSCALL STUB — x64 Windows
 *
 * Executes a raw syscall with up to 8 arguments.
 * This is the core evasion mechanism.
 *
 * We use a small trampoline allocated in executable memory
 * rather than inline asm (which MSVC doesn't support for x64).
 * MinGW (gcc) on Windows DOES support inline asm.
 * ════════════════════════════════════════════════════════════════ */

/* Syscall stub shellcode template for x64 Windows:
 *   4C 8B D1        mov r10, rcx
 *   B8 XX XX XX XX  mov eax, SSN
 *   0F 05           syscall
 *   C3              ret
 */
static unsigned char g_stub_template[10] = {
    0x4C, 0x8B, 0xD1,              /* mov r10, rcx */
    0xB8, 0x00, 0x00, 0x00, 0x00,  /* mov eax, SSN (patch bytes 4-7) */
    0x0F, 0x05,                    /* syscall */
    /* ret is appended when we build the stub */
};

/* Trampoline buffer — allocated RWX so we can execute it */
static void   *g_trampoline  = NULL;

typedef NTSTATUS (*JockyStub)(
    ULONG_PTR a1, ULONG_PTR a2, ULONG_PTR a3, ULONG_PTR a4,
    ULONG_PTR a5, ULONG_PTR a6, ULONG_PTR a7, ULONG_PTR a8
);

/*
 * jocky_syscall
 * Executes a direct syscall with the given SSN and arguments.
 * Bypasses ntdll.dll entirely — EDR hook never triggered.
 */
static NTSTATUS jocky_syscall(DWORD ssn,
    ULONG_PTR a1, ULONG_PTR a2, ULONG_PTR a3, ULONG_PTR a4,
    ULONG_PTR a5, ULONG_PTR a6, ULONG_PTR a7, ULONG_PTR a8)
{
    if (g_trampoline == NULL) {
        /* Allocate executable memory for the stub — once */
        g_trampoline = VirtualAlloc(NULL, 16,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
        if (!g_trampoline) return (NTSTATUS)0xC0000001;
    }

    /* Patch the SSN into the stub */
    unsigned char stub[11];
    memcpy(stub, g_stub_template, 10);
    stub[4] = (BYTE)(ssn & 0xFF);
    stub[5] = (BYTE)((ssn >> 8)  & 0xFF);
    stub[6] = (BYTE)((ssn >> 16) & 0xFF);
    stub[7] = (BYTE)((ssn >> 24) & 0xFF);
    stub[10] = 0xC3; /* ret */

    /* Write stub into executable buffer */
    memcpy(g_trampoline, stub, 11);
    FlushInstructionCache(GetCurrentProcess(), g_trampoline, 11);

    /* Call it */
    JockyStub fn = (JockyStub)g_trampoline;
    return fn(a1, a2, a3, a4, a5, a6, a7, a8);
}

/* ── Typed wrappers ───────────────────────────────────────────── */

static NTSTATUS jocky_NtQuerySystemInformation(
    ULONG   SystemInformationClass,
    PVOID   SystemInformation,
    ULONG   SystemInformationLength,
    PULONG  ReturnLength)
{
    return jocky_syscall(
        g_ssn.NtQuerySystemInformation,
        (ULONG_PTR)SystemInformationClass,
        (ULONG_PTR)SystemInformation,
        (ULONG_PTR)SystemInformationLength,
        (ULONG_PTR)ReturnLength,
        0, 0, 0, 0
    );
}

static NTSTATUS jocky_NtOpenProcess(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    PVOID              ObjectAttributes,
    PVOID              ClientId)
{
    return jocky_syscall(
        g_ssn.NtOpenProcess,
        (ULONG_PTR)ProcessHandle,
        (ULONG_PTR)DesiredAccess,
        (ULONG_PTR)ObjectAttributes,
        (ULONG_PTR)ClientId,
        0, 0, 0, 0
    );
}

static NTSTATUS jocky_NtQueryInformationProcess(
    HANDLE  ProcessHandle,
    ULONG   ProcessInformationClass,
    PVOID   ProcessInformation,
    ULONG   ProcessInformationLength,
    PULONG  ReturnLength)
{
    return jocky_syscall(
        g_ssn.NtQueryInformationProcess,
        (ULONG_PTR)ProcessHandle,
        (ULONG_PTR)ProcessInformationClass,
        (ULONG_PTR)ProcessInformation,
        (ULONG_PTR)ProcessInformationLength,
        (ULONG_PTR)ReturnLength,
        0, 0, 0
    );
}

static NTSTATUS jocky_NtClose(HANDLE Handle) {
    return jocky_syscall(
        g_ssn.NtClose,
        (ULONG_PTR)Handle,
        0, 0, 0, 0, 0, 0, 0
    );
}

static NTSTATUS jocky_NtReadVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  BufferSize,
    PSIZE_T NumberOfBytesRead)
{
    return jocky_syscall(
        g_ssn.NtReadVirtualMemory,
        (ULONG_PTR)ProcessHandle,
        (ULONG_PTR)BaseAddress,
        (ULONG_PTR)Buffer,
        (ULONG_PTR)BufferSize,
        (ULONG_PTR)NumberOfBytesRead,
        0, 0, 0
    );
}

/* ── Cleanup ─────────────────────────────────────────────────── */
static void jocky_syscall_cleanup(void) {
    if (g_trampoline) {
        VirtualFree(g_trampoline, 0, MEM_RELEASE);
        g_trampoline = NULL;
    }
}

#endif /* _WIN32 */
#endif /* JOCKY_SYSCALL_WINDOWS_H */
