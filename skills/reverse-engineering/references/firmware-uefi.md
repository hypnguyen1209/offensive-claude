# Firmware Extraction, UEFI/BIOS RE & Secure Boot Bypass

Cluster: pulling code out of embedded/firmware images and analyzing the pre-OS attack surface — Linux/
RTOS firmware, and UEFI/BIOS (DXE/PEI/SMM, NVRAM, Secure Boot chain). ATT&CK: T1542.001 (Pre-OS Boot:
System Firmware), T1542.003 (Bootkit). CWE: CWE-1263 (Improper Physical Access Control to firmware),
CWE-347 (Improper Verification of Cryptographic Signature — the Secure Boot bypass class).

## Theory / Mechanism

Firmware persists below the OS on SPI flash / eMMC and survives disk wipes. Two analysis tracks:
1. **Embedded Linux/RTOS firmware:** carve the image (bootloader + kernel + root FS), mount the FS,
   hunt hardcoded creds/keys/services, then statically RE or QEMU-emulate the proprietary binaries.
2. **UEFI/BIOS:** a firmware volume (FV) holds PEI modules (early init) and DXE drivers (full hardware
   access pre-OS). **SMM** (System Management Mode, ring -2) handlers are reachable via SW SMI and are
   the highest-value target. **NVRAM** variables feed PEI/DXE and can overflow. The **Secure Boot**
   chain (UEFI → shim → GRUB/bootmgr → kernel) verifies signatures against `db`; `dbx` revokes known-bad
   hashes. A signed-but-vulnerable bootloader not yet in `dbx`, or a parser bug before verification,
   lets unsigned code run → persistent bootkit.

## Modern 2024-2026 Reality (verified)

- **LogoFAIL** (CVE-2023-40238 / Insyde; AMI CVE-2023-39539, CVE-2023-39538) — image-parsing bugs in
  UEFI logo libraries. A malicious boot logo (BMP/PNG/etc.) in the ESP or unsigned firmware section runs
  code during boot, bypassing Secure Boot and Intel Boot Guard. In late 2024 **Bootkitty** weaponized it
  as the *first Linux UEFI bootkit* — a tampered BMP with embedded shellcode injecting a rogue cert into
  `MokList`. (Bootkitty is a South Korean "Best of the Best" research project, not in-the-wild, with
  hardcoded offsets for specific Acer/HP/Fujitsu/Lenovo models.)
- **PKfail** (CVE-2024-8105) — OEMs shipped the AMI test Platform Key tagged `DO NOT TRUST` (and its
  *private* key leaked), so anyone can sign Secure Boot databases on ~800+ products from 10+ vendors
  (Acer, Dell, Fujitsu, Gigabyte, HP, Intel, Lenovo, Supermicro, plus Beelink/Minisforum/Hardkernel).
  Vulnerable firmware spans 2012-2024. Scan with Binarly's `pk.fail`.
- **CVE-2024-7344** (ESET, fixed Jan 2025) — a Microsoft-signed (`Microsoft Corporation UEFI CA 2011`)
  UEFI app `reloader.efi` (Howyar SysReturn + 6 other recovery products) uses a *custom PE loader*
  instead of `LoadImage`/`StartImage`, loading an unsigned binary from `cloak.dat` (magic `ALRM`, header
  XOR'd with `0xB3`). CWE-347. Revoked in the Jan 14 2025 `dbx` update. Vulnerable hashes:
  `cdb7c90d...9f9e48` (x64), `e9e4b5a5...5491b9` (x86).
- **BlackLotus** (CVE-2022-21894 "baton drop" / CVE-2023-24932) context: first commercial UEFI bootkit;
  abused a signed pre-patch Windows bootloader not yet in `dbx`, persists in the ESP, disables HVCI/
  BitLocker/Defender after boot. Demonstrates the "revocation lag" pattern all of the above share.
- **Tooling:** **CHIPSEC** for platform/firmware security checks + SPI dump; **UEFITool/UEFIExtract**
  and **uefi-firmware-parser** for volume/section/file extraction; **unblob** as a modern binwalk
  successor for carving; **fwhunt** (Binarly) YARA-style rules over UEFI modules.

## Complete Working Firmware RE

### 1. Carve & identify (this skill's script wraps these)
```bash
python3 scripts/uefi_triage.py firmware.bin -o out/fw/
# Detects: UEFI vs embedded-Linux; runs the right extractor; lists DXE/PEI modules or root FS;
# flags PKfail test-PK, known-vulnerable bootloader hashes (CVE-2024-7344), and 'ALRM' cloak.dat.
```
Manual equivalents:
```bash
binwalk -e firmware.bin                 # signature carve + auto-extract
unblob firmware.bin -e out/             # modern carver (handles more container types)
binwalk --dd='.*' firmware.bin          # extract everything
unsquashfs squashfs-root.img            # SquashFS root FS ; jefferson for JFFS2 ; ubidump for UBIFS
file _firmware.extracted/*              # identify carved blobs
```

### 2. Embedded-Linux loot & emulation
```bash
grep -RnaE '(password|passwd|root:|BEGIN (RSA|EC) PRIVATE KEY|api[_-]?key)' squashfs-root/ etc/
# Emulate a single MIPS/ARM service binary:
qemu-mipsel -L squashfs-root/ squashfs-root/usr/sbin/httpd
# Full-system emulation for interactive RE / fuzzing:
qemu-system-arm -M virt -kernel zImage -dtb board.dtb -drive file=rootfs.img,format=raw -nographic
# Greybox-fuzz the emulated parser with AFL++ + QEMU mode:
AFL_QEMU_PERSISTENT_ADDR=0x... afl-fuzz -Q -i seeds/ -o findings/ -- ./target_binary @@
```

### 3. UEFI volume & module analysis
```bash
UEFIExtract firmware.bin                       # → firmware.bin.dump/ tree of FVs/sections/files
# or: uefi-firmware-parser -e firmware.bin
# Load a DXE driver in Ghidra/IDA as TE/PE (x64), set image base from the section header.
# In the decompiler, pivot on the EFI tables:
#   gBS  (EFI_BOOT_SERVICES)    → LocateProtocol, InstallProtocolInterface
#   gRT  (EFI_RUNTIME_SERVICES) → GetVariable/SetVariable (NVRAM surface)
#   SW SMI dispatch (EFI_SMM_SW_DISPATCH2_PROTOCOL) → SMI handler = ring -2 target
# Hunt SMM callouts: a handler dereferencing a pointer that lives OUTSIDE SMRAM = classic SMM callout.
```

### 4. Secure Boot posture & bypass research (lab)
```bash
# Windows posture:
powershell Confirm-SecureBootUEFI           # True = enforcing
# Linux: list db/dbx + check a bootloader hash against dbx (CVE-2024-7344 style):
mokutil --sb-state
efi-readvar -v dbx -o dbx.esl               # then parse for revoked hashes
# CHIPSEC platform audit (Boot Guard, SMM, SPI protection, variable security):
sudo chipsec_main -m common.secureboot.variables
sudo chipsec_main -m common.spi_desc -m common.bios_wp
# PKfail check (is the Platform Key the AMI DO-NOT-TRUST test key?):
sudo chipsec_util uefi var-read PK 8be4df61-93ca-11d2-aa0d-00e098032b8c pk.bin
strings pk.bin | grep -i 'DO NOT TRUST'
# SPI flash dump (authorized; physical or software):
sudo chipsec_util spi dump rom.bin          # or flashrom -p internal -r rom.bin
```

## Detection

```yaml
title: Secure Boot / Firmware Tamper Indicators
id: fw-secureboot-0005
status: experimental
logsource: { product: windows, category: firmware }   # measured-boot / TPM + EDR firmware module
detection:
  pcr_drift:
    Source: 'TPM'
    Field|contains: ['PCR0', 'PCR2', 'PCR4', 'PCR7']    # boot-component / SecureBoot-policy PCRs
    State: 'changed'
  esp_write:
    TargetFilename|contains: '\EFI\'                     # unexpected ESP modification
    TargetFilename|endswith: '.efi'
  condition: pcr_drift or esp_write
level: high
tags: [attack.t1542.001, attack.t1542.003]
```
IOCs: TPM PCR[0/2/4/7] drift vs golden baseline; new/unsigned `.efi` in the ESP; `cloak.dat`/`ALRM`
magic on disk (CVE-2024-7344); AMI `DO NOT TRUST` PK present (PKfail); `MokList` mutation; revoked
bootloader hash still bootable. Defender tools: CHIPSEC modules, Binarly `fwhunt`/`pk.fail`, ESET UEFI
scanner, measured-boot attestation.

## OPSEC

- **Touches:** software SPI dumps via `chipsec`/`flashrom` read the flash (low risk); **flashing** a
  modified image is destructive and may brick the device + trips measured boot. ESP writes and
  `MokList`/`dbx` changes are durable, on-disk, and forensically obvious.
- **Cleanup:** keep a verified golden firmware image and ESP backup; restore after research. For
  authorized bootkit research use disposable hardware or VMs (OVMF/edk2 under QEMU), never persist a
  real implant past the engagement.
- **Evasion:** bypass research should target the *revocation lag* (signed-but-unrevoked loaders) only in
  the lab; do not strip `dbx` updates on production hosts. Confirm any "bypass" against measured boot
  (does the PoC actually evade PCR extension?) before claiming Secure Boot defeat.

## References

- LogoFAIL → Bootkitty (Binarly) — https://www.binarly.io/blog/logofail-exploited-to-deploy-bootkitty-the-first-uefi-bootkit-for-linux
- PKfail / CVE-2024-8105 (BleepingComputer) — https://www.bleepingcomputer.com/news/security/pkfail-secure-boot-bypass-lets-attackers-install-uefi-malware/
- CVE-2024-7344 — ESET "Under the cloak of UEFI Secure Boot" — https://www.welivesecurity.com/en/eset-research/under-cloak-uefi-secure-boot-introducing-cve-2024-7344/ ; CERT/CC VU#529659 — https://www.kb.cert.org/vuls/id/529659
- NSA "Guidance for Managing UEFI Secure Boot" (Dec 2025) — https://media.defense.gov/2025/Dec/11/2003841096/-1/-1/0/CSI_UEFI_SECURE_BOOT.PDF
- CHIPSEC — https://github.com/chipsec/chipsec ; UEFITool — https://github.com/LongSoft/UEFITool ; unblob — https://github.com/onekey-sec/unblob
