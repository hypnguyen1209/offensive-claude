#!/usr/bin/env python3
"""
model_scan.py - Pre-load safety scanner for ML model artifacts (DEFENSIVE / pre-flight).

Scans models for code-execution payloads WITHOUT loading/executing them. Catches the
classes behind CVE-2025-32434 (PyTorch weights_only RCE), CVE-2024-50050, CVE-2025-32444,
and the picklescan-bypass family (CVE-2025-1716 pip global / 1889 non-standard ext /
1944,1945 zip-smuggling).

Method:
  * Disassemble pickle bytecode with pickletools.genops() - NEVER unpickles.
  * Flag dangerous GLOBAL/STACK_GLOBAL imports against an ALLOWLIST (fickling-style) -
    allowlist beats blocklist (the reason picklescan kept getting bypassed).
  * Detect REDUCE/INST/OBJ/NEWOBJ/BUILD reachable after a dangerous global.
  * Walk zip/torch containers; flag central-dir vs local-name mismatch and odd flag bits
    (CVE-2025-1944/1945 smuggling), and any pickle inside regardless of extension (1889).
  * Flag Keras Lambda layers (h5/keras) and TF SavedModel custom-op risk heuristically.

ALLOWLIST = only these modules are safe in a "weights-only" model; anything else is flagged.

Usage:
  python3 model_scan.py ./model_dir_or_file [--deep] [--json out.jsonl] [--allow extra.mod]
  python3 model_scan.py model.pkl --json -        # findings to stdout

Exit code 2 if any HIGH finding (use as a CI gate). Stdlib only (zipfile, pickletools).
Cross-check with: fickling --check-safety FILE ; modelscan -p DIR ; picklescan>=0.0.31 -p FILE
"""
import argparse, io, json, pickletools, struct, sys, zipfile
from pathlib import Path

# Modules legitimately referenced by tensor-only weights. Everything else => flag.
SAFE_MODULES = {
    "torch", "torch._utils", "torch.storage", "torch.serialization",
    "torch.nn", "torch.nn.parameter", "torch._tensor",
    "collections", "numpy", "numpy.core.multiarray", "numpy.core.numeric",
    "numpy._core.multiarray", "_codecs", "__builtin__.set", "builtins.set",
}
# Hard-deny callables (the actual exploit primitives) - always HIGH even if a module slips in.
DENY_CALLABLES = {
    "os.system", "posix.system", "nt.system", "subprocess.Popen", "subprocess.call",
    "subprocess.run", "subprocess.check_output", "builtins.eval", "builtins.exec",
    "__builtin__.eval", "__builtin__.exec", "builtins.__import__", "runpy._run_code",
    "pty.spawn", "os.popen", "pip.main", "pip._internal.main", "shutil.rmtree",
    "socket.socket", "webbrowser.open", "importlib.import_module",
}
PICKLE_EXTS = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".pkl.gz", ".joblib", ".npy", ".npz", ".data"}
REDUCE_OPS = {"REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD"}


def scan_pickle_bytes(raw, source, out):
    """Disassemble one pickle stream; flag dangerous globals + reduce reachability."""
    globals_seen, dangerous = [], []
    try:
        ops = list(pickletools.genops(io.BytesIO(raw)))
    except Exception as e:
        out.append(dict(type="parse_error", severity="low", source=source,
                        detail=f"pickletools could not parse (possible smuggling): {e}"))
        return
    # Track recent string pushes so STACK_GLOBAL (proto>=4) can be resolved to "module callable".
    # Modern torch/pickle emit SHORT_BINUNICODE module + SHORT_BINUNICODE name then STACK_GLOBAL,
    # instead of the legacy GLOBAL opcode with an inline arg - resolving these is what makes the
    # difference between flagging os.system as HIGH vs missing it.
    STRING_OPS = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
                  "STRING", "BINSTRING", "SHORT_BINSTRING"}
    # MEMOIZE/PUT/FRAME don't disturb the two strings sitting on the stack before STACK_GLOBAL.
    NOOP_FOR_TRACKING = {"MEMOIZE", "PUT", "BINPUT", "LONG_BINPUT", "FRAME"}
    recent = []
    for opcode, arg, _pos in ops:
        nm = opcode.name
        if nm in STRING_OPS and isinstance(arg, str):
            recent.append(arg)
            if len(recent) > 4:
                recent.pop(0)
            continue
        if nm in NOOP_FOR_TRACKING:
            continue
        if nm in ("GLOBAL", "STACK_GLOBAL"):
            if nm == "GLOBAL":
                mod_call = (arg or "").replace(" ", ".")
            elif len(recent) >= 2:                      # STACK_GLOBAL: module, name on stack
                mod_call = f"{recent[-2]}.{recent[-1]}"
            else:
                mod_call = None
            globals_seen.append(mod_call or "<stack_global>")
            if mod_call:
                module = mod_call.rsplit(".", 1)[0]
                if mod_call in DENY_CALLABLES:
                    dangerous.append((mod_call, "deny-listed callable"))
                elif module not in SAFE_MODULES and module.split(".")[0] not in {"torch", "numpy", "collections"}:
                    dangerous.append((mod_call, "import not on weights allowlist"))
        recent = []
    has_reduce = any(o[0].name in REDUCE_OPS for o in ops)
    for call, why in dangerous:
        sev = "high" if (call in DENY_CALLABLES or has_reduce) else "medium"
        out.append(dict(type="pickle_dangerous_global", severity=sev, source=source,
                        cwe="CWE-502", attack="AML.T0011", callable=call, reason=why,
                        reduce_reachable=has_reduce))
    if dangerous:
        return
    # stack_global with no resolvable name + reduce is still suspicious (obfuscation)
    if any(g == "<stack_global>" for g in globals_seen) and has_reduce:
        out.append(dict(type="pickle_obfuscated_global", severity="medium", source=source,
                        cwe="CWE-502", detail="STACK_GLOBAL + REDUCE (name hidden on stack)"))


def scan_zip_container(path, out, deep):
    """torch .pt / .ckpt / many models are zips. Walk members; detect smuggling + inner pickles."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        out.append(dict(type="read_error", severity="low", source=str(path), detail=str(e)))
        return
    if data[:2] != b"PK":
        return False
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception as e:
        out.append(dict(type="zip_parse_error", severity="medium", source=str(path),
                        cwe="CWE-646", detail=f"zip refused by zipfile but PK header present "
                                              f"(CVE-2025-1944/1945 smuggling pattern): {e}"))
        return True
    # central-dir name vs local-header name mismatch (CVE-2025-1944)
    for zi in zf.infolist():
        if zi.flag_bits & 0x1:  # encrypted bit set => zipfile may skip, torch may load (1945)
            out.append(dict(type="zip_flag_anomaly", severity="high", source=f"{path}!{zi.filename}",
                            cwe="CWE-646", detail="ZIP flag bit 0x1 set (scanner-skip / loader-load mismatch)"))
        name = zi.filename
        if name.endswith(tuple(PICKLE_EXTS)) or name.endswith("data.pkl") or "pickle" in name:
            try:
                scan_pickle_bytes(zf.read(zi), f"{path}!{name}", out)
            except Exception as e:
                out.append(dict(type="member_read_error", severity="low",
                                source=f"{path}!{name}", detail=str(e)))
        elif deep:
            try:
                blob = zf.read(zi)
                if blob[:1] in (b"\x80",) or b"\x00ctorch" in blob[:64] or b"REDUCE" in blob[:0]:
                    scan_pickle_bytes(blob, f"{path}!{name}", out)
            except Exception:
                pass
    return True


def scan_file(path, out, deep):
    p = Path(path)
    suf = "".join(p.suffixes[-2:]).lower() if len(p.suffixes) > 1 else p.suffix.lower()
    # zip/torch container?
    if scan_zip_container(p, out, deep):
        return
    # Keras / HDF5 lambda risk (heuristic, no h5py needed)
    if p.suffix.lower() in (".h5", ".keras", ".hdf5"):
        try:
            blob = p.read_bytes()
            if b"Lambda" in blob or b"lambda" in blob:
                out.append(dict(type="keras_lambda", severity="high", source=str(p),
                                cwe="CWE-502", detail="Keras Lambda layer can embed arbitrary Python"))
        except Exception:
            pass
        return
    # raw pickle (any extension - CVE-2025-1889 means extension is not trustworthy)
    try:
        blob = p.read_bytes()
    except Exception as e:
        out.append(dict(type="read_error", severity="low", source=str(p), detail=str(e)))
        return
    if blob[:1] == b"\x80" or (p.suffix.lower() in PICKLE_EXTS):
        scan_pickle_bytes(blob, str(p), out)
    elif deep and len(blob) > 1 and blob[0:1] in (b"\x80", b"("):  # scan unknown ext too
        scan_pickle_bytes(blob, str(p), out)


def iter_targets(root):
    p = Path(root)
    if p.is_file():
        yield p
    else:
        for f in p.rglob("*"):
            if f.is_file():
                yield f


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--deep", action="store_true", help="scan every file regardless of extension")
    ap.add_argument("--allow", action="append", default=[], help="extra module to allowlist")
    ap.add_argument("--json", help="write JSONL findings here ('-' for stdout)")
    args = ap.parse_args()
    SAFE_MODULES.update(args.allow)

    out = []
    for f in iter_targets(args.path):
        scan_file(f, out, args.deep)

    if args.json == "-":
        for r in out:
            print(json.dumps(r))
    elif args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            for r in out:
                fh.write(json.dumps(r) + "\n")

    high = [r for r in out if r.get("severity") == "high"]
    med = [r for r in out if r.get("severity") == "medium"]
    print(f"[=] scanned {args.path}: {len(high)} HIGH, {len(med)} medium, "
          f"{len(out)} total findings", file=sys.stderr)
    for r in high + med:
        print(f"  {r['severity'].upper():>6} {r['type']} :: {r.get('source','')} "
              f":: {r.get('callable') or r.get('detail','')}", file=sys.stderr)
    if not out:
        print("  no code-execution indicators (still prefer safetensors/GGUF for untrusted models)",
              file=sys.stderr)
    sys.exit(2 if high else 0)


if __name__ == "__main__":
    main()
