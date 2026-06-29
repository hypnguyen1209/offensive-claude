#!/usr/bin/env python3
"""
mcp_tool_audit.py - Static security auditor for MCP servers / agent tool schemas.

AUTHORIZED TESTING ONLY. OWASP LLM01/LLM06:2025 + OWASP Agentic AI.
Covers: tool poisoning (CVE-2025-54136 MCPoison / CVE-2025-54135 CurXecute),
command-injection RCE (CVE-2025-6514 mcp-remote, CVE-2025-53107 git-mcp),
rug-pull (manifest drift), and exfil-sink schema params.

Inputs (any combination):
  --config FILE        MCP client config JSON (e.g. claude_desktop_config.json /
                       servers.json) - lists servers; also scanned for inline tool defs.
  --manifest FILE      A tools manifest JSON: a list of {name,description,inputSchema}
                       or {"tools":[...]} (e.g. captured from tools/list).
  --src DIR            Server source tree to scan for command-injection sinks.
  --baseline FILE      Prior hashes JSON from a clean run; diff to detect rug-pull.

Output: JSONL findings on stdout (or --out), plus a human summary on stderr.

Usage:
  python3 mcp_tool_audit.py --manifest tools.json --src ./server/ --out out/mcp.jsonl
  python3 mcp_tool_audit.py --config ~/.config/Claude/claude_desktop_config.json
  # capture a baseline, then re-run later with --baseline to catch mutations:
  python3 mcp_tool_audit.py --manifest tools.json --emit-baseline base.json
  python3 mcp_tool_audit.py --manifest tools.json --baseline base.json

No third-party deps (stdlib only).
"""
import argparse, hashlib, json, re, sys
from pathlib import Path

# Imperative / instruction language hidden in tool metadata = tool poisoning.
POISON_PATTERNS = [
    (r"<\s*important\s*>", "hidden <IMPORTANT> directive block"),
    (r"<!--", "HTML comment in metadata (hidden instruction channel)"),
    (r"\bignore (all |the )?(previous|prior) instructions?\b", "instruction override"),
    (r"\bdo not (mention|tell|inform|reveal)\b", "stealth/withhold-from-user directive"),
    (r"\b(before|prior to) (answering|responding|calling)\b", "pre-action hijack"),
    (r"~/\.ssh|id_rsa|\.aws/credentials|\.env\b|secret|api[_\- ]?key|password|token",
     "credential/secret reference"),
    (r"\b(you must|the assistant must|always|first)\b.*\b(read|send|email|post|fetch|exec)\b",
     "imperative action directive"),
    (r"\bsupersedes? all\b", "authority-override phrasing"),
]

# Command-injection / RCE sinks in server source.
SINK_PATTERNS = [
    (r"child_process\.(exec|execSync)\s*\(", "Node exec (shell) - prefer execFile (CVE-2025-53107 class)"),
    (r"\bos\.system\s*\(", "Python os.system"),
    (r"subprocess\.(call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True", "subprocess shell=True"),
    (r"\beval\s*\(|\bexec\s*\(", "eval/exec dynamic code"),
    (r"pickle\.loads?\s*\(|recv_pyobj\s*\(", "pickle deserialization (CVE-2025-32444 class)"),
    (r"\brequests?\.(get|post)\s*\(\s*[a-zA-Z_]", "unrestricted URL fetch (SSRF/unbounded)"),
    (r"`[^`]*\$\{[^}]+\}[^`]*`", "JS template-string command interpolation"),
]

# Schema parameter names that look like exfiltration sinks.
EXFIL_PARAM = re.compile(r"\b(debug|context|raw|dump|all|internal|passthrough|callback|webhook|url)\b", re.I)


def finding(out, **kw):
    out.append(kw)


def text_of_tool(tool):
    parts = [str(tool.get("name", "")), str(tool.get("description", ""))]
    sch = tool.get("inputSchema") or tool.get("input_schema") or {}
    parts.append(json.dumps(sch))
    for prop in (sch.get("properties") or {}).values():
        parts.append(str(prop.get("description", "")))
    return "\n".join(parts)


def tool_hash(tool):
    blob = json.dumps({
        "name": tool.get("name"),
        "description": tool.get("description"),
        "inputSchema": tool.get("inputSchema") or tool.get("input_schema"),
    }, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


def audit_tool(tool, out, server="?"):
    name = tool.get("name", "<unnamed>")
    blob = text_of_tool(tool)
    low = blob.lower()
    for pat, desc in POISON_PATTERNS:
        if re.search(pat, low, re.I):
            finding(out, type="tool_poisoning", severity="high", server=server, tool=name,
                    cwe="CWE-74", attack="AML.T0053",
                    detail=desc, evidence=_snip(blob, pat))
    sch = tool.get("inputSchema") or tool.get("input_schema") or {}
    for pname in (sch.get("properties") or {}):
        if EXFIL_PARAM.search(pname):
            finding(out, type="exfil_sink_param", severity="medium", server=server, tool=name,
                    cwe="CWE-200", detail=f"parameter '{pname}' resembles an exfil/passthrough sink")
    return tool_hash(tool)


def _snip(text, pat):
    m = re.search(pat, text, re.I)
    if not m:
        return ""
    s = max(0, m.start() - 40)
    return text[s:m.end() + 60].replace("\n", " ")


def collect_tools(obj):
    """Pull tool dicts from a manifest (list, {tools:[...]}, or mcpServers config)."""
    tools = []
    if isinstance(obj, list):
        tools = [t for t in obj if isinstance(t, dict) and "name" in t]
    elif isinstance(obj, dict):
        if isinstance(obj.get("tools"), list):
            tools = obj["tools"]
        # inline tool defs sometimes embedded per server
        for srv in (obj.get("mcpServers") or obj.get("servers") or {}).values():
            if isinstance(srv, dict) and isinstance(srv.get("tools"), list):
                for t in srv["tools"]:
                    t.setdefault("_server", "config")
                    tools.append(t)
    return tools


def audit_config(path, out):
    """Scan a client config for risky launch specs (untrusted commands / remote servers)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    servers = data.get("mcpServers") or data.get("servers") or {}
    for name, srv in servers.items():
        cmd = " ".join([str(srv.get("command", ""))] + [str(a) for a in srv.get("args", [])])
        if re.search(r"mcp-remote\b", cmd):
            finding(out, type="risky_server", severity="high", server=name, cwe="CWE-78",
                    detail="uses mcp-remote (CVE-2025-6514 command-injection class); pin patched version",
                    evidence=cmd)
        if re.search(r"https?://", cmd) or srv.get("url", "").startswith("http"):
            finding(out, type="remote_server", severity="medium", server=name,
                    detail="remote/HTTP MCP server - verify provenance & TLS; subject to prompt-hijack (CVE-2025-6515)",
                    evidence=cmd or srv.get("url", ""))
        if re.search(r"npx\b|uvx\b|pip install|curl ", cmd):
            finding(out, type="dynamic_fetch_launch", severity="medium", server=name,
                    detail="server fetched/run at launch (rug-pull risk; pin a hash/version)", evidence=cmd)
    return collect_tools(data)


def audit_src(root, out):
    for f in Path(root).rglob("*"):
        if f.suffix.lower() not in (".js", ".ts", ".mjs", ".cjs", ".py", ".go", ".rb"):
            continue
        try:
            txt = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for i, line in enumerate(txt.splitlines(), 1):
            for pat, desc in SINK_PATTERNS:
                if re.search(pat, line):
                    finding(out, type="rce_sink", severity="high", file=str(f), line=i,
                            cwe="CWE-78", detail=desc, evidence=line.strip()[:160])


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config")
    ap.add_argument("--manifest")
    ap.add_argument("--src")
    ap.add_argument("--baseline")
    ap.add_argument("--emit-baseline", dest="emit_baseline")
    ap.add_argument("--out")
    args = ap.parse_args()

    out, hashes = [], {}
    tools = []
    if args.config:
        tools += audit_config(args.config, out)
    if args.manifest:
        tools += collect_tools(json.loads(Path(args.manifest).read_text(encoding="utf-8")))
    for t in tools:
        h = audit_tool(t, out, server=t.get("_server", "manifest"))
        hashes[t.get("name", "<unnamed>")] = h
    if args.src:
        audit_src(args.src, out)

    # rug-pull / drift detection
    if args.baseline:
        base = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        for name, h in hashes.items():
            if name in base and base[name] != h:
                finding(out, type="manifest_drift", severity="high", tool=name, cwe="CWE-74",
                        detail="tool definition changed vs baseline (rug-pull / CVE-2025-54136 mutation)")
        for name in base:
            if name not in hashes:
                finding(out, type="tool_removed", severity="low", tool=name,
                        detail="tool present in baseline now missing")
    if args.emit_baseline:
        Path(args.emit_baseline).write_text(json.dumps(hashes, indent=2))
        print(f"[+] baseline -> {args.emit_baseline} ({len(hashes)} tools)", file=sys.stderr)

    sink = sys.stdout if not args.out else open(args.out, "w", encoding="utf-8")
    for rec in out:
        sink.write(json.dumps(rec) + "\n")
    if args.out:
        sink.close()
    high = sum(1 for r in out if r.get("severity") == "high")
    print(f"[=] {len(out)} findings ({high} high) across {len(tools)} tools", file=sys.stderr)
    for r in out:
        if r.get("severity") == "high":
            print(f"  HIGH {r['type']}: {r.get('tool') or r.get('file') or r.get('server')} "
                  f"- {r['detail']}", file=sys.stderr)
    sys.exit(1 if high else 0)


if __name__ == "__main__":
    main()
