#!/usr/bin/env python3
"""variant_hunt.py - turn ONE confirmed bug into an exhaustive same-mistake-everywhere sweep.

CLAUDE.md mandates "VARIANT-COMPLETE" analysis, but a single confirmed finding does not tell you
how many siblings exist or whether one fix or many is needed. Given a seed (a vuln class / sink
pattern, or a confirmed finding), this:

  1. SWEEPS the tree for every sink of that class (reusing taint_trace's per-language sink model),
  2. QUALIFIES each hit by same-function taint reachability: tainted | likely | unlikely | false_positive,
  3. CLUSTERS by root cause (copy-paste vs shared-util vs framework-misuse) to answer "one fix or many",
  4. RANKS by exploitability and writes variants.json. False positives are KEPT (with a note) but
     excluded from the fix recommendation - never silently dropped.

This is a triage accelerator, not a prover: a 'tainted' label means "source reaches sink in one
function with no sanitizer on the path" - a strong lead a human/finding-validator must confirm.

Pure stdlib; reuses taint_trace.MODEL. Authorized source review only.

CLI:
  variant_hunt.py ./src --sink-cwe CWE-89 --lang py,js [--json variants.json]
  variant_hunt.py ./src --seed-finding finding.json [--json variants.json]
  variant_hunt.py ./src --sink-regex '\\.execute\\(' --lang py
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import taint_trace as tt  # noqa: E402

QUALITY_RANK = {"tainted": 3, "likely": 2, "unlikely": 1, "false_positive": 0}


def _containing_function(lines, func_rx, sink_idx):
    """Return (start_idx, body_lines) of the function containing sink_idx, or (sink_idx, [line])."""
    best_start = None
    for i, ln in enumerate(lines):
        if i > sink_idx:
            break
        if func_rx.search(ln):
            best_start = i
    if best_start is None:
        return sink_idx, [lines[sink_idx]] if sink_idx < len(lines) else (sink_idx, [])
    # body runs until the next function start after best_start
    end = len(lines)
    for j in range(best_start + 1, len(lines)):
        if func_rx.search(lines[j]):
            end = j
            break
    return best_start, lines[best_start:end]


def _strip_comment(line, L):
    """Drop a trailing line comment so a sanitizer token inside a comment can't flip the verdict."""
    marker = "#" if L == "py" else "//"
    idx = line.find(marker)
    return line[:idx] if idx != -1 else line


def _has_var(line, var):
    return re.search(r"\b" + re.escape(var) + r"\b", line) is not None


def _qualify(path, L, sink_idx):
    """Classify a sink site by same-function taint reachability, binding the sanitizer check to the
    tainted VARIABLE that actually reaches the sink. A sanitizer applied to an unrelated variable
    must NOT suppress a real flow (that would silently drop a true positive)."""
    m = tt.MODEL[L]
    lines = tt.scan_lines(path)
    if sink_idx >= len(lines):
        return "unlikely", "sink line out of range"
    src_rx = [re.compile(p) for p in m["sources"]]
    san_rx = [re.compile(p) for p in m["sanitizers"]]
    start, body = _containing_function(lines, m["func"], sink_idx)
    pos = sink_idx - start
    src_idx = [j for j, ln in enumerate(body) if j <= pos and any(r.search(ln) for r in src_rx)]
    if not src_idx:
        if any(r.search(ln) for ln in lines for r in src_rx):
            return "likely", "an untrusted source exists in this file but not provably in this function"
        return "unlikely", "no untrusted source detected near this sink"

    sink_line = body[pos]
    between = [_strip_comment(x, L) for x in body[min(src_idx):pos + 1]]
    # variables assigned from a source (LHS of each source-bearing line)
    src_vars = set()
    for j in src_idx:
        mm = re.match(r"\s*([A-Za-z_$]\w*)\s*=(?!=)", body[j])
        if mm:
            src_vars.add(mm.group(1))

    if not src_vars:
        # inline/anonymous source (no assignment we can name): be conservative, never drop a positive
        if any(s.search(x) for x in between for s in san_rx):
            return "likely", "inline source; a sanitizer is on the path but not provably bound (kept as likely)"
        return "tainted", "inline source reaches sink with no sanitizer on the path"

    # the tainted var(s) that actually appear in the sink line (fall back to all if none are visible)
    relevant = {v for v in src_vars if _has_var(sink_line, v)} or src_vars

    def _sanitizes(line, v):
        # a sanitizer suppresses v ONLY when v is the ASSIGNMENT TARGET (LHS) being overwritten with
        # a sanitized value. A mere RHS appearance (e.g. `page = int(q)`) sanitizes `page`, not `q` -
        # the raw `q` still flows to the sink, so it must stay tainted (never silently dropped).
        if not any(s.search(line) for s in san_rx):
            return False
        mm = re.match(r"\s*([A-Za-z_$]\w*)\s*=(?!=)", line)
        return bool(mm and mm.group(1) == v)

    unsanitized = {v for v in relevant if not any(_sanitizes(x, v) for x in between)}
    if unsanitized:
        return "tainted", ("source reaches sink; tainted variable(s) " + ",".join(sorted(unsanitized)) +
                           " are not reassigned via a sanitizer on the path")
    return "false_positive", "every tainted variable feeding the sink is sanitized (reassigned) on the path"


def _sink_patterns(seed_cwe, seed_regex, langs):
    """For each language, the list of (cwe, compiled_pattern, raw) sink patterns matching the seed."""
    out = {}
    for L in langs:
        pats = []
        for cwe, regexes in tt.MODEL[L]["sinks"].items():
            if seed_cwe and cwe != seed_cwe:
                continue
            for raw in regexes:
                if seed_regex and not re.search(seed_regex, raw):
                    # also allow regex to match the raw pattern text loosely
                    pass
                pats.append((cwe, re.compile(raw), raw))
        if seed_regex:
            # additionally include an explicit user regex as its own pattern (class from seed_cwe or UNKNOWN)
            pats.append((seed_cwe or "CWE-?", re.compile(seed_regex), seed_regex))
        out[L] = pats
    return out


def _normalize_code(code):
    return re.sub(r"\s+", " ", code).strip()


def hunt(root, langs, seed_cwe=None, seed_regex=None):
    pat_by_lang = _sink_patterns(seed_cwe, seed_regex, langs)
    sites = []
    for path in tt.iter_files(root, langs):
        L = tt.lang_for(path)
        lines = tt.scan_lines(path)
        for i, line in enumerate(lines):
            for cwe, rx, raw in pat_by_lang[L]:
                if rx.search(line):
                    qual, why = _qualify(path, L, i)
                    sites.append({"file": path, "line": i + 1, "cwe": cwe, "lang": L,
                                  "sink_api": raw, "code": line.strip()[:160],
                                  "qualification": qual, "why": why})
                    break  # one classification per line
    return _cluster(sites)


def _cluster(sites):
    groups: dict = {}
    for s in sites:
        key = (s["cwe"], s["sink_api"])
        groups.setdefault(key, []).append(s)
    clusters = []
    for (cwe, sink_api), members in groups.items():
        files = {m["file"] for m in members}
        norm = {_normalize_code(m["code"]) for m in members}
        repeated_code = len(members) - len(norm)  # identical sink lines across sites
        if repeated_code > 0:
            # identical sink code repeated (within OR across files) => one root cause, regardless of
            # how many files it spans - decoupled from file count so an in-module clone isn't missed.
            kind = "copy_paste"
            hint = ("identical sink code repeated (same or across files) - likely ONE root cause; "
                    "fix once and propagate to all siblings")
        elif len(files) >= 3:
            kind = "framework_misuse"
            hint = "same dangerous API across many files - consider a safe wrapper + lint rule (many fixes)"
        else:
            kind = "localized"
            hint = "few distinct sites - fix individually and re-sweep"
        best = max(QUALITY_RANK[m["qualification"]] for m in members)
        recommend = any(m["qualification"] != "false_positive" for m in members)
        clusters.append({
            "cwe": cwe, "sink_api": sink_api, "kind": kind, "one_fix_hint": hint,
            "site_count": len(members), "file_count": len(files),
            "max_quality": [k for k, v in QUALITY_RANK.items() if v == best][0],
            "recommend": recommend,
            "sites": sorted(members, key=lambda m: -QUALITY_RANK[m["qualification"]]),
        })
    clusters.sort(key=lambda c: (QUALITY_RANK[c["max_quality"]], c["site_count"]), reverse=True)
    return clusters


def summarize(clusters):
    counts = {q: 0 for q in QUALITY_RANK}
    total = 0
    for c in clusters:
        for s in c["sites"]:
            counts[s["qualification"]] += 1
            total += 1
    return {"sinks": total, "clusters": len(clusters), **counts}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Variant hunt: one finding -> all siblings, clustered by root cause.")
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--sink-cwe", help="e.g. CWE-89 (limit the sweep to one class)")
    ap.add_argument("--sink-regex", help="explicit sink regex to add to the sweep")
    ap.add_argument("--seed-finding", help="finding JSON; its cwe seeds the sweep")
    ap.add_argument("--lang", default="py,js,php,java")
    ap.add_argument("--json", help="write variants.json")
    args = ap.parse_args(argv)

    langs = [x.strip() for x in args.lang.split(",") if x.strip() in tt.MODEL]
    if not langs:
        print("error: no valid languages in --lang", file=sys.stderr)
        return 2

    seed_cwe = args.sink_cwe
    if args.seed_finding:
        try:
            with open(args.seed_finding, "r", encoding="utf-8") as fh:
                fnd = json.load(fh)
            if isinstance(fnd, list):
                fnd = fnd[0] if fnd else {}
            if not isinstance(fnd, dict):     # a scalar/array seed file must not crash main()
                fnd = {}
            cwe = str(fnd.get("cwe", ""))
            mm = re.search(r"(\d+)", cwe)
            if mm:
                seed_cwe = f"CWE-{mm.group(1)}"
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: --seed-finding: {exc}", file=sys.stderr)
            return 2

    if not seed_cwe and not args.sink_regex:
        print("error: provide --sink-cwe, --sink-regex, or --seed-finding", file=sys.stderr)
        return 2
    if args.sink_regex:
        try:
            re.compile(args.sink_regex)        # a malformed user regex is a clean error, not a crash
        except re.error as exc:
            print(f"error: --sink-regex: {exc}", file=sys.stderr)
            return 2

    clusters = hunt(args.root, langs, seed_cwe=seed_cwe, seed_regex=args.sink_regex)
    result = {"seed": {"cwe": seed_cwe, "regex": args.sink_regex, "root": args.root},
              "summary": summarize(clusters), "clusters": clusters}

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        print(f"[+] {result['summary']['sinks']} sink sites in {len(clusters)} clusters -> {args.json}",
              file=sys.stderr)
    else:
        for c in clusters:
            rec = "" if c["recommend"] else "  (all FP - excluded from recommendation)"
            print(f"[{c['max_quality']:13}] {c['cwe']:8} {c['sink_api'][:30]:30} "
                  f"{c['kind']:16} sites={c['site_count']} files={c['file_count']}{rec}")
        s = result["summary"]
        print(f"\nsummary: {s['sinks']} sinks, {s['clusters']} clusters, "
              f"tainted={s['tainted']} likely={s['likely']} unlikely={s['unlikely']} fp={s['false_positive']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
