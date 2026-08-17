#!/usr/bin/env python3
"""cmd_parser.py - bypass-resistant destructive-command classifier.

A naive `command.startswith("rm")` gate is trivially defeated: `sh -c 'rm -rf /'`,
`$(rm -rf x)`, `cd /tmp && rm -rf build`, split flags (`rm -r -f`), or a forced git
push spelled `git push origin +main`. This module ports the *logic* (not the code) of
ecc's gateguard destructive detector (GHSA-4v57-ph3x-gf55 and friends): it tokenizes a
shell command, recursively explodes every executable body (command substitutions,
subshell groups, `sh -c` payloads), and classifies each simple command word.

Design (matches the _lib house style):
- Pure stdlib (`shlex`), fail-safe: an unparseable command is treated as NON-destructive
  here (this is an *advisory* detector that only ever *adds* a block reason; scope_guard /
  action_guard remain the authorization boundary). It never raises on bad input.
- Reasons name the KIND of danger ("rm recursive+force", "git force-push"), never the raw
  argument values, so a command carrying a secret can't leak it into a log/verdict.

CLI:
  cmd_parser.py --command "sh -c 'rm -rf /'"
  exit 5 = destructive (block), 0 = not destructive, 2 = error
"""
from __future__ import annotations

import argparse
import re
import shlex
import sys
from dataclasses import dataclass, field
from typing import Optional

# separators between simple commands in a compound command
_SEP = {"&&", "||", ";", "|", "&"}
# wrappers whose FINAL string argument is itself a command to re-scan
_SHELL_WRAPPERS = {"sh", "bash", "zsh", "dash", "ksh", "ash"}
# "runner" prefixes that execute a FOLLOWING command; the danger is in what they wrap,
# so we strip the runner (and its own flags/env-assigns/numeric args) and re-scan the rest.
# `exec rm -rf /`, `sudo rm -rf /`, `timeout 5 rm -rf /`, `env A=b rm -rf /`, `xargs -0 rm -rf`.
_RUNNERS = {"sudo", "doas", "nohup", "setsid", "nice", "ionice", "timeout", "stdbuf",
            "env", "command", "exec", "time", "xargs", "watch", "chroot", "unbuffer"}


@dataclass
class Verdict:
    destructive: bool
    reasons: list[str] = field(default_factory=list)
    matched: list[str] = field(default_factory=list)  # the command words that tripped

    def to_dict(self) -> dict:
        return {"destructive": self.destructive, "reasons": self.reasons, "matched": self.matched}


# ---------------------------------------------------------------- flag helpers
def _flags(tokens: list[str]) -> set[str]:
    """Collect short-flag letters and long flags from a token list.

    `-rf` -> {'r','f'}; `-r -f` -> {'r','f'}; `--force` -> {'force'}.
    """
    letters: set[str] = set()
    for t in tokens:
        if t.startswith("--"):
            letters.add(t[2:].split("=", 1)[0])
        elif t.startswith("-") and len(t) > 1:
            letters.update(t[1:])
    return letters


def _is_destructive_simple(words: list[str]) -> Optional[str]:
    """Classify a single simple command (already split into words). Returns a reason or None."""
    if not words:
        return None
    cmd = words[0]
    # strip a leading path: /bin/rm -> rm
    base = cmd.rsplit("/", 1)[-1]
    rest = words[1:]
    fl = _flags(rest)

    if base == "rm":
        if ("r" in fl or "R" in fl or "recursive" in fl) and ("f" in fl or "force" in fl):
            return "rm recursive+force"
        return None
    if base == "git":
        sub = rest[0] if rest else ""
        subflags = _flags(rest[1:])
        if sub == "push":
            # force-with-lease is the SAFE force; plain --force/-f or a '+refspec' is not
            if "force-with-lease" in subflags:
                return None
            if "force" in subflags or "f" in subflags:
                return "git force-push"
            if any(a.startswith("+") for a in rest[1:]):
                return "git force-push (+refspec)"
            return None
        if sub == "reset" and "hard" in subflags:
            return "git reset --hard"
        if sub == "clean" and ("f" in subflags or "force" in subflags):
            return "git clean -f"
        if sub == "switch" and "C" in subflags:
            return "git switch -C (force-create)"
        if sub == "checkout" and "B" in subflags:
            return "git checkout -B (force-create)"
        return None
    if base == "find" and "-exec" in rest:
        try:
            payload = rest[rest.index("-exec") + 1]
        except IndexError:
            payload = ""
        if payload.rsplit("/", 1)[-1] in {"rm", "dd", "shred"}:
            return "find -exec destructive"
        return None
    if base == "dd":
        if any(a.startswith("of=") for a in rest):
            return "dd (raw device/file write)"
        return None
    if base in {"shred", "mkfs", "fdisk", "wipefs"}:
        return f"{base} (destructive disk op)"
    if base == "truncate":
        return "truncate (data loss)"
    if base in {"drop", "truncate"} or (base == "mysql" and "drop" in " ".join(rest).lower()):
        return "sql drop/truncate"
    return None


# ---------------------------------------------------------------- explosion
def _explode_bodies(command: str) -> list[str]:
    """Return inner command strings hidden in substitutions/groups: $( ), ` `, ( ), { }."""
    bodies: list[str] = []
    # $( ... ) and ` ... `
    for m in re.finditer(r"\$\(([^()]*)\)", command):
        bodies.append(m.group(1))
    for m in re.finditer(r"`([^`]*)`", command):
        bodies.append(m.group(1))
    # ( ... ) and { ... } subshell / group bodies
    for m in re.finditer(r"\(([^()]*)\)", command):
        bodies.append(m.group(1))
    for m in re.finditer(r"\{([^{}]*)\}", command):
        bodies.append(m.group(1))
    return [b.strip() for b in bodies if b.strip()]


def _strip_runners(words: list[str]) -> tuple[list[str], bool]:
    """Drop leading runner names + their own flags / KEY=VAL env-assigns / bare-numeric args,
    returning (wrapped_command_words, saw_runner). Bounded, best-effort — a runner may wrap a
    runner (`sudo timeout 5 rm ...`)."""
    i, n, saw = 0, len(words), False
    while i < n:
        base = words[i].rsplit("/", 1)[-1]
        if base not in _RUNNERS:
            break
        saw = True
        i += 1
        # skip this runner's options / env-assignments / numeric args until the next command word
        while i < n:
            t = words[i]
            if t.startswith("-") or t.isdigit() or ("=" in t and not t.startswith("=")):
                i += 1
            else:
                break
    return words[i:], saw


def _split_segments(tokens: list[str]) -> list[list[str]]:
    """Split a flat token list into simple-command segments on shell separators."""
    segs: list[list[str]] = []
    cur: list[str] = []
    for t in tokens:
        if t in _SEP:
            if cur:
                segs.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        segs.append(cur)
    return segs


def is_destructive(command: Optional[str], _depth: int = 0) -> Verdict:
    """Classify a shell command string. Fail-safe: unparseable -> not destructive."""
    if not command or not command.strip() or _depth > 6:
        return Verdict(False)

    reasons: list[str] = []
    matched: list[str] = []

    # 1. recurse into any substitution/group bodies first
    for body in _explode_bodies(command):
        inner = is_destructive(body, _depth + 1)
        if inner.destructive:
            reasons.extend(inner.reasons)
            matched.extend(inner.matched)

    # 2. tokenize the top level (posix, keep going on error). Pad shell operators so a
    #    glued separator like `make;` becomes its own token (quoted operators are protected
    #    by shlex, which keeps quoted spans intact).
    normalized = re.sub(r"(\|\||&&|;|\||&)", r" \1 ", command)
    try:
        tokens = shlex.split(normalized, posix=True)
    except ValueError:
        # unbalanced quotes etc. — fall back to a whitespace split so we still see words
        tokens = normalized.split()

    for seg in _split_segments(tokens):
        r, m = _classify_segment(seg, _depth)
        reasons.extend(r)
        matched.extend(m)

    # dedup while preserving order
    reasons = list(dict.fromkeys(reasons))
    matched = list(dict.fromkeys(matched))
    return Verdict(bool(reasons), reasons, matched)


def _classify_segment(seg: list[str], depth: int) -> tuple[list[str], list[str]]:
    """Classify one simple-command token segment, unwrapping shell wrappers / eval / runner
    prefixes by recursing on the *token list* (never re-stringified — that would lose the quoting
    that protects a payload like `sh -c 'rm -rf /'`)."""
    if not seg:
        return [], []
    reasons: list[str] = []
    matched: list[str] = []
    base = seg[0].rsplit("/", 1)[-1]

    # shell wrapper: re-scan its payload argument (`sh -c '<cmd>'`)
    if base in _SHELL_WRAPPERS and "-c" in seg:
        try:
            payload = seg[seg.index("-c") + 1]
        except IndexError:
            payload = ""
        inner = is_destructive(payload, depth + 1)
        return list(inner.reasons), list(inner.matched)

    # eval: runs a dynamically-constructed string. Re-scan the argument as a command, and flag
    # eval-of-substitution (`eval "$(...)"`/backticks) — the produced string can be destructive in
    # ways no static scan of the *body* (e.g. printf 'rm -rf /') would reveal.
    if base == "eval":
        arg = " ".join(seg[1:])
        if "$(" in arg or "`" in arg:
            reasons.append("eval of dynamic/substituted command (manual review)")
            matched.append("eval")
        inner = is_destructive(arg, depth + 1)
        reasons.extend(inner.reasons)
        matched.extend(inner.matched)
        return reasons, matched

    # runner prefix (exec/sudo/timeout/env/xargs/...): strip it and re-classify the WRAPPED tokens
    # directly (preserves quoting, so `sudo sh -c 'rm -rf /'` still re-scans the payload correctly).
    unwrapped, saw_runner = _strip_runners(seg)
    if saw_runner and unwrapped and unwrapped != seg and depth <= 6:
        return _classify_segment(unwrapped, depth + 1)

    r = _is_destructive_simple(seg)
    if r:
        reasons.append(r)
        matched.append(base)
    return reasons, matched


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Classify whether a shell command is destructive.")
    p.add_argument("--command", required=True, help="the shell command to classify")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    try:
        v = is_destructive(args.command)
        if args.json:
            import json
            print(json.dumps(v.to_dict()))
        else:
            if v.destructive:
                print(f"DESTRUCTIVE: {', '.join(v.reasons)}")
            else:
                print("ok: no destructive pattern detected")
        return 5 if v.destructive else 0
    except Exception as exc:  # never crash the caller
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
