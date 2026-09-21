#!/usr/bin/env python3
"""eval_corpus.py - code-graded decision-quality eval for the deterministic finding validator.

`agent_eval_selftest.py` proves the judge *math*; this measures whether the deterministic validator
(`validate_findings.evaluate_finding`, tiers CONFIRMED/POSSIBLE/INFO/REJECTED) actually separates real
findings from bogus ones on a realistic LABELED corpus. This is the cookbook's "code-based grading over a
held-out set" (anthropics/claude-cookbooks `misc/building_evals.ipynb`) applied offline: the validator is
deterministic, so grading is exact-match and needs no model or network.

The corpus (`eval_corpus/corpus.json`) is a list of finding records each tagged `expected_tier` (hand-
verified ground truth). Grounded fixtures cite `eval_corpus/evidence/proof.txt`; ungrounded ones cite a
missing file / [] to exercise REJECTED. `expected_lint: true` asserts the advisory hedge lint fired.

FAIL-CLOSED GATE (exit 1 on any):
  1. FALSE-CONFIRM: a case whose expected tier is NOT CONFIRMED but the validator returned CONFIRMED.
     This is the dangerous error (a bogus/unproven finding passed as confirmed) and is never tolerated.
  2. Any exact-match mismatch (the corpus is a frozen labeled regression guard - a validator logic change
     that diverges from documented intent fails here, and the per-tier P/R/F1 shows where).
  3. A case expecting a lint that did not fire.
It reports a confusion matrix + per-tier precision/recall/F1 + accuracy regardless.

CLI:
  eval_corpus.py                       # run the bundled corpus; exit 1 on any gate failure
  eval_corpus.py --json
  eval_corpus.py --corpus PATH --evidence DIR
Exit: 0 clean, 1 gate failure, 2 error.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_ROOT = Path(__file__).resolve().parents[2]
# validate_findings + its sibling `provenance` live here:
sys.path.insert(0, str(_ROOT / "skills" / "vulnerability-analysis" / "scripts"))
import validate_findings as vf  # noqa: E402

_TIERS = ("CONFIRMED", "POSSIBLE", "INFO", "REJECTED")
_DEFAULT_CORPUS = Path(__file__).resolve().parent / "eval_corpus" / "corpus.json"


@dataclass
class Result:
    total: int = 0
    correct: int = 0
    mismatches: list = field(default_factory=list)     # (id, expected, predicted, reason)
    false_confirms: list = field(default_factory=list)  # (id, expected)
    lint_failures: list = field(default_factory=list)   # (id,)
    confusion: dict = field(default_factory=dict)       # expected -> {predicted -> n}
    per_tier: dict = field(default_factory=dict)        # tier -> {precision, recall, f1, support}

    @property
    def ok(self) -> bool:
        return not (self.mismatches or self.false_confirms or self.lint_failures)

    @property
    def accuracy(self) -> float:
        return self.correct / self.total if self.total else 0.0

    def to_dict(self) -> dict:
        return {"total": self.total, "correct": self.correct, "accuracy": round(self.accuracy, 4),
                "false_confirms": self.false_confirms, "mismatches": self.mismatches,
                "lint_failures": self.lint_failures, "confusion": self.confusion,
                "per_tier": self.per_tier, "ok": self.ok}


def _load(corpus_path: Path) -> list:
    with open(corpus_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    findings = data.get("findings", data) if isinstance(data, dict) else data
    if not isinstance(findings, list):
        raise ValueError("corpus must be a JSON list or {findings:[...]}")
    return findings


def _prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * p * r / (p + r)) if (p + r) else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4), "support": tp + fn}


def evaluate(corpus_path: Path, evidence_dir: Path) -> Result:
    res = Result()
    res.confusion = {e: {p: 0 for p in _TIERS} for e in _TIERS}
    findings = _load(corpus_path)

    for f in findings:
        if not isinstance(f, dict) or "expected_tier" not in f:
            raise ValueError(f"corpus record missing expected_tier: {f!r:.80}")
        expected = str(f["expected_tier"]).upper()
        verdict = vf.evaluate_finding(f, evidence_dir)      # offline, deterministic
        predicted = verdict.tier
        res.total += 1
        if expected in res.confusion and predicted in res.confusion[expected]:
            res.confusion[expected][predicted] += 1
        if predicted == expected:
            res.correct += 1
        else:
            res.mismatches.append((f.get("id", "?"), expected, predicted, verdict.reason))
        # the dangerous error class, called out separately from a generic mismatch
        if predicted == "CONFIRMED" and expected != "CONFIRMED":
            res.false_confirms.append((f.get("id", "?"), expected))
        if f.get("expected_lint") and not verdict.lint:
            res.lint_failures.append(f.get("id", "?"))

    for t in _TIERS:
        tp = res.confusion[t][t]
        fp = sum(res.confusion[e][t] for e in _TIERS if e != t)
        fn = sum(res.confusion[t][p] for p in _TIERS if p != t)
        res.per_tier[t] = _prf(tp, fp, fn)
    return res


def _print_report(res: Result) -> None:
    print("== eval corpus: deterministic validator decision quality ==")
    print(f"accuracy: {res.correct}/{res.total} = {res.accuracy:.1%}\n")
    print("confusion (rows=expected, cols=predicted):")
    hdr = "  expected\\pred | " + " ".join(f"{t[:4]:>5}" for t in _TIERS)
    print(hdr)
    for e in _TIERS:
        row = " ".join(f"{res.confusion[e][p]:>5}" for p in _TIERS)
        print(f"  {e:13} | {row}")
    print("\nper-tier precision / recall / f1 (support):")
    for t in _TIERS:
        m = res.per_tier[t]
        print(f"  {t:10} P={m['precision']:.2f} R={m['recall']:.2f} F1={m['f1']:.2f}  (n={m['support']})")
    macro = sum(res.per_tier[t]["f1"] for t in _TIERS) / len(_TIERS)
    print(f"  macro-F1 = {macro:.3f}")
    if res.false_confirms:
        print("\nFALSE-CONFIRM (bogus/unproven finding passed as CONFIRMED) - fail-closed:")
        for fid, exp in res.false_confirms:
            print(f"  ! {fid}: expected {exp} but validator said CONFIRMED")
    if res.mismatches:
        print("\nmismatches (predicted != expected):")
        for fid, exp, pred, why in res.mismatches:
            print(f"  - {fid}: expected {exp}, got {pred}  <- {why}")
    if res.lint_failures:
        print("\nexpected-lint did not fire:")
        for fid in res.lint_failures:
            print(f"  - {fid}")
    print(f"\n{'ok' if res.ok else 'FAILED'}: labeled corpus decision quality")


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description="Code-graded decision-quality eval for the finding validator.")
    p.add_argument("--corpus", default=str(_DEFAULT_CORPUS))
    p.add_argument("--evidence", default=None, help="evidence dir (default: <corpus dir>/evidence)")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    corpus_path = Path(args.corpus)
    evidence_dir = Path(args.evidence) if args.evidence else corpus_path.parent / "evidence"
    try:
        res = evaluate(corpus_path, evidence_dir)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(res.to_dict(), indent=2))
    else:
        _print_report(res)
    return 0 if res.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
