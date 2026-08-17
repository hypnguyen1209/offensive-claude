#!/usr/bin/env python3
"""model_scorecard.py - calibrate how much to TRUST a model's verdicts, from its track record.

The autopilot re-validates findings (finding-validator / finding-checker) - expensive. If a given
model has a long, clean track record on a given decision class, we can short-circuit that re-check.
But "it's usually right" is not enough: we trust a (model, decision_class) cell ONLY when the
Wilson 95% UPPER bound on its miss-rate is at/below a threshold AND we have enough samples. That is
fail-CLOSED - a small sample has a wide Wilson interval, so a new/rarely-seen model is never trusted,
and one overturned verdict widens the bound and revokes trust.

A "miss" = a verdict later overturned (a PASS that was actually a false positive, a KILL that was
actually real). Record outcomes as you confirm them; consult `is_trusted()` in the autopilot before
skipping a re-validation.

Pure stdlib (sqlite3 + math). Separate sqlite DB (not the JSONL pattern store - different concern).

CLI:
  model_scorecard.py record --model opus --class finding-validator:PASS --outcome correct|overturned
  model_scorecard.py rate    --model opus --class finding-validator:PASS        # n + miss-rate + upper
  model_scorecard.py trusted --model opus --class finding-validator:PASS [--max-rate 0.05] [--min-n 20]
  model_scorecard.py stats
  exit: trusted -> 0 if trusted, 3 if NOT trusted (so automation can branch); others 0, error 2
"""
from __future__ import annotations

import argparse
import math
import os
import sqlite3
import sys
from collections import Counter
from typing import Optional

DEFAULT_MAX_RATE = 0.05      # trust a cell only if the miss-rate's 95% upper bound is <= 5%
DEFAULT_MIN_N = 20           # ...and only after enough samples (small n -> wide interval -> distrust)
Z_95 = 1.959963984540054     # z for a 95% one-sided/two-sided bound


def db_path() -> str:
    return os.environ.get("MODEL_SCORECARD_DB") or os.path.join(
        os.path.expanduser("~"), ".claude", "engagement-memory", "scorecard.sqlite")


def _connect(path: Optional[str] = None) -> sqlite3.Connection:
    p = path or db_path()
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    conn = sqlite3.connect(p)
    conn.execute("""CREATE TABLE IF NOT EXISTS outcomes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        model TEXT NOT NULL,
        decision_class TEXT NOT NULL,
        overturned INTEGER NOT NULL CHECK (overturned IN (0, 1)),
        ts TEXT
    )""")
    # Paired verdicts on the SAME finding by the two independent judges (finding-validator vs
    # finding-checker) - the raw material for Cohen's kappa, a reliability signal that sits ALONGSIDE
    # miss-rate. High miss-rate says "often wrong"; low kappa says "the two judges barely agree above
    # chance", i.e. the accept/reject signal itself is noisy and neither verdict should be trusted to
    # short-circuit the other. Kappa is informational - it does NOT feed is_trusted().
    conn.execute("""CREATE TABLE IF NOT EXISTS agreement (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id TEXT,
        decision_class TEXT,
        rater_a TEXT NOT NULL,
        rater_b TEXT NOT NULL,
        ts TEXT
    )""")
    conn.commit()
    return conn


def wilson_upper(misses: int, n: int, z: float = Z_95) -> float:
    """Wilson 95% UPPER bound on the failure proportion p=misses/n. n==0 -> 1.0 (max distrust)."""
    if n <= 0:
        return 1.0
    misses = max(0, min(int(misses), int(n)))
    p = misses / n
    denom = 1.0 + z * z / n
    center = p + z * z / (2 * n)
    margin = z * math.sqrt(max(0.0, p * (1 - p) / n + z * z / (4 * n * n)))
    return min(1.0, (center + margin) / denom)


def record(model: str, decision_class: str, overturned: bool, *,
           path: Optional[str] = None, ts: str = "") -> None:
    if not model or not decision_class:
        raise ValueError("model and decision_class are required")
    conn = _connect(path)
    try:
        conn.execute("INSERT INTO outcomes (model, decision_class, overturned, ts) VALUES (?,?,?,?)",
                     (str(model), str(decision_class), 1 if overturned else 0, ts or ""))
        conn.commit()
    finally:
        conn.close()


def counts(model: str, decision_class: str, *, path: Optional[str] = None) -> tuple:
    conn = _connect(path)
    try:
        row = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(overturned), 0) FROM outcomes WHERE model=? AND decision_class=?",
            (str(model), str(decision_class))).fetchone()
    finally:
        conn.close()
    n = int(row[0] or 0)
    misses = int(row[1] or 0)
    return n, misses


def miss_rate_upper(model: str, decision_class: str, *, path: Optional[str] = None) -> float:
    n, misses = counts(model, decision_class, path=path)
    return wilson_upper(misses, n)


def is_trusted(model: str, decision_class: str, *, max_rate: float = DEFAULT_MAX_RATE,
               min_n: int = DEFAULT_MIN_N, path: Optional[str] = None) -> tuple:
    """(trusted, reason). Fail-CLOSED: trusted only if n>=min_n AND Wilson upper miss-rate<=max_rate.
    A degenerate threshold (NaN, <0, or >=1.0) is rejected as max-distrust so a bogus --max-rate can't
    flip a 100%-miss cell to trusted (`x > nan` is always False; `x <= 1.0` is always True)."""
    if not (isinstance(max_rate, (int, float)) and math.isfinite(max_rate) and 0.0 <= max_rate < 1.0):
        return False, f"invalid max_rate {max_rate!r} (must be a finite value in [0,1)) - fail-closed"
    if not (isinstance(min_n, int) and min_n >= 1):
        return False, f"invalid min_n {min_n!r} (must be an int >= 1) - fail-closed"
    n, misses = counts(model, decision_class, path=path)
    if n < min_n:
        return False, f"only {n}/{min_n} samples - not enough evidence to trust (fail-closed)"
    upper = wilson_upper(misses, n)
    if not (upper <= max_rate):    # NaN-safe: if upper were NaN, not(<=) is True -> distrust
        return False, f"miss-rate 95% upper bound {upper:.3f} > {max_rate} ({misses}/{n} overturned)"
    return True, f"miss-rate upper bound {upper:.3f} <= {max_rate} over {n} samples ({misses} overturned)"


def _kappa_band(kappa: float) -> str:
    """Landis-Koch interpretation of an agreement coefficient."""
    if kappa < 0.0:
        return "poor (worse than chance)"
    if kappa < 0.20:
        return "slight"
    if kappa < 0.40:
        return "fair"
    if kappa < 0.60:
        return "moderate"
    if kappa < 0.80:
        return "substantial"
    return "almost perfect"


def cohens_kappa(pairs) -> dict:
    """Cohen's kappa over (rater_a_label, rater_b_label) pairs. Pure; category set = union of labels.

    kappa = (p_o - p_e) / (1 - p_e), p_o = observed agreement, p_e = chance agreement from marginals.
    Fail-SAFE degenerate handling: no data or a single shared category (p_e == 1, chance agreement is
    total) -> kappa is undefined, returned as None with a reason, NOT as a high score. A reliability
    metric must never report "perfect" for a case where agreement carries no information."""
    clean = [(str(a), str(b)) for a, b in pairs if a is not None and b is not None]
    n = len(clean)
    if n == 0:
        return {"kappa": None, "n": 0, "p_o": None, "p_e": None,
                "interpretation": "no data", "categories": []}
    cats = sorted({c for pair in clean for c in pair})
    p_o = sum(1 for a, b in clean if a == b) / n
    a_counts, b_counts = Counter(a for a, _ in clean), Counter(b for _, b in clean)
    p_e = sum((a_counts[c] / n) * (b_counts[c] / n) for c in cats)
    if p_e >= 1.0:
        return {"kappa": None, "n": n, "p_o": p_o, "p_e": p_e,
                "interpretation": "degenerate (single category - agreement uninformative)",
                "categories": cats}
    kappa = (p_o - p_e) / (1.0 - p_e)
    return {"kappa": kappa, "n": n, "p_o": p_o, "p_e": p_e,
            "interpretation": _kappa_band(kappa), "categories": cats}


def record_pair(rater_a: str, rater_b: str, *, finding_id: str = "", decision_class: str = "",
                path: Optional[str] = None, ts: str = "") -> None:
    """Record one paired verdict: rater_a = validator label, rater_b = checker label, same finding."""
    if not rater_a or not rater_b:
        raise ValueError("rater_a and rater_b labels are required")
    conn = _connect(path)
    try:
        conn.execute(
            "INSERT INTO agreement (finding_id, decision_class, rater_a, rater_b, ts) VALUES (?,?,?,?,?)",
            (str(finding_id or ""), str(decision_class or ""), str(rater_a), str(rater_b), ts or ""))
        conn.commit()
    finally:
        conn.close()


def _agreement_pairs(decision_class: Optional[str] = None, *, path: Optional[str] = None) -> list:
    conn = _connect(path)
    try:
        if decision_class:
            rows = conn.execute("SELECT rater_a, rater_b FROM agreement WHERE decision_class=?",
                                (str(decision_class),)).fetchall()
        else:
            rows = conn.execute("SELECT rater_a, rater_b FROM agreement").fetchall()
    finally:
        conn.close()
    return [(a, b) for a, b in rows]


# The two judges speak different dialects (validator: PASS/KILL/DOWNGRADE; checker:
# ACCEPTED/STALLED/EXHAUSTED). Kappa needs a SHARED label space, so map both onto a canonical
# accept/reject/partial before comparing - otherwise disjoint vocabularies never string-match and
# kappa reads a misleading ~0 ("poor agreement") when the judges actually concur. Unknown labels pass
# through lowercased so a novel verdict is compared literally rather than silently folded.
_CANON_VERDICT = {
    "pass": "accept", "accepted": "accept", "accept": "accept",
    "kill": "reject", "stalled": "reject", "reject": "reject", "rejected": "reject",
    "downgrade": "partial", "exhausted": "partial", "partial": "partial",
}


def _canon_verdict(label) -> str:
    s = str(label).strip().lower()
    return _CANON_VERDICT.get(s, s)


def agreement_kappa(decision_class: Optional[str] = None, *, path: Optional[str] = None) -> dict:
    """Cohen's kappa over all recorded (validator, checker) pairs, optionally scoped to a class.
    Both raters' labels are canonicalized to accept/reject/partial so the two judge dialects align."""
    pairs = [(_canon_verdict(a), _canon_verdict(b))
             for a, b in _agreement_pairs(decision_class, path=path)]
    return cohens_kappa(pairs)


def stats(path: Optional[str] = None) -> list:
    conn = _connect(path)
    try:
        rows = conn.execute(
            "SELECT model, decision_class, COUNT(*), COALESCE(SUM(overturned),0) "
            "FROM outcomes GROUP BY model, decision_class ORDER BY model, decision_class").fetchall()
    finally:
        conn.close()
    out = []
    for model, dc, n, misses in rows:
        out.append({"model": model, "decision_class": dc, "n": int(n), "overturned": int(misses),
                    "miss_rate_upper": round(wilson_upper(int(misses), int(n)), 4),
                    "trusted": is_trusted(model, dc, path=path)[0]})
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Model trust calibration (Wilson upper-bound miss-rate).")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("record")
    r.add_argument("--model", required=True); r.add_argument("--class", dest="cls", required=True)
    r.add_argument("--outcome", required=True, choices=["correct", "overturned"])
    r.add_argument("--db")
    g = sub.add_parser("rate"); g.add_argument("--model", required=True); g.add_argument("--class", dest="cls", required=True); g.add_argument("--db")
    t = sub.add_parser("trusted")
    t.add_argument("--model", required=True); t.add_argument("--class", dest="cls", required=True)
    t.add_argument("--max-rate", type=float, default=DEFAULT_MAX_RATE)
    t.add_argument("--min-n", type=int, default=DEFAULT_MIN_N); t.add_argument("--db")
    s = sub.add_parser("stats"); s.add_argument("--db")
    rp = sub.add_parser("record-pair", help="record a paired validator/checker verdict on one finding")
    rp.add_argument("--validator", required=True); rp.add_argument("--checker", required=True)
    rp.add_argument("--finding-id", default=""); rp.add_argument("--class", dest="cls", default="")
    rp.add_argument("--db")
    k = sub.add_parser("kappa", help="Cohen's kappa between validator and checker (reliability signal)")
    k.add_argument("--class", dest="cls", default=""); k.add_argument("--db")
    args = p.parse_args(argv)
    try:
        if args.cmd == "record":
            record(args.model, args.cls, args.outcome == "overturned", path=args.db)
            print(f"recorded {args.outcome} for {args.model}/{args.cls}")
            return 0
        if args.cmd == "rate":
            n, misses = counts(args.model, args.cls, path=args.db)
            print(f"{args.model}/{args.cls}: n={n} overturned={misses} "
                  f"miss_rate_upper={miss_rate_upper(args.model, args.cls, path=args.db):.4f}")
            return 0
        if args.cmd == "trusted":
            if not (math.isfinite(args.max_rate) and 0.0 <= args.max_rate < 1.0):
                print(f"error: --max-rate must be a finite value in [0,1), got {args.max_rate!r}", file=sys.stderr)
                return 2
            if args.min_n < 1:
                print(f"error: --min-n must be >= 1, got {args.min_n}", file=sys.stderr)
                return 2
            ok, why = is_trusted(args.model, args.cls, max_rate=args.max_rate, min_n=args.min_n, path=args.db)
            print(("TRUSTED: " if ok else "NOT TRUSTED: ") + why)
            return 0 if ok else 3
        if args.cmd == "stats":
            import json
            print(json.dumps(stats(path=args.db), indent=2))
            return 0
        if args.cmd == "record-pair":
            record_pair(args.validator, args.checker, finding_id=args.finding_id,
                        decision_class=args.cls, path=args.db)
            print(f"recorded pair validator={args.validator} checker={args.checker}"
                  + (f" class={args.cls}" if args.cls else ""))
            return 0
        if args.cmd == "kappa":
            import json
            print(json.dumps(agreement_kappa(args.cls or None, path=args.db), indent=2))
            return 0
    except (ValueError, sqlite3.Error, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
