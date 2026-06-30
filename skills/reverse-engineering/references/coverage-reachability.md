# Coverage / Trace Reachability — proving a native bug's line actually ran

A static crash hypothesis ("`strcpy` here overflows") is a *claim* until you show the vulnerable line
executed with your input. This is the produce-side recipe for the reachability artifacts the harness
(`validate_findings.py`) requires before a native memory-corruption finding can be `[CONFIRMED]` — see
`skills/references/finding-evidence-standards.md`. Run these in the binary-analysis devcontainer
(`.devcontainer/`); they need a Linux toolchain (gcc/clang + gcov).

## Option A — gcov line-hit (source available)

Build with coverage, run the PoC/witness, generate gcov, assert the vulnerable line is not `#####`.

```bash
# 1. instrument
gcc --coverage -O0 -g -o target_cov target.c          # or: clang -fprofile-instr-generate -fcoverage-mapping
# 2. drive the vulnerable path with your input (the crash witness)
./target_cov < poc_input                               # may crash; .gcda is flushed on normal exit,
                                                        # so wrap the sink to return cleanly OR use
                                                        # __gcov_dump() / llvm profile before the crash
# 3. emit gcov and locate the vulnerable line
gcov -b target.c                                       # writes target.c.gcov
sed -n '40,45p' target.c.gcov                          # eyeball: the vuln line must show a count, not '#####'
```

`target.c.gcov` line format is `<count>:<lineno>:<source>`. A `#####` count means the line never
executed; a `-` means it is not code. Record the proof:

```json
"proof": {"coverage_proof": {"gcov": "evidence/target.c.gcov", "line": 42}}
```

> Crash-before-flush pitfall: gcov flushes counters at process exit, which a segfault skips. Either
> compile the sink to log-and-return instead of crashing during the coverage run, call
> `__gcov_dump()` immediately before the faulting statement, or run the coverage build under a harness
> that traps the signal and dumps. ASan + `-fprofile-...` can be combined for a clean abort path.

## Option B — function trace (binary-only, no source)

Prove the vulnerable function was reached at runtime with a call trace, then cite the log.

```bash
# rr (deterministic) — record then list the functions on the crashing run
rr record ./target poc_input
rr replay -a 2>/dev/null | grep -m1 parse_header        # or use rr_root_cause.sh
# OR -finstrument-functions build that logs each entered function
# OR a Frida/ltrace/uftrace capture naming the function
uftrace record ./target poc_input && uftrace report | grep parse_header
```

```json
"proof": {"trace_proof": {"log": "evidence/trace.txt", "function": "parse_header"}}
```

## What this is / isn't

- It demonstrates **reachability** (the line/function ran), not **exploitability**. Pair it with the
  feasibility verdict + empirical mitigation map (`exploit-feasibility.md`) for the full picture.
- The harness check is mechanical and fail-closed: a missing/empty/`#####`/unparseable artifact keeps
  the finding `[POSSIBLE]`. Don't hand-edit a `.gcov` — regenerate it.
- For root-cause (not just reachability), use rr time-travel: `rr-time-travel.md` + `scripts/rr_root_cause.sh`.
