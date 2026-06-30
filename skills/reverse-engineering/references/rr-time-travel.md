# rr Time-Travel — deterministic record/replay root-cause

A segfault tells you *where* it crashed, not *why*. rr (Mozilla's record-replay debugger) records a
run once, then lets you replay it deterministically and step **backwards** to the instruction that
wrote the bad value — turning "it crashed in `memcpy`" into "the length came from this attacker field
20k instructions earlier". This is the root-cause half of the crash pipeline; the reachability half
is `coverage-reachability.md`. Backed by `scripts/rr_root_cause.sh`. Runs in `.devcontainer/`
(Linux + `CAP_SYS_PTRACE` + `perf_event_paranoid=1`).

## Why rr over plain gdb

- **Determinism.** The recorded trace replays identically every time — no heisenbugs, no "can't
  reproduce". A flaky crash recorded once is now a fixed artifact.
- **Reverse execution.** `reverse-continue` / `reverse-stepi` / hardware watchpoints run *backwards*:
  set a watchpoint on the corrupted byte and reverse-continue to the exact write.
- **Auditable.** The trace lives in the engagement workspace (`_RR_TRACE_DIR`), so the root-cause
  step is reproducible by a reviewer, not a one-off debugging session.

## Workflow

```bash
# one-shot via the script (emits a trace_proof artifact + a root-cause summary)
OUT=results CRASH_INPUT=poc.bin skills/reverse-engineering/scripts/rr_root_cause.sh ./vuln @@

# or by hand:
kernel.perf_event_paranoid=1            # sysctl; rr needs this (devcontainer sets it)
rr record ./vuln poc.bin                # record the crashing run
rr replay                               # deterministic replay in gdb
(rr) continue                           # run to the fault
(rr) bt                                 # crashing frame
(rr) watch -l corrupted_var             # watch the corrupted location
(rr) reverse-continue                   # run BACKWARDS to the write that corrupted it
(rr) reverse-stepi                      # single-step backwards to the precise cause
```

## What it produces (feeds the finding harness)

- **`trace_proof`** — the function trace of the crashing run; cite it as
  `proof.trace_proof = {log, function}` so `validate_findings.py` can confirm the vulnerable function
  executed (reachability). See `coverage-reachability.md`.
- **Root-cause summary** — the faulting instruction + the reverse-step that found where the bad value
  originated. This is what upgrades a finding from "crashes" to "here is the exact corrupting write".

## Notes / OPSEC

- rr records syscalls and memory — the trace can contain secrets from the run; keep it in the
  scoped workspace and purge on teardown (don't ship a raw rr trace in a report).
- Intel PT speeds recording on supported CPUs; software counters work otherwise. In a container use
  scoped `CAP_SYS_PTRACE`/`SYS_PERFMON`, never `--privileged` (see `.devcontainer/`).
- rr does not need network or the target's real environment — record a local copy of the binary.
- Pair with `feasibility_profile.py`: once you know the root cause, the empirical mitigation matrix
  tells you which exploitation techniques the target actually permits (`exploit-feasibility.md`).
