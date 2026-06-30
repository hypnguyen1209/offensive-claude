# Reproducible binary-analysis / crash-exploitability toolchain for the crash pipeline (PR-3).
# Pins the tools the rr/coverage/feasibility steps need so they run deterministically and in CI.
# Scoped caps (SYS_PTRACE/SYS_PERFMON) are granted by devcontainer.json - NOT --privileged.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Toolchain: rr (time-travel), gdb-multiarch, gcc/clang + gcov/lcov (coverage),
# afl++ (fuzzing), semgrep (SAST), valgrind, python3 + pwntools deps.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git build-essential \
        rr gdb gdb-multiarch valgrind \
        clang llvm lcov \
        afl++ \
        python3 python3-pip python3-venv pipx \
        binutils file patchelf elfutils \
    && rm -rf /var/lib/apt/lists/*

# Python tooling for the harness + exploit dev (pinned-ish; refine per engagement).
RUN python3 -m pip install --no-cache-dir --break-system-packages \
        pytest pyyaml pwntools ropgadget z3-solver semgrep

# CodeQL is optional and large; install on demand inside the container:
#   curl -L https://github.com/github/codeql-action/.../codeql-bundle-linux64.tar.gz | tar xz -C /opt
# (kept out of the image to stay lean; the SAST runner detects it on PATH.)

# Non-root user; engagement state stays under the single /work mount (no host creds mounted).
RUN useradd -ms /bin/bash researcher
WORKDIR /work
USER researcher

# rr needs kernel.perf_event_paranoid<=1 on the HOST; devcontainer.json documents/sets it.
LABEL org.offensive-claude.purpose="crash-exploitability pipeline (rr/gcov/afl++/feasibility)"
