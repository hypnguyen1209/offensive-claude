#!/usr/bin/env python3
"""safe_subprocess.py - hardened subprocess execution for untrusted inputs/repos.

Every active tool that shells out should go through here instead of calling subprocess
directly. The defaults are SAFE and explicit:

  * shell=False, ALWAYS. The command must be an argv *list* of strings - a bare string is
    rejected (that is the classic shell-injection foot-gun). No value is ever interpreted by
    a shell, so metacharacters in attacker-controlled args are inert.
  * A CLEAN environment. The child gets only a small safe default set (PATH + the few vars an
    interpreter needs) plus whatever the caller explicitly allowlists. Host secrets in the
    parent environment are NOT inherited.
  * Bounded. A timeout always applies; on expiry the child is killed and `timed_out` is set -
    it never hangs the engagement.
  * Fail-closed. A timeout / missing binary / policy violation is reported, never silently
    turned into a "success". `run()` does not raise on a non-zero child exit (that is data);
    it raises `SafeSubprocessError` only on a POLICY violation (string command, non-str argv).

`git_safe()` adds untrusted-repo hardening: a malicious clone must not be able to run hooks,
prompt for credentials, read host git config, follow `ext::` transports, or plant symlinks.

Pure stdlib, cross-platform (uses os.devnull, no POSIX-only deps). Mirrors scope_guard.py style.

CLI (mostly for testing / one-offs):
  safe_subprocess.py run [--cwd DIR] [--allow VAR ...] [--timeout S] -- <argv...>
  safe_subprocess.py git [--cwd DIR] [--allow VAR ...] [--timeout S] -- <git-args...>
  exit code = child's return code, or 124 on timeout, or 2 on a policy/usage error.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Optional, Sequence

DEFAULT_TIMEOUT = 60
TIMEOUT_EXIT = 124  # conventional (GNU coreutils `timeout`)
POLICY_EXIT = 2

# Vars an interpreter/loader genuinely needs to start. Everything else must be allowlisted.
# Deliberately small: no secrets, no creds, no proxy/auth vars unless the caller opts in.
if os.name == "nt":
    _SAFE_DEFAULT_VARS = ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT",
                          "TEMP", "TMP", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE")
else:
    _SAFE_DEFAULT_VARS = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TERM")


class SafeSubprocessError(Exception):
    """A POLICY violation: a string command, a non-str argv element, or a misuse.
    NOT raised for a non-zero child exit (that is a normal Result)."""


@dataclass
class Result:
    argv: list
    returncode: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def to_dict(self) -> dict:
        return {"argv": self.argv, "returncode": self.returncode, "stdout": self.stdout,
                "stderr": self.stderr, "timed_out": self.timed_out}


# --------------------------------------------------------------------------- env
def build_env(env_allow: Optional[Sequence[str]] = None,
              extra: Optional[dict] = None) -> dict:
    """A clean child environment: safe defaults + caller-allowlisted parent vars + explicit extras.
    Never inherits the full parent environment, so host secrets are not leaked to the child."""
    env: dict = {}
    for name in _SAFE_DEFAULT_VARS:
        val = os.environ.get(name)
        if val is not None:
            env[name] = val
    for name in (env_allow or ()):
        if not isinstance(name, str):
            raise SafeSubprocessError(f"env_allow entries must be strings, got {name!r}")
        val = os.environ.get(name)
        if val is not None:
            env[name] = val
    if extra:
        for k, v in extra.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise SafeSubprocessError("extra env keys and values must be strings")
            env[k] = v
    return env


def _validate_argv(cmd) -> list:
    """Enforce the core safety contract: an argv LIST of strings, never a shell string."""
    if isinstance(cmd, (str, bytes)):
        raise SafeSubprocessError(
            "command must be an argv list, not a string (shell=False is enforced; "
            "pass ['git', 'clone', url], never 'git clone ' + url)")
    try:
        argv = list(cmd)
    except TypeError as exc:
        raise SafeSubprocessError(f"command is not iterable: {cmd!r}") from exc
    if not argv:
        raise SafeSubprocessError("command argv is empty")
    for part in argv:
        if not isinstance(part, str):
            raise SafeSubprocessError(f"argv elements must be strings, got {part!r}")
    return argv


# --------------------------------------------------------------------------- run
def run(cmd: Sequence[str], *,
        cwd: Optional[str] = None,
        env_allow: Optional[Sequence[str]] = None,
        env_extra: Optional[dict] = None,
        timeout: float = DEFAULT_TIMEOUT,
        input_text: Optional[str] = None,
        allow_binaries: Optional[Sequence[str]] = None) -> Result:
    """Run `cmd` (an argv list) with shell=False, a clean env, and a hard timeout.

    Returns a Result (non-zero exit is data, not an exception). Raises SafeSubprocessError only
    on a policy violation. A timeout kills the child and returns timed_out=True."""
    argv = _validate_argv(cmd)
    if allow_binaries is not None:
        base = os.path.basename(argv[0]).lower()
        for ext in (".exe", ".cmd", ".bat", ".com"):
            if base.endswith(ext):
                base = base[: -len(ext)]
                break
        allowed = {b.lower() for b in allow_binaries}
        if base not in allowed:
            raise SafeSubprocessError(
                f"binary {argv[0]!r} not in allow_binaries {sorted(allowed)}")
    env = build_env(env_allow, env_extra)
    try:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            shell=False,                 # NEVER True
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
            check=False,                 # non-zero exit is data, surfaced in Result
        )
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        err = exc.stderr or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
        return Result(argv, None, out, err, timed_out=True)
    except FileNotFoundError as exc:
        # Missing binary is fail-closed: a Result with a non-zero code + reason, never a hang.
        return Result(argv, 127, "", f"executable not found: {argv[0]!r} ({exc})")
    except OSError as exc:
        return Result(argv, 126, "", f"could not execute {argv[0]!r}: {exc}")
    return Result(argv, proc.returncode, proc.stdout or "", proc.stderr or "")


# --------------------------------------------------------------------------- git
def git_hardening_args() -> list:
    """`-c` flags that neutralize the ways a malicious repo abuses git during clone/inspect."""
    null = os.devnull
    return [
        "-c", f"core.hooksPath={null}",   # repo cannot run hooks (pre-commit, post-checkout, ...)
        "-c", "core.fsmonitor=false",     # fsmonitor can otherwise launch a configured command
        "-c", "protocol.ext.allow=never", # ext:: transport = arbitrary command execution
        "-c", "core.symlinks=false",      # do not materialize symlinks on checkout
        "-c", "core.askPass=",            # never pop a credential helper / GUI prompt
    ]


def git_safe_env() -> dict:
    """Env that stops git from prompting, or reading system/global host config."""
    return {
        "GIT_TERMINAL_PROMPT": "0",        # no interactive credential prompt
        "GIT_CONFIG_NOSYSTEM": "1",        # ignore /etc/gitconfig
        "GIT_CONFIG_GLOBAL": os.devnull,   # ignore ~/.gitconfig
        "GIT_ASKPASS": "",                 # no askpass helper
        "GCM_INTERACTIVE": "never",        # Git Credential Manager stays quiet
    }


def git_safe(args: Sequence[str], *,
             cwd: Optional[str] = None,
             env_allow: Optional[Sequence[str]] = None,
             timeout: float = 120,
             git_binary: str = "git") -> Result:
    """Run a git subcommand against an UNTRUSTED repo with hooks/prompts/host-config disabled.

    `args` is the git subcommand argv, e.g. ['clone', '--depth', '1', url, dest] or
    ['-C', repo, 'log', '--format=%H']. Hardening `-c` flags are injected ahead of it."""
    sub = _validate_argv(args)
    argv = [git_binary, *git_hardening_args(), *sub]
    return run(argv, cwd=cwd, env_allow=env_allow, env_extra=git_safe_env(),
               timeout=timeout, allow_binaries=["git"])


# --------------------------------------------------------------------------- CLI
def _split_argv(argv):
    """Split CLI args at the '--' separator into (our_opts, child_argv)."""
    if "--" not in argv:
        return argv, []
    i = argv.index("--")
    return argv[:i], argv[i + 1:]


def main(argv: Optional[list] = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if not raw:
        print("usage: safe_subprocess.py {run|git} [opts] -- <argv...>", file=sys.stderr)
        return POLICY_EXIT
    cmd = raw[0]
    if cmd not in ("run", "git"):
        print(f"error: unknown subcommand {cmd!r} (expected run|git)", file=sys.stderr)
        return POLICY_EXIT
    our, child = _split_argv(raw[1:])
    p = argparse.ArgumentParser(prog=f"safe_subprocess.py {cmd}")
    p.add_argument("--cwd")
    p.add_argument("--allow", action="append", default=[], metavar="VAR",
                   help="copy this env var from the parent (repeatable)")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    opts = p.parse_args(our)
    if not child:
        print("error: no command after '--'", file=sys.stderr)
        return POLICY_EXIT
    try:
        if cmd == "git":
            res = git_safe(child, cwd=opts.cwd, env_allow=opts.allow, timeout=opts.timeout)
        else:
            res = run(child, cwd=opts.cwd, env_allow=opts.allow, timeout=opts.timeout)
    except SafeSubprocessError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return POLICY_EXIT
    if res.stdout:
        sys.stdout.write(res.stdout)
    if res.stderr:
        sys.stderr.write(res.stderr)
    if res.timed_out:
        print(f"error: timed out after {opts.timeout}s", file=sys.stderr)
        return TIMEOUT_EXIT
    return res.returncode if res.returncode is not None else POLICY_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
