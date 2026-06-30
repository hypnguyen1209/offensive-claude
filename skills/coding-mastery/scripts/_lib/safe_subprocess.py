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
import signal
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Optional, Sequence

DEFAULT_TIMEOUT = 60
TIMEOUT_EXIT = 124  # conventional (GNU coreutils `timeout`)
POLICY_EXIT = 2
DRAIN_TIMEOUT = 5   # hard secondary deadline so a surviving descendant cannot pin the call forever

# Vars an interpreter/loader genuinely needs to start. Everything else must be allowlisted.
# Deliberately small: no secrets, no creds, no proxy/auth vars unless the caller opts in.
if os.name == "nt":
    _SAFE_DEFAULT_VARS = ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT",
                          "TEMP", "TMP", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE")
else:
    _SAFE_DEFAULT_VARS = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TERM")

# Windows process-tree containment. A Job Object with KILL_ON_JOB_CLOSE kills the WHOLE tree when we
# close the handle - the equivalent of POSIX killpg, and (unlike `taskkill /T <child-pid>`) robust to
# a child that exits and re-parents its descendants. All ctypes here is best-effort: any failure
# falls back to taskkill /T (still bounded). POSIX uses start_new_session + killpg (see run/_kill_tree).
_WIN = os.name == "nt"
if _WIN:
    import ctypes
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    _JobObjectExtendedLimitInformation = 9
    _k32.CreateJobObjectW.restype = wintypes.HANDLE
    _k32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    _k32.SetInformationJobObject.restype = wintypes.BOOL
    _k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    _k32.AssignProcessToJobObject.restype = wintypes.BOOL
    _k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _k32.CloseHandle.restype = wintypes.BOOL
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]

    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
                    ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_void_p),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [("ReadOperationCount", ctypes.c_ulonglong),
                    ("WriteOperationCount", ctypes.c_ulonglong),
                    ("OtherOperationCount", ctypes.c_ulonglong),
                    ("ReadTransferCount", ctypes.c_ulonglong),
                    ("WriteTransferCount", ctypes.c_ulonglong),
                    ("OtherTransferCount", ctypes.c_ulonglong)]

    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ("IoInfo", _IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]


def _assign_to_job(proc):
    """Windows only: place the child in a kill-on-close Job Object. Returns the job handle or None
    (None => caller relies on taskkill /T). Best-effort; never raises."""
    if not _WIN:
        return None
    try:
        job = _k32.CreateJobObjectW(None, None)
        if not job:
            return None
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not _k32.SetInformationJobObject(job, _JobObjectExtendedLimitInformation,
                                            ctypes.byref(info), ctypes.sizeof(info)):
            _k32.CloseHandle(job)
            return None
        if not _k32.AssignProcessToJobObject(job, int(proc._handle)):
            _k32.CloseHandle(job)
            return None
        return job
    except Exception:
        return None


def _close_job(job):
    """Closing the last handle to a KILL_ON_JOB_CLOSE job terminates every process still in it."""
    if job is None:
        return
    try:
        _k32.CloseHandle(job)
    except Exception:
        pass


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
def _kill_tree(proc) -> None:
    """Terminate the child AND its descendants. POSIX: kill the session group; Windows: taskkill /T.
    Best-effort and bounded - falls back to killing just the child, never raises."""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=DRAIN_TIMEOUT)
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


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
        cmd0 = argv[0]
        # an allowlist means "the trusted program found on PATH" - a path-qualified argv[0]
        # (C:\evil\git.cmd, /tmp/git) would run an attacker-plantable lookalike, so reject it.
        if "/" in cmd0 or "\\" in cmd0 or (os.name == "nt" and ":" in cmd0):
            raise SafeSubprocessError(
                f"allow_binaries requires a bare command name (no path/drive), got {cmd0!r}")
        base = cmd0.lower()
        if base.endswith(".exe"):        # strip only .exe; .cmd/.bat/.com select different launchers
            base = base[:-4]
        allowed = {b.lower() for b in allow_binaries}
        if base not in allowed:
            raise SafeSubprocessError(
                f"binary {argv[0]!r} not in allow_binaries {sorted(allowed)}")
    env = build_env(env_allow, env_extra)
    # Run in its own process group/session so a timeout can kill the WHOLE subtree. A plain
    # subprocess.run(timeout=) only kills the direct child, then blocks on the captured pipes that a
    # surviving grandchild (e.g. git's network helper / fsmonitor) still holds open - that is the
    # fail-open hang this guards against.
    popen_kwargs: dict = {}
    if os.name == "nt":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["start_new_session"] = True
    try:
        proc = subprocess.Popen(
            argv, cwd=cwd, env=env, shell=False,
            stdin=subprocess.PIPE if input_text is not None else None,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            # Decode DETERMINISTICALLY as UTF-8 (what git/most tools emit), not the host locale -
            # otherwise a non-UTF-8 locale (e.g. cp1258) mojibake-corrupts non-ASCII output and can
            # even raise mid-read. errors='replace' never crashes on the rare non-UTF-8 byte.
            encoding="utf-8", errors="replace", **popen_kwargs)
    except FileNotFoundError as exc:
        return Result(argv, 127, "", f"executable not found: {argv[0]!r} ({exc})")
    except OSError as exc:
        return Result(argv, 126, "", f"could not execute {argv[0]!r}: {exc}")
    job = _assign_to_job(proc)        # Windows: kill-on-close job for the whole tree (None on POSIX)
    try:
        try:
            out, err = proc.communicate(input=input_text, timeout=timeout)
            return Result(argv, proc.returncode, out or "", err or "")
        except subprocess.TimeoutExpired:
            _kill_tree(proc)                                  # kill the subtree, not just the child
            try:
                out, err = proc.communicate(timeout=DRAIN_TIMEOUT)   # bounded drain; never re-block forever
            except (subprocess.TimeoutExpired, OSError):
                out, err = "", ""                             # a survivor still holds the pipe -> abandon
            return Result(argv, None, out or "", err or "", timed_out=True)
        except OSError as exc:
            _kill_tree(proc)
            return Result(argv, 126, "", f"io error running {argv[0]!r}: {exc}")
    finally:
        _close_job(job)               # KILL_ON_JOB_CLOSE: any straggler the taskkill missed dies now


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
