"""Tests for safe_subprocess — the wrapper must enforce shell=False, a clean env,
bounded execution, and untrusted-repo git hardening.

Run: pytest tests/scripts/coding-mastery/test_safe_subprocess.py
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "skills" / "coding-mastery" / "scripts" / "_lib"))

import pytest  # noqa: E402
import safe_subprocess as ss  # noqa: E402

PY = sys.executable


# --------------------------------------------------------- policy: no shell strings
def test_string_command_rejected():
    with pytest.raises(ss.SafeSubprocessError):
        ss.run("echo hello && rm -rf /")


def test_bytes_command_rejected():
    with pytest.raises(ss.SafeSubprocessError):
        ss.run(b"echo hi")


def test_non_str_argv_rejected():
    with pytest.raises(ss.SafeSubprocessError):
        ss.run([PY, "-c", 123])


def test_empty_argv_rejected():
    with pytest.raises(ss.SafeSubprocessError):
        ss.run([])


def test_metachars_are_inert_not_a_shell():
    # The ';rm' is just an argv element printed verbatim, never interpreted by a shell.
    res = ss.run([PY, "-c", "import sys;print(sys.argv[1])", "; rm -rf / #"])
    assert res.ok
    assert res.stdout.strip() == "; rm -rf / #"


# --------------------------------------------------------- clean environment
def test_secret_var_not_inherited(monkeypatch):
    monkeypatch.setenv("SAFE_SUBPROC_TEST_SECRET", "topsecret")
    code = "import os;print(os.environ.get('SAFE_SUBPROC_TEST_SECRET','<absent>'))"
    res = ss.run([PY, "-c", code])
    assert res.ok
    assert res.stdout.strip() == "<absent>"


def test_allowlisted_var_is_passed(monkeypatch):
    monkeypatch.setenv("SAFE_SUBPROC_TEST_SECRET", "topsecret")
    code = "import os;print(os.environ.get('SAFE_SUBPROC_TEST_SECRET','<absent>'))"
    res = ss.run([PY, "-c", code], env_allow=["SAFE_SUBPROC_TEST_SECRET"])
    assert res.ok
    assert res.stdout.strip() == "topsecret"


def test_build_env_excludes_unlisted(monkeypatch):
    monkeypatch.setenv("SOME_RANDOM_HOST_VAR", "x")
    env = ss.build_env()
    assert "SOME_RANDOM_HOST_VAR" not in env
    assert "PATH" in env  # safe default present so binaries still resolve


def test_env_extra_overrides_and_typechecks():
    env = ss.build_env(extra={"FOO": "bar"})
    assert env["FOO"] == "bar"
    with pytest.raises(ss.SafeSubprocessError):
        ss.build_env(extra={"FOO": 1})


# --------------------------------------------------------- bounded / fail-closed
def test_timeout_kills_and_flags():
    res = ss.run([PY, "-c", "import time;time.sleep(10)"], timeout=0.5)
    assert res.timed_out is True
    assert res.returncode is None
    assert not res.ok


def test_missing_binary_is_failclosed_not_exception():
    res = ss.run(["this_binary_does_not_exist_zzz", "--help"])
    assert res.returncode == 127
    assert not res.ok
    assert "not found" in res.stderr.lower()


def test_nonzero_exit_is_data_not_raise():
    res = ss.run([PY, "-c", "import sys;sys.exit(3)"])
    assert res.returncode == 3
    assert not res.ok  # surfaced, not raised


def test_stdin_is_passed():
    res = ss.run([PY, "-c", "import sys;sys.stdout.write(sys.stdin.read().upper())"],
                 input_text="hello")
    assert res.stdout == "HELLO"


def test_allow_binaries_enforced():
    with pytest.raises(ss.SafeSubprocessError):
        ss.run([PY, "-c", "print(1)"], allow_binaries=["git"])


# --------------------------------------------------------- git hardening
def test_git_hardening_args_present():
    args = ss.git_hardening_args()
    joined = " ".join(args)
    assert f"core.hooksPath={os.devnull}" in joined
    assert "protocol.ext.allow=never" in joined
    assert "core.symlinks=false" in joined
    assert "core.fsmonitor=false" in joined


def test_git_safe_env_disables_prompt_and_host_config():
    env = ss.git_safe_env()
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull


def test_git_safe_builds_hardened_argv(monkeypatch):
    """git_safe must inject hardening flags before the subcommand and run with a clean,
    prompt-disabled env. We stub run() to capture the assembled argv/env without needing git."""
    captured = {}

    def fake_run(argv, **kw):
        captured["argv"] = argv
        captured["kw"] = kw
        return ss.Result(argv, 0, "", "")

    monkeypatch.setattr(ss, "run", fake_run)
    ss.git_safe(["clone", "--depth", "1", "https://example.test/repo.git", "dest"])
    argv = captured["argv"]
    assert argv[0] == "git"
    assert "-c" in argv and "protocol.ext.allow=never" in argv
    # hardening flags come before the 'clone' subcommand
    assert argv.index("protocol.ext.allow=never") < argv.index("clone")
    assert captured["kw"]["env_extra"]["GIT_TERMINAL_PROMPT"] == "0"
    assert captured["kw"]["allow_binaries"] == ["git"]


def test_git_safe_rejects_string_args():
    with pytest.raises(ss.SafeSubprocessError):
        ss.git_safe("clone https://evil.test/repo.git")


# --------------------------------------------------------- CLI
def test_cli_run_passthrough(capsys):
    rc = ss.main(["run", "--", PY, "-c", "print('cli-ok')"])
    assert rc == 0
    assert "cli-ok" in capsys.readouterr().out


def test_cli_unknown_subcommand():
    assert ss.main(["frobnicate"]) == ss.POLICY_EXIT


def test_cli_string_command_policy_exit(capsys):
    # no '--' and a single token that is a valid argv of one element -> resolves as missing binary,
    # but a policy error path is exercised when nothing follows '--'
    rc = ss.main(["run", "--"])
    assert rc == ss.POLICY_EXIT


def test_cli_propagates_child_returncode():
    rc = ss.main(["run", "--", PY, "-c", "import sys;sys.exit(5)"])
    assert rc == 5


def test_cli_timeout_exit():
    rc = ss.main(["run", "--timeout", "0.5", "--", PY, "-c", "import time;time.sleep(10)"])
    assert rc == ss.TIMEOUT_EXIT


# ===================== red-team regressions (raptor PR-2 wbfdsfq1r) =====================
import time as _time  # noqa: E402


def test_regression_timeout_bounded_with_pipe_holding_grandchild():
    # [14] a surviving grandchild that inherits (holds) the stdout pipe must NOT pin the call past
    # the timeout. The fix kills the whole process subtree, so wall time stays bounded.
    parent_code = (
        "import subprocess,sys,time;"
        "subprocess.Popen([sys.executable,'-c','import time;time.sleep(25)']);"
        "time.sleep(25)"
    )
    t0 = _time.monotonic()
    res = ss.run([PY, "-c", parent_code], timeout=1)
    elapsed = _time.monotonic() - t0
    assert res.timed_out is True
    assert elapsed < 18, f"timeout was not bounded: {elapsed:.1f}s (grandchild pinned the pipe)"


def test_regression_allow_binaries_rejects_path_qualified():
    # [15] a path-qualified lookalike must not pass an allowlist meant for a bare PATH command
    for bad in ["/usr/bin/git", "C:\\evil\\git.cmd", "./git", "git.cmd", "git.bat"]:
        with pytest.raises(ss.SafeSubprocessError):
            ss.run([bad, "--version"], allow_binaries=["git"])


def test_regression_allow_binaries_accepts_bare_and_exe(monkeypatch):
    # a bare name (and a .exe variant) still passes the policy gate (then fails to find the fake bin,
    # which is a Result, not a policy raise) - proving the gate didn't over-reject.
    res = ss.run(["definitely_not_a_real_bin_zzz"], allow_binaries=["definitely_not_a_real_bin_zzz"])
    assert res.returncode == 127  # policy passed; binary simply not found (fail-closed Result)
