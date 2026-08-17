"""Tests for cmd_parser — a bypass-resistant destructive-command classifier.

Ports the *logic* of ecc's gateguard destructive detector (subshell explosion,
sh -c wrappers, split/combined flags). The verdict must catch commands that a naive
`startswith("rm")` check misses, and must NEVER echo raw argument values in reasons.

Run: pytest tests/scripts/coding-mastery/test_cmd_parser.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "skills" / "coding-mastery" / "scripts" / "_lib"))

import pytest  # noqa: E402
import cmd_parser as cp  # noqa: E402


# --------------------------------------------------------------- plain destructive
@pytest.mark.parametrize("cmd", [
    "rm -rf /",
    "rm -fr /var/www",
    "rm -r -f node_modules",          # split flags
    "rm --recursive --force build",   # long flags
    "git push --force origin main",
    "git push -f",
    "git push origin +main",          # forced refspec
    "git reset --hard HEAD~3",
    "git clean -fdx",
    "git switch -C main",
    "find . -name '*.log' -exec rm {} ;",
    "dd if=/dev/zero of=/dev/sda",
    "truncate -s 0 important.db",
])
def test_destructive_true(cmd):
    v = cp.is_destructive(cmd)
    assert v.destructive is True
    assert v.reasons  # a human-readable reason is present


@pytest.mark.parametrize("cmd", [
    "rm -i file.txt",                 # interactive, not -rf
    "ls -la",
    "git status",
    "git push --force-with-lease origin main",   # the safe force
    "echo rm -rf /",                  # rm is an echo ARGUMENT, not the command word
    "grep -rf pattern .",             # -rf here is grep flags, not rm
])
def test_destructive_false(cmd):
    assert cp.is_destructive(cmd).destructive is False


# --------------------------------------------------------------- bypass corpus
def test_sh_c_wrapper_is_unwrapped():
    assert cp.is_destructive("sh -c 'rm -rf /'").destructive is True
    assert cp.is_destructive('bash -c "git reset --hard"').destructive is True


def test_command_substitution_explodes():
    assert cp.is_destructive("echo $(rm -rf /tmp/x)").destructive is True


def test_backtick_substitution_explodes():
    assert cp.is_destructive("echo `git push --force`").destructive is True


def test_subshell_group_explodes():
    assert cp.is_destructive("( rm -rf /data )").destructive is True
    assert cp.is_destructive("{ rm -rf /data; }").destructive is True


def test_chained_command_any_segment_destructive():
    assert cp.is_destructive("cd /tmp && rm -rf build").destructive is True
    assert cp.is_destructive("make; rm -rf dist").destructive is True
    assert cp.is_destructive("ok || git reset --hard").destructive is True


# --------------------------------------------------------------- safety of output
def test_reasons_never_leak_full_command():
    # A reason names the *kind* of danger, not the full raw argument string
    secret = "rm -rf /etc/shadow-SECRETTOKEN"
    v = cp.is_destructive(secret)
    assert v.destructive is True
    assert "SECRETTOKEN" not in " ".join(v.reasons)


def test_empty_and_none_safe():
    assert cp.is_destructive("").destructive is False
    assert cp.is_destructive(None).destructive is False


# --------------------------------------------------------------- CLI
def test_cli_exit_codes(capsys):
    assert cp.main(["--command", "rm -rf /"]) == 5      # destructive -> block exit
    assert cp.main(["--command", "ls -la"]) == 0        # safe
