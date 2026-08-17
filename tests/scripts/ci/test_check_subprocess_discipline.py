"""Tests for scripts/ci/check_subprocess_discipline.py — the shell-injection ban.

AST-based: real call sites are flagged, but the SAME tokens inside string literals / regex
detectors / comments are NOT (that's the whole reason it's not a grep). A reviewed pragma with a
reason suppresses; a bare pragma does not. Real tree is clean.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts" / "ci"))

import check_subprocess_discipline as csd  # noqa: E402

_REPO = Path(__file__).resolve().parents[3]


def test_real_tree_is_clean():
    assert csd.main(["--root", str(_REPO)]) == 0


# --------------------------------------------------- _scan_source (AST) direct
def test_flags_os_system_and_popen():
    src = "import os\nos.system('x')\nos.popen('y')\n"
    kinds = {k for _, k in csd._scan_source(src)}
    assert kinds == {"os.system", "os.popen"}


def test_flags_subprocess_shell_true():
    src = "import subprocess\nsubprocess.run(cmd, shell=True)\n"
    hits = csd._scan_source(src)
    assert hits == [(2, "shell=True")]


def test_subprocess_shell_false_is_clean():
    src = "import subprocess\nsubprocess.run(['ls', '-la'])\nsubprocess.run(x, shell=False)\n"
    assert csd._scan_source(src) == []


def test_aliased_subprocess_module_is_caught():
    src = "import subprocess as sp\nsp.run(cmd, shell=True)\n"
    assert csd._scan_source(src) == [(2, "shell=True")]


def test_from_subprocess_import_run_shell_true_caught():
    src = "from subprocess import run\nrun(cmd, shell=True)\n"
    assert csd._scan_source(src) == [(2, "shell=True")]


def test_from_subprocess_import_run_alias_caught():
    src = "from subprocess import run as r\nr(cmd, shell=True)\n"
    assert csd._scan_source(src) == [(2, "shell=True")]


def test_from_os_import_system_bare_caught():
    src = "from os import system\nsystem('x')\n"
    assert csd._scan_source(src) == [(2, "os.system")]


def test_from_os_import_system_alias_caught():
    src = "from os import system as sh, popen as po\nsh('x')\npo('y')\n"
    kinds = {k for _, k in csd._scan_source(src)}
    assert kinds == {"os.system", "os.popen"}


def test_aliased_os_module_caught():
    src = "import os as o\no.system('x')\n"
    assert csd._scan_source(src) == [(2, "os.system")]


def test_unrelated_module_run_not_flagged():
    # a .run on something that is NOT the subprocess module must not be flagged
    src = "import mymod\nmymod.run(x, shell=True)\n"
    assert csd._scan_source(src) == []


def test_string_and_regex_mentions_not_flagged():
    # payload template + detector regex mention the banned forms as DATA, not calls
    src = (
        "payload = \"{{os.popen('id').read()}}\"\n"
        "PATTERN = r'subprocess\\.run\\([^)]*shell=True'\n"
        "comment_note = 'do not use os.system here'\n"
    )
    assert csd._scan_source(src) == []


# --------------------------------------------------- pragma handling
def _write(tmp_path, rel, body):
    f = tmp_path / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(body, encoding="utf-8")


def test_pragma_with_reason_suppresses(tmp_path):
    _write(tmp_path, "skills/s/scripts/x.py",
           "import subprocess\nsubprocess.run(c, shell=True)  # noqa: subprocess-discipline - fixed local cmd, no input\n")
    assert csd.check(tmp_path) == []


def test_bare_pragma_is_itself_a_violation(tmp_path):
    _write(tmp_path, "skills/s/scripts/x.py",
           "import subprocess\nsubprocess.run(c, shell=True)  # noqa: subprocess-discipline\n")
    v = csd.check(tmp_path)
    assert len(v) == 1 and v[0].kind == "bare-pragma"


def test_pragma_with_empty_reason_is_violation(tmp_path):
    _write(tmp_path, "skills/s/scripts/x.py",
           "import subprocess\nsubprocess.run(c, shell=True)  # noqa: subprocess-discipline -   \n")
    v = csd.check(tmp_path)
    assert len(v) == 1 and v[0].kind == "bare-pragma"


# --------------------------------------------------- scanning scope
def test_tests_dir_is_skipped(tmp_path):
    _write(tmp_path, "tests/x.py", "import os\nos.system('x')\n")
    assert csd.check(tmp_path) == []


def test_syntax_error_is_reported_not_swallowed(tmp_path):
    _write(tmp_path, "skills/s/scripts/bad.py", "def (:\n")
    v = csd.check(tmp_path)
    assert len(v) == 1 and "unparseable" in v[0].kind


def test_cli_exit_1_on_violation(tmp_path):
    _write(tmp_path, "skills/s/scripts/x.py", "import os\nos.system('x')\n")
    assert csd.main(["--root", str(tmp_path)]) == 1
