"""Tests for pack_target.py - scoped packing, secret gate, token budget, compress mode."""
import json
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts" / "recon"
sys.path.insert(0, str(_SCRIPTS))

import pack_target as pt  # noqa: E402


def _tree(tmp_path, files):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return str(tmp_path)


def test_estimate_tokens_is_chars_over_four():
    assert pt.estimate_tokens("") == 0
    assert pt.estimate_tokens("abcd") == 1
    assert pt.estimate_tokens("a" * 400) == 100


def test_pack_includes_structure_and_bodies(tmp_path):
    root = _tree(tmp_path, {"app.py": "def f():\n    return 1\n", "readme.md": "hello\n"})
    res = pack = pt.pack(root, max_tokens=50_000)
    assert "## Structure" in pack.body
    assert "app.py" in pack.body and "def f" in pack.body
    assert {f.path for f in res.included} == {"app.py", "readme.md"}


def test_secret_gate_redacts_value_but_keeps_location(tmp_path):
    root = _tree(tmp_path, {
        "conf.py": "SAFE = 1\nAWS = 'AKIAIOSFODNN7EXAMPLE'\nMORE = 2\n",
    })
    res = pt.pack(root, max_tokens=50_000)
    # the literal secret value must NOT appear in the pack
    assert "AKIAIOSFODNN7EXAMPLE" not in res.body
    # but the redaction marker + rule + line do
    assert "REDACTED secret" in res.body
    assert res.secret_files == 1
    inc = {f.path: f for f in res.included}
    assert inc["conf.py"].secrets and inc["conf.py"].secrets[0]["rule"] == "aws-access-key-id"
    # surrounding safe lines survive intact
    assert "SAFE = 1" in res.body and "MORE = 2" in res.body


def test_compress_mode_keeps_signatures_only(tmp_path):
    root = _tree(tmp_path, {
        "m.py": "def alpha(a, b):\n    secret_body = 42\n    return a + b\n"
                "class C:\n    def meth(self, x):\n        return x\n",
    })
    res = pt.pack(root, max_tokens=50_000, compress=True)
    body = res.body
    assert "def alpha(a, b): ..." in body
    assert "class C:" in body
    assert "def meth(self, x): ..." in body
    # the body statements are gone in signature mode
    assert "secret_body = 42" not in body
    assert any(f.mode == "signatures" for f in res.included)


def test_compress_degrades_to_full_on_syntax_error(tmp_path):
    root = _tree(tmp_path, {"broken.py": "def oops(:\n    this is not python\n"})
    res = pt.pack(root, max_tokens=50_000, compress=True)
    inc = {f.path: f for f in res.included}
    assert inc["broken.py"].mode == "full"          # unparseable -> full body, not dropped
    assert "this is not python" in res.body


def test_token_budget_drops_and_reports(tmp_path):
    big = "x = 1\n" * 2000                          # ~ large file
    root = _tree(tmp_path, {"big.py": big, "small.py": "y = 2\n"})
    res = pt.pack(root, max_tokens=50)               # tiny budget
    dropped = {f.path for f in res.dropped if f.mode == "skipped-budget"}
    assert "big.py" in dropped                        # too big for the budget, explicitly dropped
    assert res.total_tokens <= 50 + pt.estimate_tokens("")  # stayed within budget


def test_lang_filter_restricts_extensions(tmp_path):
    root = _tree(tmp_path, {"a.py": "p = 1\n", "b.js": "var q = 2\n", "c.md": "doc\n"})
    res = pt.pack(root, max_tokens=50_000, langs={"py"})
    paths = {f.path for f in res.included}
    assert "a.py" in paths and "b.js" not in paths and "c.md" not in paths


def test_skip_dirs_are_excluded(tmp_path):
    root = _tree(tmp_path, {
        "real.py": "a = 1\n",
        "node_modules/dep.js": "junk\n",
        ".git/config.py": "b = 2\n",
    })
    res = pt.pack(root, max_tokens=50_000)
    paths = {f.path for f in res.included}
    assert "real.py" in paths
    assert not any("node_modules" in p or ".git" in p for p in paths)


def test_binary_file_skipped(tmp_path):
    root = tmp_path
    (root / "blob.json").write_bytes(b"\x00\x01\x02binary\x00data")
    (root / "ok.py").write_text("z = 1\n", encoding="utf-8")
    res = pt.pack(str(root), max_tokens=50_000)
    assert any(d.path == "blob.json" and d.mode == "skipped-binary" for d in res.dropped)
    assert any(f.path == "ok.py" for f in res.included)


# --------------------------------------------------------- CLI
def test_cli_writes_pack_file(tmp_path, capsys):
    root = _tree(tmp_path, {"app.py": "def f():\n    return 1\n"})
    out = tmp_path / "out" / "pack.md"
    rc = pt.main(["--root", root, "--out", str(out)])
    assert rc == 0
    assert out.exists() and "def f" in out.read_text(encoding="utf-8")
    assert "packed 1 file" in capsys.readouterr().out


def test_cli_json_manifest(tmp_path, capsys):
    root = _tree(tmp_path, {"a.py": "x = 1\n"})
    rc = pt.main(["--root", root, "--json"])
    assert rc == 0
    manifest = json.loads(capsys.readouterr().out)
    assert manifest["included"][0]["path"] == "a.py"


def test_cli_secret_gate_message(tmp_path, capsys):
    root = _tree(tmp_path, {"s.py": "K = 'AKIAIOSFODNN7EXAMPLE'\n"})
    rc = pt.main(["--root", root, "--out", str(tmp_path / "p.md"), "--json"])
    assert rc == 0
    manifest = json.loads(capsys.readouterr().out)
    assert manifest["secret_files"] == 1


def test_cli_bad_root_errors(tmp_path):
    assert pt.main(["--root", str(tmp_path / "nope")]) == 2
