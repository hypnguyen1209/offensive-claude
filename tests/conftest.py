"""Pytest bootstrap: put every skill's scripts/ (and scripts/_lib/) on sys.path so
tests can `import scope_guard`, `import validate_findings`, etc. without packaging.

Cross-platform; no external deps. Also runnable under plain `python -m unittest`
because each test file repeats a minimal sys.path insert.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _script_dirs():
    skills = ROOT / "skills"
    if not skills.is_dir():
        return
    for scripts in skills.glob("*/scripts"):
        yield scripts
        lib = scripts / "_lib"
        if lib.is_dir():
            yield lib


for _d in _script_dirs():
    s = str(_d)
    if s not in sys.path:
        sys.path.insert(0, s)
