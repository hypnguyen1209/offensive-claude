---
title: Prevent Server-Side Template Injection — Never Embed User Input in Template Strings
impact: CRITICAL
impactDescription: SSTI enables remote code execution through template engine evaluation
tags: ssti, template-injection, jinja2, freemarker, code-execution, rce
---

## Prevent Server-Side Template Injection — Never Embed User Input in Template Strings

Server-side template injection occurs when user input is embedded directly into template strings before compilation, allowing attackers to execute arbitrary code through the template engine. Jinja2, Twig, Freemarker, Velocity, Pebble, and Thymeleaf all support expressions that can achieve code execution. Even "sandboxed" template engines frequently have escape vectors.

**Incorrect (user input compiled as part of template):**

```python
from flask import Flask, request
from jinja2 import Template

# SSTI: user input becomes part of the template itself
@app.route("/greet")
def greet():
    name = request.args.get("name")
    template = Template(f"Hello, {name}!")  # name = "{{config.items()}}"
    return template.render()
    # Attacker uses: {{''.__class__.__mro__[1].__subclasses__()}} for RCE

# Also vulnerable: render_template_string with user data
@app.route("/page")
def dynamic_page():
    content = request.form.get("content")
    return render_template_string(content)  # Full template control = RCE
```

**Correct (user input passed as data to a pre-compiled template):**

```python
from flask import Flask, request, render_template_string

# Safe: user input is DATA passed to the template, not part of it
@app.route("/greet")
def greet():
    name = request.args.get("name")
    return render_template_string("Hello, {{ name }}!", name=name)
    # {{ and }} in name are displayed literally, not evaluated

# Best: use template files, not string construction
@app.route("/page")
def dynamic_page():
    content = request.form.get("content")
    return render_template("page.html", content=content)
    # page.html: <div>{{ content }}</div> — auto-escaped by Jinja2
```

Test for SSTI by injecting `{{7*7}}` — if the response contains `49`, the template engine is evaluating user input. Freemarker uses `${7*7}`, Velocity uses `#set($x=7*7)${x}`. Flask's `render_template_string()` with user-controlled first argument is always an RCE vulnerability.
