---
title: Trace Every Source-to-Sink Path With Systematic Taint Analysis
impact: CRITICAL
impactDescription: Identifies 80%+ of exploitable vulnerabilities by tracking untrusted data flow
tags: taint-analysis, source, sink, data-flow, methodology
---

## Trace Every Source-to-Sink Path With Systematic Taint Analysis

Mark untrusted data as "tainted" at its origin (source) and track how it propagates through the program to dangerous operations (sink). A vulnerability exists when tainted data reaches a sink without adequate sanitization. Direct sources are explicit user inputs; indirect sources are data retrieved from storage that was originally user-supplied.

**Incorrect (no taint tracking — user input flows directly to dangerous sink):**

```python
# Source: request parameter
# Sink: SQL query execution
# No sanitization between source and sink
@app.route("/users")
def get_user():
    user_id = request.args.get("id")  # SOURCE: untrusted
    query = f"SELECT * FROM users WHERE id = '{user_id}'"  # SINK: SQL execution
    result = db.execute(query)  # Tainted data reaches sink unsanitized
    return jsonify(result)
```

**Correct (taint neutralized before reaching sink via parameterized query):**

```python
# Source: request parameter
# Sanitizer: parameterized query (neutralization)
# Sink: SQL query execution — taint cannot affect query structure
@app.route("/users")
def get_user():
    user_id = request.args.get("id")  # SOURCE: untrusted
    query = "SELECT * FROM users WHERE id = %s"  # Parameterized
    result = db.execute(query, (user_id,))  # SINK: taint neutralized by parameterization
    return jsonify(result)
```

Track indirect sources carefully: a comment stored safely in a database becomes a new taint source when retrieved and rendered on another page (stored XSS pattern). Sanitizers should be placed as close to the sink as possible — placing them at the input boundary leaves alternate code paths unprotected.
