---
title: Prevent Resource Exhaustion — Enforce Limits on All Allocations from Untrusted Input
impact: HIGH
impactDescription: Uncontrolled resource allocation enables denial of service by exhausting memory, CPU, disk, or connections
tags: resource-exhaustion, dos, rate-limiting, allocation-limits, cwe-770, cwe-400
---

## Prevent Resource Exhaustion — Enforce Limits on All Allocations from Untrusted Input

Resource exhaustion (CWE-770/CWE-400) occurs when applications allocate memory, CPU, disk, file descriptors, or connections based on attacker-controlled values without limits. A single request specifying a large array size, deeply nested JSON, or massive file can crash a service. 72 combined high-severity CVEs in the last 6 months (avg CVSS 7.7). Common vectors: unbounded request body sizes, uncapped collection allocations, recursive parsing, and missing connection/rate limits.

**Incorrect (allocations driven by untrusted input with no limits):**

```python
@app.route('/api/process', methods=['POST'])
def process():
    data = request.get_json()  # No body size limit
    count = data.get('count', 0)
    items = [0] * count  # Attacker sends count=10000000000 — OOM kill

    # Unbounded file read
    size = int(request.headers.get('Content-Length', 0))
    body = request.stream.read()  # Reads entire body into memory

    # No timeout on external call
    response = requests.get(data['url'])  # Attacker points to slow server — thread hung forever
    return jsonify({"items": len(items)})
```

**Correct (enforce limits on every allocation path):**

```python
from flask import Flask
from werkzeug.exceptions import RequestEntityTooLarge

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1 MB request body limit

MAX_ITEMS = 10_000
REQUEST_TIMEOUT = 5  # seconds

@app.route('/api/process', methods=['POST'])
def process():
    data = request.get_json()
    count = min(data.get('count', 0), MAX_ITEMS)  # Cap allocation
    if count < 0:
        return "Invalid count", 400
    items = [0] * count

    # Stream large bodies with bounded reads
    chunk_size = 8192
    total = 0
    for chunk in request.stream:
        total += len(chunk)
        if total > app.config['MAX_CONTENT_LENGTH']:
            return "Too large", 413
        process_chunk(chunk)

    # Always set timeouts on external calls
    response = requests.get(
        data['url'],
        timeout=REQUEST_TIMEOUT,
        stream=True,  # Don't buffer entire response
    )
    return jsonify({"items": count})
```

Apply limits at every layer: web server (request body size, header count), application (collection sizes, recursion depth), database (query timeouts, row limits), and infrastructure (connection pools, rate limiting). Set timeouts on all external calls. Use streaming for large payloads. Configure JSON parsers with depth limits (`json.loads` with custom decoder, or frameworks like FastAPI with `max_content_length`).
