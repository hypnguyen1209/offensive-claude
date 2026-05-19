---
title: Restrict File Uploads — Validate Type, Size, and Store Outside Webroot
impact: CRITICAL
impactDescription: Unrestricted file upload enables remote code execution by uploading web shells or overwriting critical files
tags: file-upload, web-shell, content-type, extension-validation, cwe-434
---

## Restrict File Uploads — Validate Type, Size, and Store Outside Webroot

Unrestricted file upload (CWE-434) allows attackers to upload executable files (web shells, scripts, malicious binaries) to a server, then execute them via direct URL access. This is one of the most exploited vulnerability classes — 133 high-severity CVEs in the last 6 months (avg CVSS 8.7) with 5 public PoCs. Bypass techniques include double extensions (`.php.jpg`), null bytes (`shell.php%00.jpg`), Content-Type spoofing, and case manipulation (`.PhP`).

**Incorrect (client-side validation and extension check only):**

```python
# Trusts client-supplied Content-Type and only checks extension
@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['document']
    if file.filename.endswith(('.jpg', '.png', '.pdf')):  # Bypassed with shell.php.jpg
        file.save(os.path.join('static/uploads', file.filename))  # Stored in webroot!
        return jsonify({"url": f"/static/uploads/{file.filename}"})
    return "Invalid file type", 400
```

**Correct (validate magic bytes, generate safe filename, store outside webroot):**

```python
import magic
import uuid
from pathlib import Path

ALLOWED_TYPES = {'image/jpeg', 'image/png', 'application/pdf'}
MAX_SIZE = 10 * 1024 * 1024  # 10 MB
UPLOAD_DIR = Path('/var/app/uploads')  # Outside webroot, not directly accessible

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['document']
    content = file.read(MAX_SIZE + 1)
    if len(content) > MAX_SIZE:
        return "File too large", 413

    # Validate actual content type via magic bytes, not client headers
    detected_type = magic.from_buffer(content, mime=True)
    if detected_type not in ALLOWED_TYPES:
        return "Invalid file type", 400

    # Generate safe filename — never use user-supplied name
    ext = {'image/jpeg': '.jpg', 'image/png': '.png', 'application/pdf': '.pdf'}[detected_type]
    safe_name = f"{uuid.uuid4()}{ext}"
    (UPLOAD_DIR / safe_name).write_bytes(content)

    # Serve files through application, not static file handler
    return jsonify({"id": safe_name})
```

Never trust file extensions or Content-Type headers. Validate content with magic byte detection. Generate random filenames server-side. Store uploads outside the webroot and serve through an application endpoint that sets `Content-Disposition: attachment`. Disable script execution in upload directories via web server config.
