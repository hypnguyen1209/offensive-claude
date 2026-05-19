---
title: Prevent Cross-Site Scripting — Apply Context-Appropriate Output Encoding
impact: CRITICAL
impactDescription: XSS enables session hijacking, credential theft, and full account takeover
tags: xss, cross-site-scripting, output-encoding, dom, sanitization, html
---

## Prevent Cross-Site Scripting — Apply Context-Appropriate Output Encoding

XSS occurs when attacker-controlled data is rendered in a browser without proper encoding for the output context. HTML context needs HTML entity encoding, JavaScript context needs JS encoding, URL context needs URL encoding — using the wrong encoding for the context is equivalent to no encoding. DOM-based XSS flows entirely client-side through `document.location`, `document.URL`, or `postMessage` handlers.

**Incorrect (raw user data in multiple rendering contexts):**

```javascript
// Reflected XSS: user input in innerHTML
app.get("/search", (req, res) => {
  const query = req.query.q;
  res.send(`<h1>Results for: ${query}</h1>`);  // <script>alert(1)</script>
});

// DOM-based XSS: hash fragment into innerHTML
document.getElementById("output").innerHTML = location.hash.slice(1);

// React: dangerouslySetInnerHTML with user data
function Comment({ text }) {
  return <div dangerouslySetInnerHTML={{ __html: text }} />;
}

// Context mismatch: HTML-encoded data in JavaScript context
app.get("/profile", (req, res) => {
  const name = escapeHtml(req.query.name);
  res.send(`<script>var user = "${name}";</script>`);
  // HTML encoding doesn't prevent JS string escape: \";alert(1)//
});
```

**Correct (context-appropriate encoding and safe APIs):**

```javascript
// Safe: use text content or template engine with auto-escaping
app.get("/search", (req, res) => {
  const query = req.query.q;
  res.render("search", { query });  // Template engine auto-escapes for HTML
});

// Safe: use textContent instead of innerHTML for text data
document.getElementById("output").textContent = location.hash.slice(1);

// Safe: React auto-escapes by default — don't bypass it
function Comment({ text }) {
  return <div>{text}</div>;  // React escapes automatically
}

// Safe: JSON serialization for JavaScript context
app.get("/profile", (req, res) => {
  const name = req.query.name;
  res.send(`<script>var user = ${JSON.stringify(name)};</script>`);
  // JSON.stringify handles all JS special characters correctly
});
```

Watch for mutation XSS (mXSS) where sanitized HTML is re-interpreted by the browser parser. `javascript:` URLs in `href` attributes bypass HTML encoding. SVG and MathML contexts support inline scripts. PostMessage handlers must validate `event.origin` before trusting message data.
