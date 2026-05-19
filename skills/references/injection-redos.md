---
title: Prevent Regular Expression Denial of Service (ReDoS) — Avoid Catastrophic Backtracking
impact: HIGH
impactDescription: ReDoS causes application hangs via crafted input that triggers exponential regex backtracking
tags: redos, regex, denial-of-service, backtracking, cwe-1333
---

## Prevent Regular Expression Denial of Service (ReDoS) — Avoid Catastrophic Backtracking

ReDoS (CWE-1333) occurs when a regular expression with ambiguous quantifiers enters catastrophic backtracking on attacker-crafted input. Patterns with nested quantifiers (`(a+)+`), overlapping alternations (`(a|a)+`), or repeated groups with overlapping character classes cause exponential time complexity. 8 high-severity CVEs in the last 6 months (avg CVSS 7.6). A single request with a ~30-character payload can freeze a Node.js event loop for minutes.

**Incorrect (vulnerable regex patterns with catastrophic backtracking):**

```javascript
// Nested quantifiers — exponential backtracking on "aaaaaaaaaaaaaaaaX"
const emailRegex = /^([a-zA-Z0-9]+)+@[a-zA-Z]+\.[a-zA-Z]+$/;

// Overlapping alternation with quantifier
const urlRegex = /^(https?:\/\/)?([\w-]+\.)+[\w-]+(\/[\w-./?%&=]*)*$/;

function validateEmail(input) {
  return emailRegex.test(input);  // Hangs on "a".repeat(25) + "!"
}
```

**Correct (use atomic patterns, bounded quantifiers, or RE2):**

```javascript
// Option 1: Bounded quantifiers prevent catastrophic backtracking
const safeEmailRegex = /^[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,253}\.[a-zA-Z]{2,63}$/;

// Option 2: Use RE2 engine (linear-time guarantee, no backtracking)
const RE2 = require('re2');
const safePattern = new RE2('^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$');

function validateEmail(input) {
  if (input.length > 254) return false;  // RFC 5321 max length
  return safePattern.test(input);
}

// Option 3: Avoid regex entirely for structured validation
function validateEmailSimple(input) {
  if (input.length > 254) return false;
  const atIndex = input.indexOf('@');
  if (atIndex < 1 || atIndex > 64) return false;
  const domain = input.slice(atIndex + 1);
  return domain.includes('.') && domain.length <= 253;
}
```

Audit all regex patterns that process user input. Use tools like `recheck`, `safe-regex`, or `vuln-regex-detector` to identify vulnerable patterns. Prefer the RE2 engine (linear-time guarantee) for untrusted input. Add input length limits before regex matching. In Node.js, consider `validator.js` instead of custom regex for common formats.
