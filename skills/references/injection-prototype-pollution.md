---
title: Prevent Prototype Pollution — Validate Object Keys and Use Null-Prototype Objects
impact: HIGH
impactDescription: Prototype pollution enables property injection across all objects, leading to RCE, authentication bypass, and DoS
tags: prototype-pollution, javascript, object-merge, property-injection, cwe-1321
---

## Prevent Prototype Pollution — Validate Object Keys and Use Null-Prototype Objects

Prototype pollution occurs when user-controlled input modifies `Object.prototype` through unsafe recursive merge, deep clone, or property assignment operations. Attackers inject keys like `__proto__`, `constructor`, or `prototype` to add or modify properties inherited by all JavaScript objects. This can escalate to RCE (via gadget chains in templating engines or child_process), authentication bypass (by injecting `isAdmin: true`), or denial of service. 9 high-severity CVEs in the last 6 months (avg CVSS 8.7), including CVE-2026-25047 (deephas), CVE-2025-66456 (Elysia), CVE-2026-26021 (set-in).

**Incorrect (recursive merge without key validation):**

```javascript
// Vulnerable deep merge — attacker controls both key path and value
function deepMerge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      target[key] = target[key] || {};
      deepMerge(target[key], source[key]);  // recurses into __proto__
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// POST body: {"__proto__": {"isAdmin": true}}
deepMerge({}, req.body);
// Now ALL objects inherit isAdmin === true
console.log({}.isAdmin); // true — authentication bypass
```

**Correct (block dangerous keys, use null-prototype objects):**

```javascript
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function safeMerge(target, source) {
  for (const key of Object.keys(source)) {  // Own properties only, not inherited
    if (FORBIDDEN_KEYS.has(key)) continue;   // Block prototype-polluting keys
    if (typeof source[key] === 'object' && source[key] !== null && !Array.isArray(source[key])) {
      target[key] = target[key] || Object.create(null);  // Null-prototype target
      safeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Or use Map for user-controlled key-value data instead of plain objects
const config = new Map(Object.entries(req.body));
```

Audit all deep merge, deep clone, `set`-by-path, and `defaultsDeep` calls. Libraries like lodash (pre-4.17.12), jQuery `$.extend`, and Hoek `merge` had prototype pollution bugs. Use `Object.create(null)` for lookup objects, `Map` for dynamic keys, and `Object.freeze(Object.prototype)` in hardened environments.
