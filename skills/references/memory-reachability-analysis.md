---
title: Verify Attacker Reachability Before Reporting Panics and Assertions as Vulnerabilities
impact: CRITICAL
impactDescription: Eliminates 50%+ of DoS false positives by distinguishing internal assertions from attacker-triggerable panics
tags: reachability, panic, unwrap, assertion, dos, attacker-controlled, code-path
---

## Verify Attacker Reachability Before Reporting Panics and Assertions as Vulnerabilities

Not every `.unwrap()`, `.expect()`, or `assert!()` is a denial-of-service vulnerability. Many are internal invariant assertions placed after code that guarantees the value is `Some`/`Ok`. The key question is: can an attacker control the input that makes this panic reachable? If the panic is only reachable through violated internal invariants (which would indicate a bug, not an attack), it is not an exploitable vulnerability.

**Incorrect (flagging all unwrap/expect as attacker-triggerable DoS):**

```rust
// AUDIT: "HIGH — Guest-triggered VMM crash via .unwrap() in device handler"
// This is a FALSE POSITIVE — the unwrap is guarded by prior validation.

fn process_queue(&mut self) -> Result<()> {
    // Step 1: Parse descriptors with full validation (returns Err on invalid)
    let descriptors = self.parse_descriptors()?;  // Validated ✓

    // Step 2: Process each validated descriptor
    for desc in &descriptors {
        self.write_response(desc)?;
    }

    // Step 3: Mark as used — unwrap is safe because descriptors were validated above
    let head = descriptors.first().unwrap();  // <-- Auditor flagged this
    // But descriptors is non-empty: parse_descriptors returns Err if no valid
    // descriptors found. If we reached here, .first() is always Some.
    self.used_ring.add(head.index).expect("index validated during parsing");
    // .expect() is reachable only if internal bookkeeping is corrupted,
    // NOT from guest input. This is an assertion, not a vulnerability.
    Ok(())
}
```

**Correct (distinguishing reachable panics from internal assertions):**

```rust
// REAL attacker-triggerable panic — external input directly controls panic path:
fn handle_request(&self, request: &[u8]) -> Response {
    let command = std::str::from_utf8(request).unwrap();  // VULNERABLE
    // Attacker sends invalid UTF-8 → panic → DoS
    // Fix: use from_utf8(request).map_err(|_| Error::InvalidInput)?
    process(command)
}

// NOT attacker-triggerable — internal invariant after successful validation:
fn handle_request(&self, request: &[u8]) -> Result<Response> {
    let validated = self.validate(request)?;  // Returns Err on invalid input
    // If we reach here, validated.header is guaranteed to be present
    // because validate() checks for it and returns Err if missing
    let header = validated.header.unwrap();  // Safe: validate() guarantees Some
    Ok(self.process(header))
}

// REACHABILITY ANALYSIS CHECKLIST:
// 1. Identify the value being unwrapped
// 2. Trace backward: what conditions make it None/Err?
// 3. Check if those conditions are prevented by prior validation
// 4. If prior validation is in a DIFFERENT function, verify ALL callers validate
// 5. If the panic is reachable only through internal invariant violation → NOT a vuln
// 6. If the panic is reachable from external input → REAL DoS finding
```

For Rust specifically: `.unwrap()` after `.get(idx)` where `idx` was bounds-checked is safe. `.expect()` after a match/if-let that handles the `None`/`Err` case is safe. The audit should focus on unwrap/expect where the value comes from external input without prior validation in the same call chain.
