---
title: Eliminate False Positives — Trace Validation Chains and Verify Reachability Before Reporting
impact: CRITICAL
impactDescription: Reduces false positive rate by 60-80%, focusing remediation effort on real vulnerabilities
tags: false-positive, validation-chain, reachability, threat-model, severity-calibration
---

## Eliminate False Positives — Trace Validation Chains and Verify Reachability Before Reporting

A pattern match at a sink is not a vulnerability. Before reporting any finding, trace backward through the full validation chain, confirm the code path is reachable from attacker-controlled input, and evaluate severity based on actual exploitability — not the CWE's theoretical maximum impact.

**Incorrect (flagging a pattern without checking upstream validation):**

```rust
// AUDIT FINDING: "CRITICAL — unchecked_add on guest-controlled value (CWE-190)"
// This is a FALSE POSITIVE.

// The auditor saw unchecked_add and stopped looking.
// But self.size was validated 50 lines earlier:
fn initialize(&mut self) -> Result<()> {
    // self.size is u16, validated: non-zero, power of two, <= 256
    if self.size == 0 || !self.size.is_power_of_two() || self.size > MAX_QUEUE_SIZE {
        return Err(Error::InvalidQueueSize);
    }
    // ...
}

fn avail_ring_end(&self) -> usize {
    // "CRITICAL overflow!" — but max value is 2 + 256 = 258. Cannot overflow usize.
    self.avail_ring_ptr.add(2_usize.unchecked_add(usize::from(self.size)))
}
```

**Correct (tracing the validation chain before assessing severity):**

```rust
// AUDIT ANALYSIS for unchecked_add at queue.rs:396
//
// Step 1 — Identify the value: self.size (u16)
// Step 2 — Trace validation chain:
//   - queue.rs:347: initialize() validates size <= MAX_QUEUE_SIZE (256)
//   - queue.rs:348: validates power of two and non-zero
//   - MAX_QUEUE_SIZE is a compile-time constant = 256
// Step 3 — Calculate actual range at sink:
//   - 2_usize + usize::from(u16 max 256) = max 258
//   - usize::MAX on 64-bit = 18,446,744,073,709,551,615
//   - Overflow: IMPOSSIBLE
// Step 4 — Verdict: Code smell (prefer checked_add for clarity), NOT a vulnerability
//
// Finding: INFORMATIONAL — unchecked_add is safe due to upstream bounds validation.
// Recommendation: Replace with checked_add for defense-in-depth, not as a security fix.
```

The five-step FP reduction protocol: (1) Identify the tainted value at the sink. (2) Trace backward through every assignment, cast, and validation to the source. (3) Calculate the actual value range at the sink given upstream constraints. (4) Confirm the code path is reachable from external input — internal assertions after invariant checks are not attacker-triggerable. (5) Rate severity based on actual exploitability, not pattern-match severity.
