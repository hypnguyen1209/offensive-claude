---
title: Audit Unsafe Rust by Verifying Safety Invariants — Not by Flagging the Keyword
impact: CRITICAL
impactDescription: Distinguishes real soundness holes from safe unsafe code, eliminating 70%+ of Rust FPs
tags: rust, unsafe, soundness, invariants, audit, borrow-checker, ffi
---

## Audit Unsafe Rust by Verifying Safety Invariants — Not by Flagging the Keyword

Unsafe Rust blocks have documented safety invariants that the caller must uphold. Auditing unsafe code means verifying those invariants are actually maintained — not flagging every `unsafe` block as a vulnerability. Well-written unsafe code with upheld invariants is sound. The real vulnerabilities are where invariants are assumed but not enforced.

**Incorrect (flagging unsafe blocks without analyzing invariants):**

```rust
// AUDIT: "CRITICAL — unsafe pointer arithmetic, potential buffer overflow"
// This is a FALSE POSITIVE if the safety invariant holds.

/// # Safety
/// `idx` must be less than `self.size` (validated by caller via bounds check)
unsafe fn get_unchecked(&self, idx: usize) -> &T {
    &*self.ptr.add(idx)  // Auditor flags this without checking callers
}

// The auditor should check: do ALL callers validate idx < self.size?
fn process(&self, idx: usize) -> Option<&T> {
    if idx >= self.size {
        return None;  // Bounds check BEFORE unsafe call
    }
    Some(unsafe { self.get_unchecked(idx) })  // Invariant upheld ✓
}
```

**Correct (auditing the invariant enforcement, not the unsafe keyword):**

```rust
// AUDIT METHODOLOGY for unsafe blocks:
//
// Step 1: Read the safety contract (/// # Safety documentation)
// Step 2: Identify ALL callers of this unsafe function
// Step 3: For each caller, verify the precondition is enforced
// Step 4: Check for edge cases: overflow in bounds calculation,
//         concurrent modification, lifetime escapes

// REAL VULNERABILITY — invariant documented but NOT enforced:
/// # Safety
/// Descriptor chains must not reference overlapping memory regions.
pub unsafe fn from_descriptor_chain(chain: &DescriptorChain) -> IoVecBuffer {
    // No runtime check that regions don't overlap!
    // Caller is trusted to uphold this, but callers pass guest-controlled data.
    // Guest can craft overlapping descriptors → aliased mutable references → UB
    // FINDING: Soundness hole — caller cannot guarantee invariant for untrusted input
}

// SAFE — invariant is enforced:
fn write_used_element(&mut self, head_index: u16) -> Result<()> {
    if usize::from(head_index) >= self.size {
        return Err(Error::InvalidIndex);  // Enforced ✓
    }
    unsafe { self.used_ring.write(head_index) }  // Sound
}
```

Audit priority for unsafe Rust: (1) FFI boundaries — C code called via FFI has zero Rust safety guarantees. (2) Unsafe functions called with data derived from external input — the caller chain must enforce invariants before the untrusted data reaches the unsafe block. (3) Interior mutability (`UnsafeCell`) — verify no aliased mutable references. (4) Transmute/pointer casts — verify type compatibility and alignment. `.unwrap()` after a check that guarantees `Some`/`Ok` is an assertion, not a vulnerability.
