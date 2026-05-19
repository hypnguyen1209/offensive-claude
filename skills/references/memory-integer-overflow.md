---
title: Guard Against Integer Overflow in Size Calculations and Loop Bounds
impact: CRITICAL
impactDescription: Integer overflow in allocations leads to heap overflow — a critical code execution vector
tags: integer-overflow, truncation, signed-unsigned, size-calculation, memory-safety
---

## Guard Against Integer Overflow in Size Calculations and Loop Bounds

Integer overflow occurs when arithmetic exceeds the type's range, wrapping to an unexpected value. When this happens in memory allocation sizes, a large intended allocation wraps to a small value, and subsequent writes overflow the undersized buffer. Signed/unsigned mismatches cause negative values to become enormous unsigned values.

**Incorrect (unchecked arithmetic in allocation and signed/unsigned mismatch):**

```c
// Integer overflow: n * sizeof(int) wraps to small value for large n
void process_items(int count) {
    // If count = 0x40000001 and sizeof(int) = 4:
    // 0x40000001 * 4 = 0x100000004, truncated to 0x4 on 32-bit
    int *items = malloc(count * sizeof(int));
    for (int i = 0; i < count; i++) {
        items[i] = read_value();  // Writes far beyond allocation
    }
}

// Signed/unsigned mismatch: negative length becomes huge positive
void copy_data(char *dst, const char *src, int length) {
    memcpy(dst, src, (size_t)length);  // length=-1 becomes SIZE_MAX
}
```

**Correct (overflow-checked arithmetic and type-safe comparisons):**

```c
// Safe: explicit overflow check before allocation
void process_items(size_t count) {
    if (count > SIZE_MAX / sizeof(int)) {
        return;  // Would overflow
    }
    int *items = malloc(count * sizeof(int));
    if (!items) return;
    for (size_t i = 0; i < count; i++) {
        items[i] = read_value();
    }
    free(items);
}

// Safe: validate non-negative before cast
void copy_data(char *dst, const char *src, int length) {
    if (length < 0 || (size_t)length > DST_SIZE) {
        return;  // Reject negative and oversized values
    }
    memcpy(dst, src, (size_t)length);
}
```

In Go, integers wrap silently in release builds (no panic). In Rust release builds, integer overflow also wraps — use `checked_mul()`, `saturating_add()`, or `wrapping_*` explicitly. ML frameworks computing tensor buffer sizes from dimensions are particularly vulnerable.
