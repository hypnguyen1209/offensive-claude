---
title: Prevent Out-of-Bounds Read — Validate Buffer Indices and Lengths Before Access
impact: HIGH
impactDescription: Out-of-bounds reads leak sensitive memory contents including keys, tokens, and ASLR layout
tags: out-of-bounds-read, buffer-overread, memory-disclosure, heartbleed, cwe-125
---

## Prevent Out-of-Bounds Read — Validate Buffer Indices and Lengths Before Access

Out-of-bounds read (CWE-125) occurs when code reads memory beyond the allocated buffer boundary, leaking adjacent data. This is distinct from buffer overflow (write) — OOB reads don't corrupt memory but expose secrets (Heartbleed leaked TLS private keys). 115 high-severity CVEs in the last 6 months (avg CVSS 7.6). Common in C/C++ with unchecked index arithmetic, length fields from untrusted input, and off-by-one errors in loop bounds.

**Incorrect (trusts user-supplied length without validation):**

```c
// Attacker controls 'length' field in protocol message
void process_message(const uint8_t *buffer, size_t buffer_size) {
    uint16_t payload_length = ntohs(*(uint16_t *)buffer);  // From untrusted input
    uint8_t *response = malloc(payload_length);

    // Copies payload_length bytes but buffer may be smaller — reads past end
    memcpy(response, buffer + 2, payload_length);  // OOB read if payload_length > buffer_size - 2
    send_response(response, payload_length);
    free(response);
}
```

**Correct (validate all lengths against actual buffer bounds):**

```c
int process_message(const uint8_t *buffer, size_t buffer_size) {
    if (buffer_size < 2) return -1;  // Need at least the length field

    uint16_t payload_length = ntohs(*(uint16_t *)buffer);

    // Validate claimed length against actual available data
    if (payload_length > buffer_size - 2) return -1;  // Reject, don't truncate silently

    uint8_t *response = malloc(payload_length);
    if (!response) return -1;

    memcpy(response, buffer + 2, payload_length);  // Now guaranteed in-bounds
    send_response(response, payload_length);
    free(response);
    return 0;
}
```

Every length, index, or offset derived from external input must be validated against the actual buffer size before use. Check for integer overflow in size calculations (`offset + length` can wrap). In C, use `size_t` for sizes and check `offset + length <= buffer_size` with overflow-safe arithmetic. In Rust, use slice indexing (panics on OOB) or `.get()` (returns `Option`). Treat any protocol field specifying a length as untrusted.
