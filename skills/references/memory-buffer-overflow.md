---
title: Prevent Buffer Overflows — Validate Lengths Before All Memory Operations
impact: CRITICAL
impactDescription: Buffer overflows enable arbitrary code execution — the most severe vulnerability class
tags: buffer-overflow, memory-safety, bounds-checking, stack, heap, c, cpp
---

## Prevent Buffer Overflows — Validate Lengths Before All Memory Operations

Buffer overflows occur when data is written beyond allocated memory boundaries. Stack overflows corrupt return addresses for control flow hijacking. Heap overflows corrupt metadata for arbitrary write primitives. Off-by-one errors in null terminator handling (allocating `strlen(s)` instead of `strlen(s)+1`) are the most common variant.

**Incorrect (unbounded copy into fixed-size buffer):**

```c
// Stack buffer overflow: strcpy has no length limit
void process_username(const char *input) {
    char username[64];
    strcpy(username, input);  // If input > 63 bytes, overwrites stack
    printf("Hello, %s\n", username);
}

// Heap buffer overflow: integer overflow in size calculation
void process_image(unsigned int width, unsigned int height) {
    // width * height * 4 can overflow to a small value
    size_t size = width * height * 4;
    char *buffer = malloc(size);  // Undersized allocation
    read_pixels(buffer, width, height);  // Writes past buffer end
}
```

**Correct (bounded operations with overflow-safe arithmetic):**

```c
// Safe: explicit length limit with null termination
void process_username(const char *input) {
    char username[64];
    strncpy(username, input, sizeof(username) - 1);
    username[sizeof(username) - 1] = '\0';  // Guarantee null termination
    printf("Hello, %s\n", username);
}

// Safe: overflow-checked size calculation
void process_image(unsigned int width, unsigned int height) {
    // Check for multiplication overflow before allocation
    if (width > 0 && height > SIZE_MAX / width / 4) {
        return;  // Would overflow
    }
    size_t size = (size_t)width * height * 4;
    char *buffer = malloc(size);
    if (!buffer) return;
    read_pixels(buffer, width, height);
    free(buffer);
}
```

In ML/AI contexts, tensor shape calculations (batch_size * seq_len * hidden_dim) can trigger integer overflow leading to undersized allocations. Always use checked arithmetic for size computations derived from external data.
