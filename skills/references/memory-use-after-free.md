---
title: Eliminate Use-After-Free — Ensure Pointer Validity Across All Lifetimes
impact: CRITICAL
impactDescription: Use-after-free enables control flow hijacking via corrupted vtables and heap metadata
tags: use-after-free, dangling-pointer, double-free, lifetime, memory-safety
---

## Eliminate Use-After-Free — Ensure Pointer Validity Across All Lifetimes

Use-after-free occurs when memory is freed but a pointer to it is still used. Attackers control the freed memory's contents through heap manipulation, turning dangling reads into information disclosure and dangling writes into arbitrary code execution. Error paths that free memory without nulling the pointer are the most common source.

**Incorrect (pointer used after free on error path):**

```c
// Use-after-free: error path frees buffer but continues using it
struct Connection {
    char *buffer;
    size_t length;
    void (*handler)(struct Connection *);
};

void process_connection(struct Connection *conn) {
    conn->buffer = malloc(1024);
    if (read_data(conn->buffer, 1024) < 0) {
        free(conn->buffer);  // Freed here
        log_error(conn->buffer);  // UAF: buffer already freed
        return;
    }
    conn->handler(conn);  // If handler stored elsewhere, conn may be freed
}
```

**Correct (null after free, validate lifetime before use):**

```c
// Safe: null pointer after free, check before use
void process_connection(struct Connection *conn) {
    conn->buffer = malloc(1024);
    if (!conn->buffer) return;

    if (read_data(conn->buffer, 1024) < 0) {
        log_error("read failed");  // Log message, not freed buffer
        free(conn->buffer);
        conn->buffer = NULL;  // Prevent dangling reference
        return;
    }
    // Copy handler before use — avoid TOCTOU if conn is shared
    void (*handler)(struct Connection *) = conn->handler;
    if (handler) {
        handler(conn);
    }
}
```

In C++, watch for lambda captures of `this` in async contexts where the object may be destroyed before the lambda executes, and `std::unique_ptr` moved from but the source location still accessed. In higher-level languages, native extensions (Python C extensions, Node.js addons, JNI) inherit these risks.
