---
title: Guard Against NULL Pointer Dereference — Validate All Pointer and Reference Values Before Use
impact: HIGH
impactDescription: NULL dereferences cause crashes enabling denial of service, and in some contexts allow attacker-controlled memory writes
tags: null-pointer, null-dereference, segfault, denial-of-service, cwe-476
---

## Guard Against NULL Pointer Dereference — Validate All Pointer and Reference Values Before Use

NULL pointer dereference (CWE-476) occurs when code uses a pointer or reference that may be NULL without checking first. In most cases this causes a crash (segfault/SIGSEGV), enabling denial of service. In rare cases on systems without memory protection, writing through a NULL pointer can corrupt memory at address zero, enabling code execution. 27 high-severity CVEs in the last 6 months (avg CVSS 7.5). Common vectors: unchecked return values from allocation or lookup functions, error paths that forget to return early, and chained dereferences where intermediate results can be NULL.

**Incorrect (using pointers without NULL checks):**

```c
// Unchecked malloc return
void process_data(size_t count) {
    struct item *items = malloc(count * sizeof(struct item));
    items[0].value = 42;  // Crash if malloc returned NULL (OOM)

    // Unchecked lookup result
    struct user *user = find_user_by_id(user_id);
    printf("Name: %s\n", user->name);  // Crash if user not found
}
```

```python
# Unchecked dictionary/attribute access chains
def get_user_email(response):
    data = response.json()
    # Crashes with TypeError if 'user' key missing or None
    return data['user']['profile']['email']

# Unchecked return from database query
def update_user(user_id, new_name):
    user = db.session.query(User).filter_by(id=user_id).first()
    user.name = new_name  # AttributeError if user is None
    db.session.commit()
```

**Correct (validate before use):**

```c
void process_data(size_t count) {
    if (count == 0 || count > MAX_ITEMS) {
        return;
    }
    struct item *items = malloc(count * sizeof(struct item));
    if (items == NULL) {
        log_error("allocation failed for %zu items", count);
        return;
    }
    items[0].value = 42;

    struct user *user = find_user_by_id(user_id);
    if (user == NULL) {
        log_error("user %d not found", user_id);
        return;
    }
    printf("Name: %s\n", user->name);
}
```

```python
def get_user_email(response):
    data = response.json()
    user = data.get('user')
    if user is None:
        return None
    profile = user.get('profile')
    if profile is None:
        return None
    return profile.get('email')

def update_user(user_id, new_name):
    user = db.session.query(User).filter_by(id=user_id).first()
    if user is None:
        raise ValueError(f"User {user_id} not found")
    user.name = new_name
    db.session.commit()
```

In C/C++, always check `malloc`/`calloc` return values and function results that may return NULL. Use static analysis tools (clang-tidy `bugprone-null-dereference`, Coverity) to catch unchecked paths. In Rust, leverage `Option<T>` — never use `unwrap()` on values from external input. In Python/JS, use optional chaining (`user?.profile?.email`) or explicit None checks for any data from external sources.
