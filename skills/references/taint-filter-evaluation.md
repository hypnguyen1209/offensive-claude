---
title: Evaluate Filters for Bypass — Prefer Allowlists and Neutralization Over Denylists
impact: CRITICAL
impactDescription: Denylist bypasses account for 40%+ of injection vulnerabilities in mature applications
tags: filter, sanitization, allowlist, denylist, bypass, neutralization
---

## Evaluate Filters for Bypass — Prefer Allowlists and Neutralization Over Denylists

When a source-to-sink path includes a filter, evaluate whether it can be bypassed. Denylist filters block known-bad values but are inherently weak — they only protect against anticipated attacks. Allowlist filters accept only predefined safe values. Neutralization uses inherently safe APIs that prevent data from being interpreted maliciously.

**Incorrect (denylist filter with multiple bypass vectors):**

```python
# Denylist approach — blocks known bad patterns but misses bypasses
def sanitize_input(value: str) -> str:
    dangerous = ["SELECT", "DROP", "DELETE", "INSERT", "UPDATE", "--", ";"]
    result = value
    for keyword in dangerous:
        result = result.replace(keyword, "")  # Case-sensitive only!
    return result

# Bypasses: "sElEcT", URL encoding "%53ELECT", double-write "SELSELECTECT"
user_input = sanitize_input(request.args.get("search"))
db.execute(f"SELECT * FROM products WHERE name LIKE '%{user_input}%'")
```

**Correct (neutralization via parameterized query — no bypass possible):**

```python
# Neutralization approach — inherently safe API prevents interpretation
def search_products(search_term: str) -> list:
    # Parameterized query: data can never become SQL structure
    query = "SELECT * FROM products WHERE name LIKE %s"
    return db.execute(query, (f"%{search_term}%",))

# For cases requiring allowlist (e.g., column names that can't be parameterized)
ALLOWED_SORT_COLUMNS = {"name", "price", "created_at"}

def get_sorted_products(sort_by: str) -> list:
    if sort_by not in ALLOWED_SORT_COLUMNS:
        sort_by = "name"  # Default to safe value
    return db.execute(f"SELECT * FROM products ORDER BY {sort_by}")
```

Even allowlists can fail: allowing hyphens in arguments enables CLI flag injection (`--admin`), allowing dots in filenames permits traversal (`../../etc/passwd`), and regex anchoring errors (`^safe` without `$`) allow injection after the match.
