---
title: Eliminate SQL Injection — Use Parameterized Queries for All Database Operations
impact: CRITICAL
impactDescription: SQL injection enables full database compromise including data exfiltration and modification
tags: sql-injection, parameterized-queries, orm, prepared-statements, database
---

## Eliminate SQL Injection — Use Parameterized Queries for All Database Operations

SQL injection occurs when user-controlled data is concatenated into SQL query strings, allowing attackers to modify query structure. This includes direct injection in raw queries and second-order injection where stored data is later used unsafely. ORM raw query methods (Django `raw()`, SQLAlchemy `text()`, ActiveRecord `find_by_sql()`) are common bypass points.

**Incorrect (string concatenation and ORM raw query with interpolation):**

```python
# Direct SQL injection via f-string
def get_user(user_id: str):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return db.execute(query)  # user_id = "' OR '1'='1" dumps all users

# Second-order: data stored safely but used unsafely later
def generate_report(username: str):
    # username was stored via parameterized INSERT, but...
    user = db.execute("SELECT name FROM users WHERE username = %s", (username,))
    # ...now used unsafely in a different query
    query = f"SELECT * FROM orders WHERE customer_name = '{user.name}'"
    return db.execute(query)  # Stored name with quotes breaks query
```

**Correct (parameterized queries everywhere, including ORM raw methods):**

```python
# Parameterized: data can never become SQL structure
def get_user(user_id: str):
    return db.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Second-order: parameterize ALL queries, even with "trusted" stored data
def generate_report(username: str):
    user = db.execute("SELECT name FROM users WHERE username = %s", (username,))
    return db.execute(
        "SELECT * FROM orders WHERE customer_name = %s", (user.name,)
    )

# For dynamic column names (can't parameterize), use strict allowlist
ALLOWED_COLUMNS = {"name", "created_at", "status"}

def sort_users(sort_by: str):
    if sort_by not in ALLOWED_COLUMNS:
        sort_by = "name"
    return db.execute(f"SELECT * FROM users ORDER BY {sort_by}")
```

Watch for ORDER BY, LIMIT, and table/column names — these cannot be parameterized in most databases and require strict allowlist validation. LIKE patterns with user-controlled wildcards (`%`, `_`) can cause denial of service through expensive scans.
