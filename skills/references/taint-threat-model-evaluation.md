---
title: Evaluate Against the Project's Threat Model Before Assigning Severity
impact: CRITICAL
impactDescription: Prevents 50%+ of severity inflation by grounding findings in actual attacker capabilities
tags: threat-model, severity, attacker-capability, design-decision, false-positive
---

## Evaluate Against the Project's Threat Model Before Assigning Severity

Every project has an explicit or implicit threat model defining what attackers can and cannot do. A finding that requires capabilities outside the threat model is either informational or a design-level concern — not an exploitable vulnerability. Flagging intentional design decisions as critical vulnerabilities wastes remediation effort and erodes trust in the audit.

**Incorrect (ignoring threat model, flagging design decisions as vulnerabilities):**

```text
# AUDIT REPORT — Flagging these as HIGH/CRITICAL without threat model context

CRITICAL: Snapshot restore loads serialized VM state without integrity verification.
  → But snapshots are produced by the same Firecracker instance within a jailer chroot.
    The threat model trusts the local filesystem. This is a design decision.

HIGH: Jailer TOCTOU — directory could be replaced with symlink between create and use.
  → But the jailer runs as root creating its own directories. Exploiting this requires
    an already-compromised host — outside the threat model.

HIGH: Jailer doesn't drop privileges until exec().
  → But the jailer NEEDS root for chroot setup, cgroup creation, and mount operations.
    Dropping privileges earlier would break the sandbox. This is correct design.
```

**Correct (grounding findings in the threat model):**

```text
# AUDIT REPORT — Findings contextualized against threat model

Threat model: Firecracker assumes a malicious guest VM attempting host escape.
The host OS, jailer, and local filesystem are trusted. The API socket is
protected by jailer filesystem restrictions.

INFORMATIONAL: Snapshot restore lacks integrity verification.
  Threat model context: Snapshots are trusted local files within the jailer chroot.
  Risk: If the threat model expands to multi-tenant snapshot storage or network-
  sourced snapshots, this becomes HIGH. Flag as design limitation, not vulnerability.
  Recommendation: Document trust assumption; add optional HMAC for defense-in-depth.

NOT APPLICABLE: Jailer TOCTOU between directory creation and pivot_root.
  Threat model context: Requires already-compromised host with root access.
  The jailer is the only process manipulating these paths. Outside threat model.

NOT APPLICABLE: Jailer runs privileged operations before exec().
  This is the correct design — chroot, cgroup, and mount require CAP_SYS_ADMIN.
  Privileges are dropped at the earliest possible point (exec into Firecracker).
```

Before starting any audit, answer these questions: (1) What is the trust boundary? (2) What attacker capabilities are assumed? (3) What is explicitly trusted by design? Then categorize findings as: exploitable within threat model, exploitable if threat model expands (design limitation), or not applicable (requires capabilities outside threat model).
