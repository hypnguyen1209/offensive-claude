---
title: Distinguish Privileged Setup Phases From Privilege Escalation Vulnerabilities
impact: HIGH
impactDescription: Prevents flagging correct sandbox and container initialization as security vulnerabilities
tags: privilege, sandbox, jailer, chroot, capabilities, setup-phase, container
---

## Distinguish Privileged Setup Phases From Privilege Escalation Vulnerabilities

Sandbox and container runtimes require elevated privileges during setup (creating chroots, cgroups, namespaces, mounting filesystems) and drop privileges before executing the sandboxed process. Flagging the privileged setup phase as a "privilege escalation vulnerability" is a false positive — the setup IS the privileged operation. The real audit targets are: (1) are privileges dropped at the earliest possible point? (2) is the drop verified? (3) can any code path skip the drop?

**Incorrect (flagging correct privilege management as a vulnerability):**

```rust
// AUDIT: "HIGH — Privilege escalation: jailer runs as root during chroot setup"
// This is a FALSE POSITIVE — chroot requires root.

fn setup_jail(&self) -> Result<()> {
    // These operations REQUIRE root/CAP_SYS_ADMIN:
    fs::create_dir_all(&self.chroot_dir)?;    // Create jail directory
    mount(None, &self.chroot_dir, ...)?;       // Mount filesystems
    pivot_root(&self.chroot_dir, &old_root)?;  // Change root filesystem
    setup_cgroups(&self.cgroup_config)?;        // Create cgroup hierarchy

    // Privileges dropped at exec — this is the CORRECT pattern
    Command::new(&self.exec_path)
        .uid(self.uid)   // Drop to unprivileged user
        .gid(self.gid)   // Drop to unprivileged group
        .exec();         // Privileges dropped atomically at kernel level
}
// Auditor flagged: "privileges not dropped until exec() — large attack window"
// Reality: every line before exec() NEEDS privileges. There is no earlier point.
```

**Correct (auditing privilege management for actual flaws):**

```rust
// REAL privilege management vulnerabilities to look for:

// 1. Privileges never dropped — process stays root after setup
fn bad_setup() {
    create_chroot();
    // BUG: forgot to drop privileges, sandboxed process runs as root
    run_sandboxed_process();  // Still root!
}

// 2. Incomplete privilege drop — supplementary groups retained
fn incomplete_drop() {
    setuid(unprivileged_uid);
    setgid(unprivileged_gid);
    // BUG: didn't call setgroups([]) — supplementary groups (e.g., 'docker') retained
    // Attacker can use retained group membership to escape
}

// 3. Drop not verified — setuid failure silently ignored
fn unverified_drop() {
    let _ = setuid(unprivileged_uid);  // Ignoring return value!
    // If setuid fails (e.g., RLIMIT_NPROC reached), process stays root
    // MUST check: assert!(getuid() == unprivileged_uid)
}

// 4. Code path that skips the drop — error handling runs privileged
fn skippable_drop() -> Result<()> {
    setup_chroot()?;
    if config.debug_mode {
        run_diagnostics();  // Runs as root if reached before exec()
    }
    drop_privileges_and_exec()?;
    Ok(())
}
```

When auditing privilege management: verify privileges are dropped (not just requested), verify the drop is checked (return value of setuid/setgid), verify supplementary groups are cleared, and verify no error/debug path bypasses the drop. The setup phase running as root is expected and correct — audit the boundary between setup and execution.
