# Build Integrity & Provenance Defense (the counterweight)

ATT&CK (defends against): T1195 / T1195.001/.002 (Supply Chain Compromise) · CWE-347 (Improper
Verification of Cryptographic Signature), CWE-494 (Download of Code Without Integrity Check),
CWE-1357 (Reliance on Insufficiently Trustworthy Component). Frameworks: SLSA, in-toto, Sigstore,
NIST SSDF, OWASP CICD-SEC.

## Theory / Mechanism

Every offensive technique in this skill produces a **build whose output does not match a trustworthy
record of how it was built**. Provenance + signing turns that into a detectable, *enforceable* gap:

- **SLSA (Supply-chain Levels for Software Artifacts).** v1.0 (Apr 2023) defines a Build track,
  Levels 0-3. L1 = provenance exists; L2 = signed provenance from a hosted build service; L3 =
  non-falsifiable provenance from an isolated, ephemeral builder the build script can't tamper with.
- **in-toto attestation + DSSE.** Provenance is an in-toto predicate (builder identity, build
  instructions, parameters, env, dependency digests) wrapped in a DSSE envelope and signed. This is
  what `slsa-github-generator` emits and what `slsa-verifier` checks.
- **Sigstore (Fulcio + Rekor) keyless signing.** `cosign` signs with a short-lived cert tied to an
  **OIDC identity** (the workflow's own identity) issued by Fulcio; the event is logged in the
  append-only transparency log **Rekor**. No long-lived signing key to steal — the exact key-theft
  vector from action/runner compromise disappears.
- **Enforcement gate.** Attestations are worthless unless something *verifies before promote*:
  `slsa-verifier` / `cosign verify-attestation` in the release job, plus admission control
  (Kyverno / OPA-Gatekeeper / Sigstore policy-controller) so K8s only runs signed images matching the
  expected builder, repo, and ref.

Critical anti-pattern this defeats: a poisoned pipeline (PPE) or compromised action *can* edit a build
script, but with an L3 builder-provided generator the script **cannot lie about its own inputs**, and
a verifier rejects any artifact whose provenance identity/repo/ref doesn't match policy.

## Working defensive implementation (complete)

### A. Generate SLSA L3 provenance + keyless cosign signing in CI
```yaml
# .github/workflows/release.yml
permissions: { id-token: write, contents: write, packages: write, attestations: write }
jobs:
  build:
    runs-on: ubuntu-latest
    outputs: { digest: ${{ steps.push.outputs.digest }} }
    steps:
      - uses: actions/checkout@<40-char-sha>          # SHA-pin everything
      - id: push
        run: |
          IMG=ghcr.io/${{ github.repository }}:${{ github.sha }}
          docker build -t "$IMG" . && docker push "$IMG"
          echo "digest=$(docker buildx imagetools inspect "$IMG" --format '{{.Manifest.Digest}}')" >>"$GITHUB_OUTPUT"
      # GitHub-native build attestation (provenance), keyless via the workflow OIDC identity:
      - uses: actions/attest-build-provenance@<40-char-sha>
        with: { subject-name: ghcr.io/${{ github.repository }}, subject-digest: ${{ steps.push.outputs.digest }}, push-to-registry: true }
  # SLSA L3 provenance from the trusted reusable generator (script can't forge it):
  provenance:
    needs: build
    permissions: { id-token: write, contents: write, packages: write, actions: read }
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@<sha>
    with: { image: ghcr.io/${{ github.repository }}, digest: ${{ needs.build.outputs.digest }} }
```

### B. Verify BEFORE promote (the gate) — used by scripts/provenance_verify.sh
```bash
# Verify SLSA provenance: artifact must come from THIS repo via the trusted builder
slsa-verifier verify-image "ghcr.io/org/app@sha256:DIGEST" \
  --source-uri github.com/org/app \
  --builder-id 'https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0'

# Verify cosign keyless signature: identity must match the expected workflow + issuer
cosign verify-attestation "ghcr.io/org/app@sha256:DIGEST" --type slsaprovenance \
  --certificate-identity-regexp '^https://github.com/org/app/\.github/workflows/release\.yml@refs/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

### C. Admission control — only run verified images (Kyverno)
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata: { name: require-slsa-provenance }
spec:
  validationFailureAction: Enforce
  rules:
    - name: verify-ghcr
      match: { any: [ { resources: { kinds: [Pod] } } ] }
      verifyImages:
        - imageReferences: [ "ghcr.io/org/*" ]
          attestations:
            - type: https://slsa.dev/provenance/v1
              attestors:
                - entries:
                    - keyless:
                        subject: "https://github.com/org/app/.github/workflows/release.yml@*"
                        issuer: "https://token.actions.githubusercontent.com"
                        rekor: { url: "https://rekor.sigstore.dev" }
              conditions:
                - all:
                    - key: "{{ buildDefinition.externalParameters.workflow.repository }}"
                      operator: Equals
                      value: "https://github.com/org/app"
```

### D. Defensive recon — SBOM + pin audit + provenance check in one pass
```bash
syft packages dir:./repo -o cyclonedx-json > sbom.json    # inventory for confusion/typosquat triage
python3 scripts/malicious_action_scanner.py --path ./repo --check-pins   # all actions SHA-pinned?
bash scripts/provenance_verify.sh --image ghcr.io/org/app:tag --repo org/app
```

## Modern 2024-2026 status (verified)

- **GitHub-native build attestations** (`actions/attest-build-provenance`, GA 2024) make SLSA L2
  achievable "in an afternoon"; `slsa-github-generator` reusable workflows reach L3 on GHA.
- **`cosign` keyless + Rekor** is the de facto signing path; container registries (GHCR, Google
  Artifact Registry) store attestations alongside artifacts. Verification with `slsa-verifier` /
  `cosign verify-attestation` is the enforceable gate.
- **Kyverno / Sigstore policy-controller / OPA-Gatekeeper** provide admission-time verification;
  NIST SSDF maps SLSA as the concrete technical control for software-integrity practices.
- Lesson from tj-actions/Shai-Hulud: SHA-pinning + provenance verification + secret rotation +
  egress allowlisting are the controls that would have contained each 2025 incident.

## Detection (verification = detection, here)

- **Provenance mismatch** (builder id, source repo, ref, or digest != policy) at the verify gate or
  admission controller = blocked deploy and an alert — the direct detection of a poisoned/forged build.
- **Sigma — unsigned/unverified image admitted (control failure):**
```yaml
title: Image Admitted Without Valid SLSA Provenance
id: e8b0d2c1-5a44-4b9f-9c10-cicddef0001
logsource: { product: kubernetes, service: kyverno }
detection:
  sel: { policy: 'require-slsa-provenance', result: 'fail' }
  condition: sel
level: high
```
- **IOCs of a control gap:** images with no Rekor entry; provenance whose `externalParameters`
  repo/ref differs from the deployed source; cosign cert identity not matching the release workflow;
  actions not SHA-pinned in the workflow that built a release.

## OPSEC (defender's note)

- These are *defensive* controls, but red teams should map them during recon: a target enforcing
  cosign keyless + `slsa-verifier` + Kyverno admission + SHA-pinned actions + egress allowlist defeats
  the mutable-tag, cache-poisoning, and forged-build vectors — pivot instead to identity/runner
  compromise (still in scope) or pre-signing PPE (compromise *before* the signed step).
- Demonstrating a provenance bypass (e.g. forging inputs against a non-L3 generator, or compromising
  the signing step itself) is a high-value finding for the report.

## References

- SLSA spec v1.0 (slsa.dev); in-toto attestation framework; DSSE.
- Sigstore (Fulcio, Rekor), cosign docs; `slsa-framework/slsa-github-generator`; `slsa-verifier`.
- GitHub Docs, "Using artifact attestations" (`actions/attest-build-provenance`).
- Kyverno `verifyImages` / Sigstore policy-controller; OPA-Gatekeeper.
- Legit Security, "Deep Dive Into SLSA Provenance and Software Attestation"; JFrog, "What is SLSA."
- NIST SSDF (SP 800-218) mapping to SLSA controls.
