# Section Definitions

This file defines the vulnerability categories for security analysis. Rules are automatically assigned to sections based on their filename prefix.

---

## 1. Taint Analysis (taint)
**Impact:** CRITICAL
**Description:** Source-to-sink data flow tracing, filter evaluation methodology, and hybrid analysis strategies. The foundational technique for all vulnerability hunting.

## 2. Memory Safety (memory)
**Impact:** CRITICAL
**Description:** Buffer overflows, use-after-free, integer overflow, format strings, and uninitialized memory. The most dangerous vulnerability class enabling arbitrary code execution.

## 3. Injection Attacks (injection)
**Impact:** CRITICAL
**Description:** SQL injection, command injection, XSS, SSTI, path traversal, deserialization, and SSRF. Exploiting insufficient separation between data and control flow.

## 4. Authentication & Authorization (auth)
**Impact:** HIGH
**Description:** Authentication bypass, authorization flaws, session management weaknesses, JWT vulnerabilities, and IDOR. Failures in identity verification and access control.

## 5. Cryptographic Vulnerabilities (crypto)
**Impact:** HIGH
**Description:** Weak algorithms, improper key management, insufficient randomness, and side-channel attacks. Failures in confidentiality, integrity, and authenticity guarantees.

## 6. Concurrency & Race Conditions (concurrency)
**Impact:** HIGH
**Description:** TOCTOU vulnerabilities, atomicity violations, double-spend races, and lock ordering failures. Exploiting timing assumptions in concurrent systems.

## 7. Web & API Security (web)
**Impact:** MEDIUM-HIGH
**Description:** CORS misconfiguration, CSRF, API mass assignment, broken object-level authorization, and cache poisoning. Web-specific attack vectors beyond injection.

## 8. Supply Chain & Dependencies (supply)
**Impact:** MEDIUM
**Description:** Dependency confusion, known CVEs in dependencies, malicious model files, typosquatting, and build system compromise. Attacks through the software supply chain.
