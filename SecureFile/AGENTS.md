# SecureFile — Agent & Developer Instructions

This document defines the mandatory rules, architectural principles, cryptographic constraints, and operational guidelines for AI agents and developers contributing to the **SecureFile** project.

---

## 1. Core Principles

- **Language & Standards**: The application must be implemented in C (targeting C99/C11 standards).
- **Platform Focus**: Target Windows compatibility first (supporting native Windows runtime and toolchains such as MinGW-w64 / MSVC).
- **Code Clarity**: Keep the implementation beginner-friendly, clean, well-commented, and modular.
- **Documentation**: Explain significant implementation decisions in plain English in code comments and documentation.
- **Strict Warnings**: Use strict compiler warnings (e.g., `-Wall -Wextra -Wpedantic` on GCC/Clang or `/W4` on MSVC) and immediately fix any warnings introduced by our code.
- **Preserve User Code**: Preserve existing user changes and do not modify unrelated files.
- **No Assumptions on Tests**: Do not claim tests passed unless they were actually executed and their results verified.

---

## 2. Cryptographic Rules & Standards

- **Never Invent Cryptography**: Never invent or roll your own cryptographic algorithm or mode.
- **Established Libraries**: Use an established, audited cryptographic library for all cryptographic operations.
- **Encryption Scheme**: Prefer **AES-256-GCM** for authenticated, confidential file encryption.
- **Key Derivation (KDF)**:
  - Prefer **Argon2id** for password-based key derivation when a maintained, compatible implementation is available.
  - If Argon2id is unavailable, **stop and document suitable alternatives** (e.g., PBKDF2 with high iterations or scrypt) instead of silently substituting a weaker design without user approval.
- **Random Number Generation**: Use a cryptographically secure random-number generator (CSPRNG, such as Windows `BCryptGenRandom` or OpenSSL `RAND_bytes`) for all salts, nonces, and initialization vectors.
- **Nonce Uniqueness**: Never reuse a nonce (IV) with the same AES-GCM key. Nonces must be generated uniquely per file encryption operation.
- **Password Security**: Never store passwords in plaintext in memory longer than necessary; zero-fill password buffers after derivation. Never write passwords to disk or logs.
- **Authentication Verification**: Verify authentication (the AES-GCM authentication tag) before accepting, writing, or treating decrypted output as valid.

---

## 3. File Safety & Integrity

- **Never Overwrite Input**: Never overwrite the input source file under any circumstances.
- **Safe Output Defaults**: Refuse to overwrite existing output files by default. Require an explicit user opt-in flag (e.g., `--force` or `-f`) if overwriting is requested.
- **Preserve Original Files**: Never delete the original file after encryption or decryption.
- **Robust Error Handling**: Handle all file I/O errors, invalid inputs, malformed encrypted files, header corruptions, and memory allocation failures gracefully with descriptive error messages.
- **Non-Destructive Operations**: Never run destructive commands against user data.

---

## 4. Engineering & Repository Best Practices

- **Clean Source Control**: Do not place secrets, generated binaries, object files, or sensitive sample data in Git.
- **Contained Workflows**: Keep builds, test harnesses, and generated artifacts within the project directory where practical.
- **No Global System Modifications**: Do not install software globally, alter system settings, or modify unrelated directories without explicit user approval.
- **Step-by-Step Evolution**: Do not rush to implement encryption before verifying the environment, toolchains, and dependency compatibility.
