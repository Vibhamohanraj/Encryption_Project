# SecureFile Security Architecture & Threat Model

This document outlines the cryptographic design, threat model, memory hygiene practices, and filesystem safety mechanisms implemented in **SecureFile**.

---

## 1. Cryptographic Primitives & Design

| Function | Primitive | Standard / Implementation |
| :--- | :--- | :--- |
| **Authenticated Cipher** | **AES-256-GCM** | NIST SP 800-38D via OpenSSL 3.x EVP |
| **Key Derivation (KDF)** | **Argon2id** | RFC 9106 via libsodium `crypto_pwhash()` |
| **CSPRNG** | **libsodium CSPRNG** | `randombytes_buf()` (OS-backed entropy) |
| **Key Size** | 256 bits (32 bytes) | High security margin against brute force |
| **Tag Size** | 128 bits (16 bytes) | Negligible forgery probability ($2^{-128}$) |
| **Salt Size** | 128 bits (16 bytes) | Prevents rainbow tables and cross-file collisions |
| **Nonce / IV Size** | 96 bits (12 bytes) | Standard recommended length for AES-GCM |

---

## 2. Key Derivation & Resource Bounds

Human-chosen passwords do not have sufficient entropy to directly serve as 256-bit cryptographic keys. SecureFile uses **Argon2id**, the winner of the Password Hashing Competition (PHC), which provides hybrid resistance against both side-channel attacks and GPU/ASIC hardware acceleration.

### Default Desktop Profile
- **Iterations (`opslimit`)**: `3`
- **Memory (`memlimit`)**: `64 MiB` (`67,108,864` bytes)
- **Algorithm**: `crypto_pwhash_ALG_ARGON2ID13`

### Resource Exhaustion Prevention (DoS Guard)
Before allocating memory or performing key derivation on an untrusted encrypted file, SecureFile strictly validates the header's KDF limits against sanity boundaries:
- `1 <= opslimit <= 100`
- `8 MiB <= memlimit <= 1024 MiB`

Malformed or adversarial files requesting extreme memory or iteration counts are rejected immediately, protecting the host system from memory exhaustion or CPU denial-of-service.

---

## 3. Cryptographic Binding (AAD)

The 60-byte binary header is supplied as **Additional Authenticated Data (AAD)** to `EVP_EncryptUpdate` / `EVP_DecryptUpdate`. This cryptographically binds the metadata (version, KDF parameters, salt, and nonce) to the ciphertext and the authentication tag. An attacker cannot tamper with the header parameters without invalidating the 16-byte authentication tag.

---

## 4. Nonce Uniqueness & CSPRNG (Probabilistic Guarantee)

AES-GCM catastrophic failure occurs if the same key and nonce pair is used to encrypt two different plaintexts. In SecureFile:
- Every file encryption operation generates a fresh 16-byte random salt and 12-byte random nonce via libsodium's CSPRNG (`randombytes_buf()`).
- **Probabilistic Guarantee**: Under NIST SP 800-38D, a 96-bit random nonce provides a probabilistic collision-resistance guarantee: the probability of a collision under the exact same key across $M$ encryptions is approximately $M^2 / 2^{97}$.
- **Defense in Depth**: Because a fresh 128-bit random salt is generated for every file encryption, even identical passwords derive distinct 256-bit AES keys with overwhelming probability ($1 - 2^{-128}$). Therefore, nonce reuse across identical keys is statistically negligible.

---

## 5. Memory Hygiene & Password Protection

- Passwords are never written to disk, swap, logs, or command-line arguments.
- Password entry on Windows uses `_getch()` without echoing characters to the terminal.
- Sensitive buffers (plaintext passwords, confirmation buffers, derived AES keys, and temporary decryption chunk buffers) are zeroed using `sodium_memzero()` immediately after derivation or upon authentication failure.

---

## 6. Filesystem Safety & Atomic Publication

### 1. Protection Against Input Overwriting
SecureFile performs deep same-file checks using Windows `GetFileInformationByHandle`. It compares the **volume serial number** and **64-bit file index** of the source and destination paths. Even if paths use relative notation, symlinks, or different casings, SecureFile detects when both paths point to the same physical file and aborts before opening any write streams.

### 2. Output Protection by Default
By default, SecureFile refuses to overwrite existing files. Users must pass `--overwrite` or explicitly answer `y` to replace existing output.

### 3. Safe Exclusive Temporary Decryption & Publication
In stream-based authenticated decryption, the authenticity tag can only be fully verified after the final byte of ciphertext has been processed:
1. SecureFile creates a temporary file in the destination directory using `CreateFileW` with **`CREATE_NEW`** and **exclusive sharing mode `0`**. This ensures the file is created uniquely without race conditions and prevents symlink or junction hijacking.
2. If `EVP_DecryptFinal_ex()` fails (wrong password, corrupted file, or modified ciphertext/tag), SecureFile closes and **deletes the temporary file immediately**. Decrypted plaintext buffers are zeroed before being freed.
3. Plaintext is only published to the final destination path upon successful authentication.
4. Keeping the temporary file in the same directory allows Windows `MoveFileExW` to perform an atomic metadata rename on NTFS/ReFS filesystems on the same volume. Cross-volume moves fall back safely to copy-and-delete.

---

## 7. Crucial Security Notice for Users

> **WARNING**: SecureFile uses authenticated cryptography with no backdoor, master key, or escrow mechanism. If a password is lost or forgotten, the encrypted file **CANNOT** be recovered by any means.
