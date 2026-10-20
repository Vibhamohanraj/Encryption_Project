/**
 * @file kdf.h
 * @brief Password-based key derivation using libsodium Argon2id and secure wipe helpers.
 */

#ifndef SECFILE_KDF_H
#define SECFILE_KDF_H

#include "common.h"

/**
 * @brief Initialize cryptographic runtime dependencies (libsodium).
 * @return secfile_error_t SECFILE_OK on success.
 */
secfile_error_t secfile_crypto_subsystem_init(void);

/**
 * @brief Derive a 32-byte AES key from password and salt using Argon2id.
 *
 * @param password Plaintext password.
 * @param password_len Length of password in bytes.
 * @param salt 16-byte random salt.
 * @param opslimit Number of iterations.
 * @param memlimit Memory cost in bytes.
 * @param key_out Output buffer of SECFILE_KEY_SIZE (32 bytes).
 * @return secfile_error_t SECFILE_OK on success.
 */
secfile_error_t secfile_derive_key(
    const char *password,
    size_t password_len,
    const uint8_t *salt,
    uint64_t opslimit,
    uint64_t memlimit,
    uint8_t *key_out
);

/**
 * @brief Generate cryptographically secure random bytes.
 */
void secfile_random_bytes(uint8_t *buf, size_t len);

/**
 * @brief Safely zero-fill sensitive memory (passwords, keys).
 */
void secfile_memzero(void *ptr, size_t len);

#endif /* SECFILE_KDF_H */
