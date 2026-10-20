/**
 * @file kdf.c
 * @brief Key derivation function and secure memory management implementation.
 */

#include "kdf.h"
#include <sodium.h>
#include <string.h>

secfile_error_t secfile_crypto_subsystem_init(void) {
    if (sodium_init() < 0) {
        return SECFILE_ERR_CRYPTO_INIT;
    }
    return SECFILE_OK;
}

secfile_error_t secfile_derive_key(
    const char *password,
    size_t password_len,
    const uint8_t *salt,
    uint64_t opslimit,
    uint64_t memlimit,
    uint8_t *key_out
) {
    if (!password || password_len == 0 || !salt || !key_out) {
        return SECFILE_ERR_INVALID_PARAM;
    }

    /* Initialize crypto subsystem if not yet initialized */
    if (secfile_crypto_subsystem_init() != SECFILE_OK) {
        return SECFILE_ERR_CRYPTO_INIT;
    }

    /* Derive key using Argon2id via libsodium */
    if (crypto_pwhash(
            key_out,
            SECFILE_KEY_SIZE,
            password,
            password_len,
            salt,
            opslimit,
            (size_t)memlimit,
            crypto_pwhash_ALG_ARGON2ID13
        ) != 0) {
        return SECFILE_ERR_KDF_FAILED;
    }

    return SECFILE_OK;
}

void secfile_random_bytes(uint8_t *buf, size_t len) {
    if (buf && len > 0) {
        randombytes_buf(buf, len);
    }
}

void secfile_memzero(void *ptr, size_t len) {
    if (ptr && len > 0) {
        sodium_memzero(ptr, len);
    }
}
