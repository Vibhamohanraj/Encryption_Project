/**
 * @file common.h
 * @brief Common definitions, error codes, and cryptographic constants for SecureFile.
 */

#ifndef SECFILE_COMMON_H
#define SECFILE_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Cryptographic Constants */
#define SECFILE_MAGIC "SECFIL01"
#define SECFILE_MAGIC_LEN 8
#define SECFILE_VERSION 1

#define SECFILE_KEY_SIZE 32      /* AES-256 key: 256 bits = 32 bytes */
#define SECFILE_SALT_SIZE 16     /* Argon2id salt: 128 bits = 16 bytes */
#define SECFILE_NONCE_SIZE 12    /* AES-GCM IV/nonce: 96 bits = 12 bytes */
#define SECFILE_TAG_SIZE 16      /* AES-GCM auth tag: 128 bits = 16 bytes */

/* Argon2id KDF Default Parameters (suitable for Windows desktop interactive use) */
/* 64 MiB RAM, 3 iterations */
#define SECFILE_ARGON2_OPSLIMIT 3ULL
#define SECFILE_ARGON2_MEMLIMIT (64ULL * 1024ULL * 1024ULL)

/* Sanity bounds for KDF parameters to reject malformed/hostile headers */
#define SECFILE_ARGON2_OPSLIMIT_MIN 1ULL
#define SECFILE_ARGON2_OPSLIMIT_MAX 100ULL
#define SECFILE_ARGON2_MEMLIMIT_MIN (8ULL * 1024ULL * 1024ULL)    /* 8 MiB */
#define SECFILE_ARGON2_MEMLIMIT_MAX (1024ULL * 1024ULL * 1024ULL) /* 1 GiB */

/* Buffer sizes */
#define SECFILE_CHUNK_SIZE (64 * 1024) /* 64 KiB I/O buffer */
#define SECFILE_MAX_PATH 1024
#define SECFILE_MAX_PASSWORD_LEN 256

/* Error Codes */
typedef enum {
    SECFILE_OK = 0,
    SECFILE_ERR_INVALID_PARAM = -1,
    SECFILE_ERR_FILE_NOT_FOUND = -2,
    SECFILE_ERR_FILE_EXISTS = -3,
    SECFILE_ERR_SAME_FILE = -4,
    SECFILE_ERR_FILE_IO = -5,
    SECFILE_ERR_FORMAT_INVALID = -6,
    SECFILE_ERR_VERSION_UNSUPPORTED = -7,
    SECFILE_ERR_KDF_FAILED = -8,
    SECFILE_ERR_CRYPTO_INIT = -9,
    SECFILE_ERR_CRYPTO_OP = -10,
    SECFILE_ERR_AUTH_FAILED = -11,
    SECFILE_ERR_MEMORY = -12,
    SECFILE_ERR_PASSWORD_MISMATCH = -13,
    SECFILE_ERR_CANCELLED = -14
} secfile_error_t;

/**
 * @brief Get human-readable description of error code.
 */
const char *secfile_strerror(secfile_error_t err);

#endif /* SECFILE_COMMON_H */
