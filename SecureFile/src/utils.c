/**
 * @file utils.c
 * @brief Utility and error-string reporting routines.
 */

#include "common.h"

const char *secfile_strerror(secfile_error_t err) {
    switch (err) {
        case SECFILE_OK:
            return "Operation succeeded";
        case SECFILE_ERR_INVALID_PARAM:
            return "Invalid argument or parameter";
        case SECFILE_ERR_FILE_NOT_FOUND:
            return "Input file not found";
        case SECFILE_ERR_FILE_EXISTS:
            return "Output file already exists (use overwrite option to replace)";
        case SECFILE_ERR_SAME_FILE:
            return "Input and output refer to the exact same file";
        case SECFILE_ERR_FILE_IO:
            return "File read or write error";
        case SECFILE_ERR_FORMAT_INVALID:
            return "Malformed or corrupt file (invalid header format)";
        case SECFILE_ERR_VERSION_UNSUPPORTED:
            return "Unsupported file format version";
        case SECFILE_ERR_KDF_FAILED:
            return "Key derivation failure (Argon2id resource exhaustion)";
        case SECFILE_ERR_CRYPTO_INIT:
            return "Cryptographic subsystem initialization failure";
        case SECFILE_ERR_CRYPTO_OP:
            return "Cryptographic operation failure";
        case SECFILE_ERR_AUTH_FAILED:
            return "Authentication verification failed (incorrect password or corrupted/tampered file)";
        case SECFILE_ERR_MEMORY:
            return "Memory allocation failure";
        case SECFILE_ERR_PASSWORD_MISMATCH:
            return "Passwords do not match";
        case SECFILE_ERR_CANCELLED:
            return "Operation cancelled by user";
        default:
            return "Unknown error";
    }
}
