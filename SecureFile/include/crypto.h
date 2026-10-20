/**
 * @file crypto.h
 * @brief AES-256-GCM file encryption and authenticated decryption routines.
 */

#ifndef SECFILE_CRYPTO_H
#define SECFILE_CRYPTO_H

#include "common.h"

/**
 * @brief Encrypt a file using AES-256-GCM and Argon2id key derivation.
 *
 * @param input_path Path to the plaintext input file.
 * @param output_path Path to the encrypted output file.
 * @param password Password for key derivation.
 * @param overwrite If true, overwrite output if it exists; otherwise refuse.
 * @return secfile_error_t SECFILE_OK on success.
 */
secfile_error_t secfile_encrypt_file(
    const char *input_path,
    const char *output_path,
    const char *password,
    bool overwrite
);

/**
 * @brief Decrypt an encrypted file after verifying AES-256-GCM authentication.
 *
 * @param input_path Path to the encrypted input file.
 * @param output_path Path for the decrypted plaintext file.
 * @param password Password for key derivation.
 * @param overwrite If true, overwrite output if it exists; otherwise refuse.
 * @return secfile_error_t SECFILE_OK on success.
 */
secfile_error_t secfile_decrypt_file(
    const char *input_path,
    const char *output_path,
    const char *password,
    bool overwrite
);

#endif /* SECFILE_CRYPTO_H */
