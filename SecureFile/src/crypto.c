/**
 * @file crypto.c
 * @brief AES-256-GCM chunked file encryption and authenticated decryption.
 */

#include "crypto.h"
#include "format.h"
#include "kdf.h"
#include "file_handler.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

secfile_error_t secfile_encrypt_file(
    const char *input_path,
    const char *output_path,
    const char *password,
    bool overwrite
) {
    if (!input_path || !output_path || !password) {
        return SECFILE_ERR_INVALID_PARAM;
    }

    if (!secfile_file_exists(input_path)) {
        return SECFILE_ERR_FILE_NOT_FOUND;
    }

    if (!overwrite && secfile_file_exists(output_path)) {
        return SECFILE_ERR_FILE_EXISTS;
    }

    if (secfile_is_same_file(input_path, output_path)) {
        return SECFILE_ERR_SAME_FILE;
    }

    /* Initialize file header with new random salt and nonce */
    secfile_header_t header;
    secfile_error_t err = secfile_header_init(&header);
    if (err != SECFILE_OK) {
        return err;
    }

    /* Derive 32-byte encryption key from password and salt */
    uint8_t key[SECFILE_KEY_SIZE];
    err = secfile_derive_key(
        password,
        strlen(password),
        header.salt,
        header.opslimit,
        header.memlimit,
        key
    );
    if (err != SECFILE_OK) {
        secfile_memzero(key, sizeof(key));
        return err;
    }

    /* Serialize header to binary buffer */
    uint8_t header_buf[SECFILE_HEADER_SIZE];
    err = secfile_header_serialize(&header, header_buf, sizeof(header_buf));
    if (err != SECFILE_OK) {
        secfile_memzero(key, sizeof(key));
        return err;
    }

    /* Exclusively create and open unique temporary output file */
    char temp_path[SECFILE_MAX_PATH] = {0};
    FILE *f_out = NULL;
    err = secfile_open_unique_temp_file(output_path, temp_path, sizeof(temp_path), &f_out);
    if (err != SECFILE_OK) {
        secfile_memzero(key, sizeof(key));
        return err;
    }

    FILE *f_in = secfile_open_read(input_path);
    if (!f_in) {
        fclose(f_out);
        secfile_remove_file(temp_path);
        secfile_memzero(key, sizeof(key));
        return SECFILE_ERR_FILE_IO;
    }

    /* Write serialized header to output file */
    if (fwrite(header_buf, 1, SECFILE_HEADER_SIZE, f_out) != SECFILE_HEADER_SIZE) {
        fclose(f_in);
        fclose(f_out);
        secfile_remove_file(temp_path);
        secfile_memzero(key, sizeof(key));
        return SECFILE_ERR_FILE_IO;
    }

    /* Initialize OpenSSL AES-256-GCM context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(f_in);
        fclose(f_out);
        secfile_remove_file(temp_path);
        secfile_memzero(key, sizeof(key));
        return SECFILE_ERR_CRYPTO_INIT;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, SECFILE_NONCE_SIZE, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, header.nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(f_in);
        fclose(f_out);
        secfile_remove_file(temp_path);
        secfile_memzero(key, sizeof(key));
        return SECFILE_ERR_CRYPTO_INIT;
    }

    /* Key buffer is no longer needed; wipe immediately */
    secfile_memzero(key, sizeof(key));

    /* Authenticate header metadata as Additional Authenticated Data (AAD) */
    int out_len = 0;
    if (EVP_EncryptUpdate(ctx, NULL, &out_len, header_buf, SECFILE_HEADER_SIZE) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(f_in);
        fclose(f_out);
        secfile_remove_file(temp_path);
        return SECFILE_ERR_CRYPTO_OP;
    }

    /* Allocate streaming I/O buffers */
    uint8_t *in_chunk = malloc(SECFILE_CHUNK_SIZE);
    uint8_t *out_chunk = malloc(SECFILE_CHUNK_SIZE + 16);
    if (!in_chunk || !out_chunk) {
        free(in_chunk);
        free(out_chunk);
        EVP_CIPHER_CTX_free(ctx);
        fclose(f_in);
        fclose(f_out);
        secfile_remove_file(temp_path);
        return SECFILE_ERR_MEMORY;
    }

    /* Stream and encrypt plaintext chunks */
    size_t bytes_read = 0;
    while ((bytes_read = fread(in_chunk, 1, SECFILE_CHUNK_SIZE, f_in)) > 0) {
        if (EVP_EncryptUpdate(ctx, out_chunk, &out_len, in_chunk, (int)bytes_read) != 1) {
            secfile_memzero(in_chunk, SECFILE_CHUNK_SIZE);
            free(in_chunk);
            free(out_chunk);
            EVP_CIPHER_CTX_free(ctx);
            fclose(f_in);
            fclose(f_out);
            secfile_remove_file(temp_path);
            return SECFILE_ERR_CRYPTO_OP;
        }

        if (out_len > 0) {
            if (fwrite(out_chunk, 1, (size_t)out_len, f_out) != (size_t)out_len) {
                secfile_memzero(in_chunk, SECFILE_CHUNK_SIZE);
                free(in_chunk);
                free(out_chunk);
                EVP_CIPHER_CTX_free(ctx);
                fclose(f_in);
                fclose(f_out);
                secfile_remove_file(temp_path);
                return SECFILE_ERR_FILE_IO;
            }
        }
    }

    secfile_memzero(in_chunk, SECFILE_CHUNK_SIZE);
    free(in_chunk);

    if (ferror(f_in)) {
        free(out_chunk);
        EVP_CIPHER_CTX_free(ctx);
        fclose(f_in);
        fclose(f_out);
        secfile_remove_file(temp_path);
        return SECFILE_ERR_FILE_IO;
    }

    fclose(f_in);

    /* Finalize encryption */
    if (EVP_EncryptFinal_ex(ctx, out_chunk, &out_len) != 1) {
        free(out_chunk);
        EVP_CIPHER_CTX_free(ctx);
        fclose(f_out);
        secfile_remove_file(temp_path);
        return SECFILE_ERR_CRYPTO_OP;
    }

    if (out_len > 0) {
        if (fwrite(out_chunk, 1, (size_t)out_len, f_out) != (size_t)out_len) {
            free(out_chunk);
            EVP_CIPHER_CTX_free(ctx);
            fclose(f_out);
            secfile_remove_file(temp_path);
            return SECFILE_ERR_FILE_IO;
        }
    }
    free(out_chunk);

    /* Retrieve 16-byte GCM authentication tag */
    uint8_t tag[SECFILE_TAG_SIZE];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, SECFILE_TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(f_out);
        secfile_remove_file(temp_path);
        return SECFILE_ERR_CRYPTO_OP;
    }
    EVP_CIPHER_CTX_free(ctx);

    /* Append tag to the end of the encrypted file */
    if (fwrite(tag, 1, SECFILE_TAG_SIZE, f_out) != SECFILE_TAG_SIZE) {
        fclose(f_out);
        secfile_remove_file(temp_path);
        return SECFILE_ERR_FILE_IO;
    }

    /* Verify buffered write flushes and close without error */
    if (fflush(f_out) != 0 || ferror(f_out)) {
        fclose(f_out);
        secfile_remove_file(temp_path);
        return SECFILE_ERR_FILE_IO;
    }

    if (fclose(f_out) != 0) {
        secfile_remove_file(temp_path);
        return SECFILE_ERR_FILE_IO;
    }

    /* Publish encrypted file to destination */
    err = secfile_publish_file(temp_path, output_path, overwrite);
    if (err != SECFILE_OK) {
        secfile_remove_file(temp_path);
        return err;
    }

    return SECFILE_OK;
}

secfile_error_t secfile_decrypt_file(
    const char *input_path,
    const char *output_path,
    const char *password,
    bool overwrite
) {
    if (!input_path || !output_path || !password) {
        return SECFILE_ERR_INVALID_PARAM;
    }

    if (!secfile_file_exists(input_path)) {
        return SECFILE_ERR_FILE_NOT_FOUND;
    }

    if (!overwrite && secfile_file_exists(output_path)) {
        return SECFILE_ERR_FILE_EXISTS;
    }

    if (secfile_is_same_file(input_path, output_path)) {
        return SECFILE_ERR_SAME_FILE;
    }

    /* Check file size: must at least contain header + auth tag */
    uint64_t file_size = 0;
    secfile_error_t err = secfile_get_file_size(input_path, &file_size);
    if (err != SECFILE_OK) {
        return err;
    }

    if (file_size < (SECFILE_HEADER_SIZE + SECFILE_TAG_SIZE)) {
        return SECFILE_ERR_FORMAT_INVALID;
    }

    uint64_t ciphertext_len = file_size - SECFILE_HEADER_SIZE - SECFILE_TAG_SIZE;

    FILE *f_in = secfile_open_read(input_path);
    if (!f_in) {
        return SECFILE_ERR_FILE_IO;
    }

    /* Read header */
    uint8_t header_buf[SECFILE_HEADER_SIZE];
    if (fread(header_buf, 1, SECFILE_HEADER_SIZE, f_in) != SECFILE_HEADER_SIZE) {
        fclose(f_in);
        return SECFILE_ERR_FILE_IO;
    }

    /* Deserialize and validate header */
    secfile_header_t header;
    err = secfile_header_deserialize(header_buf, SECFILE_HEADER_SIZE, &header);
    if (err != SECFILE_OK) {
        fclose(f_in);
        return err;
    }

    /* Read authentication tag from the end of the file using 64-bit seek */
    int64_t tag_offset = (int64_t)(SECFILE_HEADER_SIZE + ciphertext_len);
    if (_fseeki64(f_in, tag_offset, SEEK_SET) != 0) {
        fclose(f_in);
        return SECFILE_ERR_FILE_IO;
    }

    uint8_t expected_tag[SECFILE_TAG_SIZE];
    if (fread(expected_tag, 1, SECFILE_TAG_SIZE, f_in) != SECFILE_TAG_SIZE) {
        fclose(f_in);
        return SECFILE_ERR_FILE_IO;
    }

    /* Rewind to start of ciphertext using 64-bit seek */
    if (_fseeki64(f_in, SECFILE_HEADER_SIZE, SEEK_SET) != 0) {
        fclose(f_in);
        return SECFILE_ERR_FILE_IO;
    }

    /* Derive 32-byte decryption key using header parameters */
    uint8_t key[SECFILE_KEY_SIZE];
    err = secfile_derive_key(
        password,
        strlen(password),
        header.salt,
        header.opslimit,
        header.memlimit,
        key
    );
    if (err != SECFILE_OK) {
        fclose(f_in);
        secfile_memzero(key, sizeof(key));
        return err;
    }

    /* Exclusively create and open unique temporary output file */
    char temp_path[SECFILE_MAX_PATH] = {0};
    FILE *f_out = NULL;
    err = secfile_open_unique_temp_file(output_path, temp_path, sizeof(temp_path), &f_out);
    if (err != SECFILE_OK) {
        fclose(f_in);
        secfile_memzero(key, sizeof(key));
        return err;
    }

    /* Initialize OpenSSL AES-256-GCM context for decryption */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(f_in);
        fclose(f_out);
        secfile_remove_file(temp_path);
        secfile_memzero(key, sizeof(key));
        return SECFILE_ERR_CRYPTO_INIT;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, SECFILE_NONCE_SIZE, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, header.nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(f_in);
        fclose(f_out);
        secfile_remove_file(temp_path);
        secfile_memzero(key, sizeof(key));
        return SECFILE_ERR_CRYPTO_INIT;
    }

    /* Wipe key immediately */
    secfile_memzero(key, sizeof(key));

    /* Authenticate header as AAD */
    int out_len = 0;
    if (EVP_DecryptUpdate(ctx, NULL, &out_len, header_buf, SECFILE_HEADER_SIZE) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(f_in);
        fclose(f_out);
        secfile_remove_file(temp_path);
        return SECFILE_ERR_CRYPTO_OP;
    }

    /* Allocate streaming buffers */
    uint8_t *in_chunk = malloc(SECFILE_CHUNK_SIZE);
    uint8_t *out_chunk = malloc(SECFILE_CHUNK_SIZE + 16);
    if (!in_chunk || !out_chunk) {
        free(in_chunk);
        free(out_chunk);
        EVP_CIPHER_CTX_free(ctx);
        fclose(f_in);
        fclose(f_out);
        secfile_remove_file(temp_path);
        return SECFILE_ERR_MEMORY;
    }

    /* Stream and decrypt ciphertext chunks */
    uint64_t remaining = ciphertext_len;
    while (remaining > 0) {
        size_t to_read = (remaining > SECFILE_CHUNK_SIZE) ? SECFILE_CHUNK_SIZE : (size_t)remaining;
        size_t bytes_read = fread(in_chunk, 1, to_read, f_in);
        if (bytes_read == 0) {
            break;
        }

        if (EVP_DecryptUpdate(ctx, out_chunk, &out_len, in_chunk, (int)bytes_read) != 1) {
            secfile_memzero(in_chunk, SECFILE_CHUNK_SIZE);
            secfile_memzero(out_chunk, SECFILE_CHUNK_SIZE + 16);
            free(in_chunk);
            free(out_chunk);
            EVP_CIPHER_CTX_free(ctx);
            fclose(f_in);
            fclose(f_out);
            secfile_remove_file(temp_path);
            return SECFILE_ERR_CRYPTO_OP;
        }

        if (out_len > 0) {
            if (fwrite(out_chunk, 1, (size_t)out_len, f_out) != (size_t)out_len) {
                secfile_memzero(in_chunk, SECFILE_CHUNK_SIZE);
                secfile_memzero(out_chunk, SECFILE_CHUNK_SIZE + 16);
                free(in_chunk);
                free(out_chunk);
                EVP_CIPHER_CTX_free(ctx);
                fclose(f_in);
                fclose(f_out);
                secfile_remove_file(temp_path);
                return SECFILE_ERR_FILE_IO;
            }
        }

        remaining -= bytes_read;
    }

    secfile_memzero(in_chunk, SECFILE_CHUNK_SIZE);
    free(in_chunk);

    if (remaining != 0 || ferror(f_in)) {
        secfile_memzero(out_chunk, SECFILE_CHUNK_SIZE + 16);
        free(out_chunk);
        EVP_CIPHER_CTX_free(ctx);
        fclose(f_in);
        fclose(f_out);
        secfile_remove_file(temp_path);
        return SECFILE_ERR_FILE_IO;
    }

    fclose(f_in);

    /* Set expected tag in GCM context */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, SECFILE_TAG_SIZE, expected_tag) != 1) {
        secfile_memzero(out_chunk, SECFILE_CHUNK_SIZE + 16);
        free(out_chunk);
        EVP_CIPHER_CTX_free(ctx);
        fclose(f_out);
        secfile_remove_file(temp_path);
        return SECFILE_ERR_CRYPTO_OP;
    }

    /* Finalize and verify GCM authentication tag */
    int final_ret = EVP_DecryptFinal_ex(ctx, out_chunk, &out_len);
    EVP_CIPHER_CTX_free(ctx);

    if (final_ret <= 0) {
        /*
         * CRITICAL: Authentication failed!
         * Either the password was wrong, or the file was modified/tampered.
         * Wipe buffer, close file, and delete temporary plaintext file immediately.
         * Never publish unauthenticated plaintext.
         */
        secfile_memzero(out_chunk, SECFILE_CHUNK_SIZE + 16);
        secfile_memzero(expected_tag, sizeof(expected_tag));
        free(out_chunk);
        fclose(f_out);
        secfile_remove_file(temp_path);
        return SECFILE_ERR_AUTH_FAILED;
    }

    if (out_len > 0) {
        if (fwrite(out_chunk, 1, (size_t)out_len, f_out) != (size_t)out_len) {
            secfile_memzero(out_chunk, SECFILE_CHUNK_SIZE + 16);
            free(out_chunk);
            fclose(f_out);
            secfile_remove_file(temp_path);
            return SECFILE_ERR_FILE_IO;
        }
    }
    secfile_memzero(out_chunk, SECFILE_CHUNK_SIZE + 16);
    secfile_memzero(expected_tag, sizeof(expected_tag));
    free(out_chunk);

    /* Verify buffered write flushes and close without error */
    if (fflush(f_out) != 0 || ferror(f_out)) {
        fclose(f_out);
        secfile_remove_file(temp_path);
        return SECFILE_ERR_FILE_IO;
    }

    if (fclose(f_out) != 0) {
        secfile_remove_file(temp_path);
        return SECFILE_ERR_FILE_IO;
    }

    /* Authentication succeeded! Publish decrypted file */
    err = secfile_publish_file(temp_path, output_path, overwrite);
    if (err != SECFILE_OK) {
        secfile_remove_file(temp_path);
        return err;
    }

    return SECFILE_OK;
}
