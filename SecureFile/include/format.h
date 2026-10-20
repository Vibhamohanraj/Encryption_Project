/**
 * @file format.h
 * @brief Binary header format definitions and serialization routines.
 */

#ifndef SECFILE_FORMAT_H
#define SECFILE_FORMAT_H

#include "common.h"

#define SECFILE_HEADER_SIZE 60

/**
 * @brief Parsed file header structure.
 */
typedef struct {
    uint8_t magic[SECFILE_MAGIC_LEN];
    uint32_t version;
    uint32_t kdf_algorithm;
    uint64_t opslimit;
    uint64_t memlimit;
    uint8_t salt[SECFILE_SALT_SIZE];
    uint8_t nonce[SECFILE_NONCE_SIZE];
} secfile_header_t;

/**
 * @brief Initialize a header structure with default parameters and random salt/nonce.
 *
 * @param header Pointer to header to populate.
 * @return secfile_error_t SECFILE_OK on success.
 */
secfile_error_t secfile_header_init(secfile_header_t *header);

/**
 * @brief Serialize header struct into a binary buffer (Little-Endian).
 *
 * @param header Source header.
 * @param buffer Output buffer of at least SECFILE_HEADER_SIZE bytes.
 * @param buf_len Size of buffer.
 * @return secfile_error_t SECFILE_OK on success.
 */
secfile_error_t secfile_header_serialize(const secfile_header_t *header, uint8_t *buffer, size_t buf_len);

/**
 * @brief Deserialize and validate a binary buffer into a header struct.
 *
 * @param buffer Input binary buffer of at least SECFILE_HEADER_SIZE bytes.
 * @param buf_len Size of buffer.
 * @param header Destination header.
 * @return secfile_error_t SECFILE_OK on success, or validation error.
 */
secfile_error_t secfile_header_deserialize(const uint8_t *buffer, size_t buf_len, secfile_header_t *header);

#endif /* SECFILE_FORMAT_H */
