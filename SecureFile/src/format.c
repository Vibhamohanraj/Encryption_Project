/**
 * @file format.c
 * @brief Binary header serialization and deserialization with strict validation.
 */

#include "format.h"
#include "kdf.h"
#include <string.h>

/* Helper functions for Little-Endian encoding/decoding */
static void write_uint32_le(uint8_t *dst, uint32_t val) {
    dst[0] = (uint8_t)(val & 0xFF);
    dst[1] = (uint8_t)((val >> 8) & 0xFF);
    dst[2] = (uint8_t)((val >> 16) & 0xFF);
    dst[3] = (uint8_t)((val >> 24) & 0xFF);
}

static uint32_t read_uint32_le(const uint8_t *src) {
    return ((uint32_t)src[0]) |
           (((uint32_t)src[1]) << 8) |
           (((uint32_t)src[2]) << 16) |
           (((uint32_t)src[3]) << 24);
}

static void write_uint64_le(uint8_t *dst, uint64_t val) {
    for (int i = 0; i < 8; i++) {
        dst[i] = (uint8_t)((val >> (i * 8)) & 0xFF);
    }
}

static uint64_t read_uint64_le(const uint8_t *src) {
    uint64_t val = 0;
    for (int i = 0; i < 8; i++) {
        val |= (((uint64_t)src[i]) << (i * 8));
    }
    return val;
}

secfile_error_t secfile_header_init(secfile_header_t *header) {
    if (!header) {
        return SECFILE_ERR_INVALID_PARAM;
    }

    memcpy(header->magic, SECFILE_MAGIC, SECFILE_MAGIC_LEN);
    header->version = SECFILE_VERSION;
    header->kdf_algorithm = 2; /* crypto_pwhash_ALG_ARGON2ID13 */
    header->opslimit = SECFILE_ARGON2_OPSLIMIT;
    header->memlimit = SECFILE_ARGON2_MEMLIMIT;

    /* Generate cryptographically secure random salt and nonce */
    secfile_random_bytes(header->salt, SECFILE_SALT_SIZE);
    secfile_random_bytes(header->nonce, SECFILE_NONCE_SIZE);

    return SECFILE_OK;
}

secfile_error_t secfile_header_serialize(const secfile_header_t *header, uint8_t *buffer, size_t buf_len) {
    if (!header || !buffer || buf_len < SECFILE_HEADER_SIZE) {
        return SECFILE_ERR_INVALID_PARAM;
    }

    size_t offset = 0;

    /* Magic (8 bytes) */
    memcpy(buffer + offset, header->magic, SECFILE_MAGIC_LEN);
    offset += SECFILE_MAGIC_LEN;

    /* Version (4 bytes, LE) */
    write_uint32_le(buffer + offset, header->version);
    offset += 4;

    /* KDF algorithm (4 bytes, LE) */
    write_uint32_le(buffer + offset, header->kdf_algorithm);
    offset += 4;

    /* Opslimit (8 bytes, LE) */
    write_uint64_le(buffer + offset, header->opslimit);
    offset += 8;

    /* Memlimit (8 bytes, LE) */
    write_uint64_le(buffer + offset, header->memlimit);
    offset += 8;

    /* Salt (16 bytes) */
    memcpy(buffer + offset, header->salt, SECFILE_SALT_SIZE);
    offset += SECFILE_SALT_SIZE;

    /* Nonce (12 bytes) */
    memcpy(buffer + offset, header->nonce, SECFILE_NONCE_SIZE);
    offset += SECFILE_NONCE_SIZE;

    if (offset != SECFILE_HEADER_SIZE) {
        return SECFILE_ERR_FORMAT_INVALID;
    }

    return SECFILE_OK;
}

secfile_error_t secfile_header_deserialize(const uint8_t *buffer, size_t buf_len, secfile_header_t *header) {
    if (!buffer || !header || buf_len < SECFILE_HEADER_SIZE) {
        return SECFILE_ERR_INVALID_PARAM;
    }

    size_t offset = 0;

    /* Magic check */
    if (memcmp(buffer + offset, SECFILE_MAGIC, SECFILE_MAGIC_LEN) != 0) {
        return SECFILE_ERR_FORMAT_INVALID;
    }
    memcpy(header->magic, buffer + offset, SECFILE_MAGIC_LEN);
    offset += SECFILE_MAGIC_LEN;

    /* Version check */
    header->version = read_uint32_le(buffer + offset);
    offset += 4;
    if (header->version != SECFILE_VERSION) {
        return SECFILE_ERR_VERSION_UNSUPPORTED;
    }

    /* KDF algorithm check (must be 2 = Argon2id) */
    header->kdf_algorithm = read_uint32_le(buffer + offset);
    offset += 4;
    if (header->kdf_algorithm != 2) {
        return SECFILE_ERR_FORMAT_INVALID;
    }

    /* Opslimit check */
    header->opslimit = read_uint64_le(buffer + offset);
    offset += 8;
    if (header->opslimit < SECFILE_ARGON2_OPSLIMIT_MIN ||
        header->opslimit > SECFILE_ARGON2_OPSLIMIT_MAX) {
        return SECFILE_ERR_FORMAT_INVALID;
    }

    /* Memlimit check */
    header->memlimit = read_uint64_le(buffer + offset);
    offset += 8;
    if (header->memlimit < SECFILE_ARGON2_MEMLIMIT_MIN ||
        header->memlimit > SECFILE_ARGON2_MEMLIMIT_MAX) {
        return SECFILE_ERR_FORMAT_INVALID;
    }

    /* Salt */
    memcpy(header->salt, buffer + offset, SECFILE_SALT_SIZE);
    offset += SECFILE_SALT_SIZE;

    /* Nonce */
    memcpy(header->nonce, buffer + offset, SECFILE_NONCE_SIZE);
    offset += SECFILE_NONCE_SIZE;

    return SECFILE_OK;
}
