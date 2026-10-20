/**
 * @file file_handler.h
 * @brief File system utilities, path checking, safe exclusive temporary file creation,
 *        Unicode path support, and atomic publishing.
 */

#ifndef SECFILE_FILE_HANDLER_H
#define SECFILE_FILE_HANDLER_H

#include "common.h"
#include <stdio.h>

/**
 * @brief Check if a file exists. Supports Unicode UTF-8 paths.
 */
bool secfile_file_exists(const char *path);

/**
 * @brief Get the size of an existing file in bytes (64-bit safe).
 */
secfile_error_t secfile_get_file_size(const char *path, uint64_t *size_out);

/**
 * @brief Check if two paths refer to the exact same file on disk.
 *
 * Uses canonical path normalization, casing comparison, and Windows file index /
 * volume serial numbers to handle hard links, relative paths, and aliases.
 */
bool secfile_is_same_file(const char *path1, const char *path2);

/**
 * @brief Open an existing file for reading in binary mode (Unicode UTF-8 aware).
 */
FILE *secfile_open_read(const char *path);

/**
 * @brief Exclusively create and open a unique temporary file in the destination directory.
 *
 * Guarantees exclusive creation via CREATE_NEW and exclusive sharing flags,
 * preventing symlink following, collisions, or race conditions.
 *
 * @param dest_path Target destination path used to locate the adjacent directory.
 * @param temp_path_out Buffer to receive the generated temporary file path.
 * @param max_len Size of temp_path_out buffer.
 * @param file_out Receives opened FILE* handle on success.
 * @return secfile_error_t SECFILE_OK on success.
 */
secfile_error_t secfile_open_unique_temp_file(
    const char *dest_path,
    char *temp_path_out,
    size_t max_len,
    FILE **file_out
);

/**
 * @brief Atomically publish (move/replace) the temporary file to the final destination.
 *
 * Handles atomic replacement on same-volume filesystems and respects overwrite policies.
 */
secfile_error_t secfile_publish_file(const char *temp_path, const char *dest_path, bool overwrite);

/**
 * @brief Safely remove a file from disk if it exists (Unicode UTF-8 aware).
 */
void secfile_remove_file(const char *path);

#endif /* SECFILE_FILE_HANDLER_H */
