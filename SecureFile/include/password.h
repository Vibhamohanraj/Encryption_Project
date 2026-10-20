/**
 * @file password.h
 * @brief Windows-compatible masked / non-echoing password input routines.
 */

#ifndef SECFILE_PASSWORD_H
#define SECFILE_PASSWORD_H

#include "common.h"

/**
 * @brief Prompt user for a password without echoing characters to the terminal.
 *
 * Falls back safely to standard input when stdin is not an interactive terminal
 * (e.g. during automated test execution).
 *
 * @param prompt Prompt message displayed to the user.
 * @param buffer Output buffer to store null-terminated password.
 * @param max_len Size of buffer in bytes.
 * @return secfile_error_t SECFILE_OK on success.
 */
secfile_error_t secfile_get_password(const char *prompt, char *buffer, size_t max_len);

/**
 * @brief Prompt user for a password twice and verify confirmation.
 *
 * @param buffer Output buffer for verified password.
 * @param max_len Size of buffer.
 * @return secfile_error_t SECFILE_OK on success, SECFILE_ERR_PASSWORD_MISMATCH if mismatch.
 */
secfile_error_t secfile_get_password_confirm(char *buffer, size_t max_len);

#endif /* SECFILE_PASSWORD_H */
