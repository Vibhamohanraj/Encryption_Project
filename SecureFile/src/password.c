/**
 * @file password.c
 * @brief Masked console password input for Windows systems.
 */

#include "password.h"
#include "kdf.h"
#include <stdio.h>
#include <string.h>
#include <io.h>
#include <conio.h>

secfile_error_t secfile_get_password(const char *prompt, char *buffer, size_t max_len) {
    if (!buffer || max_len < 2) {
        return SECFILE_ERR_INVALID_PARAM;
    }

    if (prompt) {
        printf("%s", prompt);
        fflush(stdout);
    }

    memset(buffer, 0, max_len);

    /* Check if stdin is an interactive console terminal */
    if (_isatty(_fileno(stdin))) {
        size_t idx = 0;
        while (1) {
            int ch = _getch();

            /* Extended key prefix (e.g. arrow keys, function keys) */
            if (ch == 0 || ch == 0xE0) {
                (void)_getch(); /* Discard the scan code */
                continue;
            }

            /* Return / Enter */
            if (ch == '\r' || ch == '\n') {
                printf("\n");
                fflush(stdout);
                break;
            }

            /* Ctrl+C or EOF */
            if (ch == 3 || ch == 26 || ch == EOF) {
                printf("\n");
                secfile_memzero(buffer, max_len);
                return SECFILE_ERR_CANCELLED;
            }

            /* Backspace */
            if (ch == '\b' || ch == 127) {
                if (idx > 0) {
                    idx--;
                    buffer[idx] = '\0';
                }
                continue;
            }

            /* Printable characters */
            if (ch >= 32 && ch <= 126) {
                if (idx + 1 < max_len) {
                    buffer[idx++] = (char)ch;
                    buffer[idx] = '\0';
                }
            }
        }
    } else {
        /* Non-interactive stdin (e.g. piped input in tests) */
        if (!fgets(buffer, (int)max_len, stdin)) {
            secfile_memzero(buffer, max_len);
            return SECFILE_ERR_CANCELLED;
        }

        /* Strip trailing newlines */
        size_t len = strlen(buffer);
        while (len > 0 && (buffer[len - 1] == '\r' || buffer[len - 1] == '\n')) {
            buffer[--len] = '\0';
        }
    }

    if (strlen(buffer) == 0) {
        secfile_memzero(buffer, max_len);
        return SECFILE_ERR_INVALID_PARAM;
    }

    return SECFILE_OK;
}

secfile_error_t secfile_get_password_confirm(char *buffer, size_t max_len) {
    if (!buffer || max_len < 2) {
        return SECFILE_ERR_INVALID_PARAM;
    }

    secfile_error_t err = secfile_get_password("Enter password: ", buffer, max_len);
    if (err != SECFILE_OK) {
        return err;
    }

    char confirm[SECFILE_MAX_PASSWORD_LEN] = {0};
    err = secfile_get_password("Confirm password: ", confirm, sizeof(confirm));
    if (err != SECFILE_OK) {
        secfile_memzero(buffer, max_len);
        secfile_memzero(confirm, sizeof(confirm));
        return err;
    }

    if (strcmp(buffer, confirm) != 0) {
        secfile_memzero(buffer, max_len);
        secfile_memzero(confirm, sizeof(confirm));
        return SECFILE_ERR_PASSWORD_MISMATCH;
    }

    secfile_memzero(confirm, sizeof(confirm));
    return SECFILE_OK;
}
