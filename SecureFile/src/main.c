/**
 * @file main.c
 * @brief Application entry point and interactive menu for SecureFile.
 */

#include "common.h"
#include "crypto.h"
#include "password.h"
#include "file_handler.h"
#include "kdf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_banner(void) {
    printf("\n");
    printf("========================================\n");
    printf("      SecureFile - AES-256-GCM Tool     \n");
    printf("========================================\n");
}

static void print_menu(void) {
    print_banner();
    printf("1. Encrypt a file\n");
    printf("2. Decrypt a file\n");
    printf("3. Exit\n");
    printf("----------------------------------------\n");
    printf("Enter choice (1-3): ");
    fflush(stdout);
}

static void read_path_input(const char *prompt, char *buffer, size_t max_len) {
    printf("%s", prompt);
    fflush(stdout);
    memset(buffer, 0, max_len);

    if (fgets(buffer, (int)max_len, stdin)) {
        size_t len = strlen(buffer);
        while (len > 0 && (buffer[len - 1] == '\r' || buffer[len - 1] == '\n')) {
            buffer[--len] = '\0';
        }

        /* Strip surrounding quotes if user copied path with quotes or drag-and-dropped */
        if (len >= 2 && buffer[0] == '"' && buffer[len - 1] == '"') {
            memmove(buffer, buffer + 1, len - 2);
            buffer[len - 2] = '\0';
        }
    }
}

static bool ask_overwrite(const char *output_path) {
    if (!secfile_file_exists(output_path)) {
        return false;
    }

    char ans[16] = {0};
    printf("Warning: Output file '%s' already exists.\nOverwrite? (y/N): ", output_path);
    fflush(stdout);

    if (fgets(ans, sizeof(ans), stdin)) {
        if (ans[0] == 'y' || ans[0] == 'Y') {
            return true;
        }
    }
    return false;
}

static bool handle_encrypt(const char *in_arg, const char *out_arg, bool force_overwrite) {
    char in_path[SECFILE_MAX_PATH] = {0};
    char out_path[SECFILE_MAX_PATH] = {0};
    char password[SECFILE_MAX_PASSWORD_LEN] = {0};

    if (in_arg) {
        strncpy(in_path, in_arg, sizeof(in_path) - 1);
    } else {
        read_path_input("Enter path of file to encrypt: ", in_path, sizeof(in_path));
    }

    if (strlen(in_path) == 0) {
        printf("Error: Input path cannot be empty.\n");
        return false;
    }

    if (!secfile_file_exists(in_path)) {
        printf("Error: Input file '%s' does not exist.\n", in_path);
        return false;
    }

    if (out_arg) {
        strncpy(out_path, out_arg, sizeof(out_path) - 1);
    } else {
        read_path_input("Enter path for encrypted output: ", out_path, sizeof(out_path));
    }

    if (strlen(out_path) == 0) {
        printf("Error: Output path cannot be empty.\n");
        return false;
    }

    if (secfile_is_same_file(in_path, out_path)) {
        printf("Error: Input and output paths refer to the same file. Aborting.\n");
        return false;
    }

    bool overwrite = force_overwrite;
    if (!overwrite && secfile_file_exists(out_path)) {
        if (in_arg) {
            /* CLI mode: require explicit --overwrite flag */
            printf("Error: Output file '%s' already exists. Use --overwrite to replace it.\n", out_path);
            return false;
        } else {
            /* Interactive mode: prompt the user */
            if (!ask_overwrite(out_path)) {
                printf("Operation cancelled: Output file exists.\n");
                return false;
            }
            overwrite = true;
        }
    }

    secfile_error_t err = secfile_get_password_confirm(password, sizeof(password));
    if (err != SECFILE_OK) {
        printf("Password entry error: %s\n", secfile_strerror(err));
        secfile_memzero(password, sizeof(password));
        return false;
    }

    printf("Encrypting '%s' -> '%s'...\n", in_path, out_path);
    err = secfile_encrypt_file(in_path, out_path, password, overwrite);
    secfile_memzero(password, sizeof(password));

    if (err == SECFILE_OK) {
        printf("Success: File encrypted successfully.\n");
        return true;
    } else {
        printf("Encryption failed: %s\n", secfile_strerror(err));
        return false;
    }
}

static bool handle_decrypt(const char *in_arg, const char *out_arg, bool force_overwrite) {
    char in_path[SECFILE_MAX_PATH] = {0};
    char out_path[SECFILE_MAX_PATH] = {0};
    char password[SECFILE_MAX_PASSWORD_LEN] = {0};

    if (in_arg) {
        strncpy(in_path, in_arg, sizeof(in_path) - 1);
    } else {
        read_path_input("Enter path of file to decrypt: ", in_path, sizeof(in_path));
    }

    if (strlen(in_path) == 0) {
        printf("Error: Input path cannot be empty.\n");
        return false;
    }

    if (!secfile_file_exists(in_path)) {
        printf("Error: Input file '%s' does not exist.\n", in_path);
        return false;
    }

    if (out_arg) {
        strncpy(out_path, out_arg, sizeof(out_path) - 1);
    } else {
        read_path_input("Enter path for decrypted output: ", out_path, sizeof(out_path));
    }

    if (strlen(out_path) == 0) {
        printf("Error: Output path cannot be empty.\n");
        return false;
    }

    if (secfile_is_same_file(in_path, out_path)) {
        printf("Error: Input and output paths refer to the same file. Aborting.\n");
        return false;
    }

    bool overwrite = force_overwrite;
    if (!overwrite && secfile_file_exists(out_path)) {
        if (in_arg) {
            /* CLI mode: require explicit --overwrite flag */
            printf("Error: Output file '%s' already exists. Use --overwrite to replace it.\n", out_path);
            return false;
        } else {
            /* Interactive mode: prompt the user */
            if (!ask_overwrite(out_path)) {
                printf("Operation cancelled: Output file exists.\n");
                return false;
            }
            overwrite = true;
        }
    }

    secfile_error_t err = secfile_get_password("Enter password: ", password, sizeof(password));
    if (err != SECFILE_OK) {
        printf("Password entry error: %s\n", secfile_strerror(err));
        secfile_memzero(password, sizeof(password));
        return false;
    }

    printf("Decrypting and verifying '%s' -> '%s'...\n", in_path, out_path);
    err = secfile_decrypt_file(in_path, out_path, password, overwrite);
    secfile_memzero(password, sizeof(password));

    if (err == SECFILE_OK) {
        printf("Success: File decrypted and authenticated successfully.\n");
        return true;
    } else {
        printf("Decryption failed: %s\n", secfile_strerror(err));
        return false;
    }
}

int main(int argc, char *argv[]) {
    /* Initialize crypto subsystem */
    if (secfile_crypto_subsystem_init() != SECFILE_OK) {
        fprintf(stderr, "Fatal error: Failed to initialize cryptographic subsystem.\n");
        return 1;
    }

    /* CLI Mode: Command-line arguments supplied */
    if (argc > 1) {
        if (strcmp(argv[1], "--encrypt") == 0 || strcmp(argv[1], "-e") == 0) {
            if (argc < 4) {
                fprintf(stderr, "Usage: %s --encrypt <input> <output> [--overwrite]\n", argv[0]);
                return 1;
            }
            if (argc > 5) {
                fprintf(stderr, "Error: Too many arguments. Usage: %s --encrypt <input> <output> [--overwrite]\n", argv[0]);
                return 1;
            }
            bool overwrite = false;
            if (argc == 5) {
                if (strcmp(argv[4], "--overwrite") == 0 || strcmp(argv[4], "-f") == 0) {
                    overwrite = true;
                } else {
                    fprintf(stderr, "Error: Unknown option '%s'. Use --overwrite or -f to allow overwriting.\n", argv[4]);
                    return 1;
                }
            }
            bool ok = handle_encrypt(argv[2], argv[3], overwrite);
            return ok ? 0 : 1;
        } else if (strcmp(argv[1], "--decrypt") == 0 || strcmp(argv[1], "-d") == 0) {
            if (argc < 4) {
                fprintf(stderr, "Usage: %s --decrypt <input> <output> [--overwrite]\n", argv[0]);
                return 1;
            }
            if (argc > 5) {
                fprintf(stderr, "Error: Too many arguments. Usage: %s --decrypt <input> <output> [--overwrite]\n", argv[0]);
                return 1;
            }
            bool overwrite = false;
            if (argc == 5) {
                if (strcmp(argv[4], "--overwrite") == 0 || strcmp(argv[4], "-f") == 0) {
                    overwrite = true;
                } else {
                    fprintf(stderr, "Error: Unknown option '%s'. Use --overwrite or -f to allow overwriting.\n", argv[4]);
                    return 1;
                }
            }
            bool ok = handle_decrypt(argv[2], argv[3], overwrite);
            return ok ? 0 : 1;
        } else if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            printf("Usage:\n");
            printf("  Interactive mode: %s\n", argv[0]);
            printf("  Encrypt:          %s --encrypt <input> <output> [--overwrite]\n", argv[0]);
            printf("  Decrypt:          %s --decrypt <input> <output> [--overwrite]\n", argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s. Use --help for usage.\n", argv[1]);
            return 1;
        }
    }

    /* Interactive Menu Mode */
    char choice_buf[32] = {0};
    while (1) {
        print_menu();
        if (!fgets(choice_buf, sizeof(choice_buf), stdin)) {
            break;
        }

        int choice = atoi(choice_buf);
        switch (choice) {
            case 1:
                handle_encrypt(NULL, NULL, false);
                break;
            case 2:
                handle_decrypt(NULL, NULL, false);
                break;
            case 3:
                printf("Exiting SecureFile. Goodbye!\n");
                return 0;
            default:
                printf("Invalid selection. Please choose 1, 2, or 3.\n");
                break;
        }
    }

    return 0;
}
