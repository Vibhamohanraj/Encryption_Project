/**
 * @file test_main.c
 * @brief Automated verification and security regression suite for SecureFile.
 *        Covers functional, cryptographic, filesystem safety, and edge-case tests.
 */

#include "common.h"
#include "crypto.h"
#include "format.h"
#include "file_handler.h"
#include "kdf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define TEST_DIR "tests/scratch_test"
#define TEST_PASS 1
#define TEST_FAIL 0

static int g_tests_run = 0;
static int g_tests_passed = 0;

static void report_test(int test_num, const char *name, int passed, const char *detail) {
    g_tests_run++;
    if (passed) {
        g_tests_passed++;
        printf("  [PASS] Test %2d: %s\n", test_num, name);
    } else {
        printf("  [FAIL] Test %2d: %s (%s)\n", test_num, name, detail);
    }
}

static void setup_test_dir(void) {
    CreateDirectoryW(L"tests", NULL);
    CreateDirectoryW(L"tests/scratch_test", NULL);
}

static void cleanup_test_dir(void) {
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(L"tests/scratch_test/*", &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0) {
                wchar_t path[MAX_PATH + 64];
                swprintf(path, sizeof(path) / sizeof(wchar_t), L"tests/scratch_test/%ls", fd.cFileName);
                DeleteFileW(path);
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
    RemoveDirectoryW(L"tests/scratch_test");
}

static FILE *open_test_file_w(const char *path, const wchar_t *mode) {
    int wlen = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);
    if (wlen <= 0) return NULL;
    wchar_t *wpath = malloc((size_t)wlen * sizeof(wchar_t));
    if (!wpath) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, wlen);
    FILE *f = _wfopen(wpath, mode);
    free(wpath);
    return f;
}

static bool create_test_file(const char *path, const void *data, size_t size) {
    FILE *f = open_test_file_w(path, L"wb");
    if (!f) return false;
    if (size > 0) {
        if (fwrite(data, 1, size, f) != size) {
            fclose(f);
            return false;
        }
    }
    fclose(f);
    return true;
}

static bool read_test_file(const char *path, void *buffer, size_t size) {
    FILE *f = open_test_file_w(path, L"rb");
    if (!f) return false;
    size_t read = fread(buffer, 1, size, f);
    fclose(f);
    return (read == size);
}

/* ========================================================================= */
/* FUNCTIONAL TESTS (1 - 14)                                                 */
/* ========================================================================= */

/* Test 1: Encryption and decryption of a normal text file */
static void test_1_normal_text(void) {
    const char *in_path = TEST_DIR "/test1_plain.txt";
    const char *enc_path = TEST_DIR "/test1.enc";
    const char *dec_path = TEST_DIR "/test1_dec.txt";
    const char *text = "Hello, SecureFile! This is a confidential test message.\nLine 2.\n";
    size_t len = strlen(text);

    create_test_file(in_path, text, len);
    secfile_error_t err = secfile_encrypt_file(in_path, enc_path, "SecretPassword123", false);
    if (err != SECFILE_OK) {
        report_test(1, "Normal text encryption/decryption", TEST_FAIL, "Encryption failed");
        return;
    }

    err = secfile_decrypt_file(enc_path, dec_path, "SecretPassword123", false);
    if (err != SECFILE_OK) {
        report_test(1, "Normal text encryption/decryption", TEST_FAIL, "Decryption failed");
        return;
    }

    char buf[128] = {0};
    if (!read_test_file(dec_path, buf, len) || memcmp(buf, text, len) != 0) {
        report_test(1, "Normal text encryption/decryption", TEST_FAIL, "Plaintext content mismatch");
        return;
    }

    report_test(1, "Normal text encryption/decryption", TEST_PASS, NULL);
}

/* Test 2: Encryption and decryption of a binary file */
static void test_2_binary_file(void) {
    const char *in_path = TEST_DIR "/test2_in.bin";
    const char *enc_path = TEST_DIR "/test2.enc";
    const char *dec_path = TEST_DIR "/test2_out.bin";

    #define BIN_SIZE (70 * 1024)
    uint8_t *orig_data = malloc(BIN_SIZE);
    uint8_t *dec_data = malloc(BIN_SIZE);
    for (size_t i = 0; i < BIN_SIZE; i++) {
        orig_data[i] = (uint8_t)((i * 37 + 13) & 0xFF);
    }

    create_test_file(in_path, orig_data, BIN_SIZE);
    secfile_error_t err = secfile_encrypt_file(in_path, enc_path, "BinaryP@ssw0rd!#", false);
    if (err != SECFILE_OK) {
        report_test(2, "Binary file spanning chunk boundaries", TEST_FAIL, "Encryption failed");
        free(orig_data);
        free(dec_data);
        return;
    }

    err = secfile_decrypt_file(enc_path, dec_path, "BinaryP@ssw0rd!#", false);
    if (err != SECFILE_OK) {
        report_test(2, "Binary file spanning chunk boundaries", TEST_FAIL, "Decryption failed");
        free(orig_data);
        free(dec_data);
        return;
    }

    uint64_t dec_size = 0;
    secfile_get_file_size(dec_path, &dec_size);
    if (dec_size != BIN_SIZE || !read_test_file(dec_path, dec_data, BIN_SIZE) ||
        memcmp(orig_data, dec_data, BIN_SIZE) != 0) {
        report_test(2, "Binary file spanning chunk boundaries", TEST_FAIL, "Binary content mismatch");
        free(orig_data);
        free(dec_data);
        return;
    }

    free(orig_data);
    free(dec_data);
    report_test(2, "Binary file spanning chunk boundaries", TEST_PASS, NULL);
}

/* Test 3: Encryption and decryption of an empty file */
static void test_3_empty_file(void) {
    const char *in_path = TEST_DIR "/test3_empty.txt";
    const char *enc_path = TEST_DIR "/test3.enc";
    const char *dec_path = TEST_DIR "/test3_dec.txt";

    create_test_file(in_path, "", 0);
    secfile_error_t err = secfile_encrypt_file(in_path, enc_path, "EmptyPass", false);
    if (err != SECFILE_OK) {
        report_test(3, "Empty file (0 bytes)", TEST_FAIL, "Encryption failed");
        return;
    }

    uint64_t enc_size = 0;
    secfile_get_file_size(enc_path, &enc_size);
    if (enc_size != (SECFILE_HEADER_SIZE + SECFILE_TAG_SIZE)) {
        report_test(3, "Empty file (0 bytes)", TEST_FAIL, "Encrypted size should be exactly 76 bytes");
        return;
    }

    err = secfile_decrypt_file(enc_path, dec_path, "EmptyPass", false);
    if (err != SECFILE_OK) {
        report_test(3, "Empty file (0 bytes)", TEST_FAIL, "Decryption failed");
        return;
    }

    uint64_t dec_size = 0;
    secfile_get_file_size(dec_path, &dec_size);
    if (dec_size != 0) {
        report_test(3, "Empty file (0 bytes)", TEST_FAIL, "Decrypted file is not 0 bytes");
        return;
    }

    report_test(3, "Empty file (0 bytes)", TEST_PASS, NULL);
}

/* Test 4: Incorrect password */
static void test_4_incorrect_password(void) {
    const char *in_path = TEST_DIR "/test4_plain.txt";
    const char *enc_path = TEST_DIR "/test4.enc";
    const char *dec_path = TEST_DIR "/test4_dec.txt";

    create_test_file(in_path, "SuperSecret", 11);
    secfile_encrypt_file(in_path, enc_path, "CorrectPassword", false);

    secfile_error_t err = secfile_decrypt_file(enc_path, dec_path, "WrongPassword", false);
    int passed = (err == SECFILE_ERR_AUTH_FAILED) && !secfile_file_exists(dec_path);
    report_test(4, "Incorrect password rejection & cleanup", passed,
        passed ? NULL : "Did not return AUTH_FAILED or published unauthenticated output");
}

/* Test 5: Modified ciphertext */
static void test_5_modified_ciphertext(void) {
    const char *in_path = TEST_DIR "/test5_plain.txt";
    const char *enc_path = TEST_DIR "/test5.enc";
    const char *dec_path = TEST_DIR "/test5_dec.txt";

    create_test_file(in_path, "TamperTest1234567890", 20);
    secfile_encrypt_file(in_path, enc_path, "Password5", false);

    /* Tamper one byte in the ciphertext portion */
    FILE *f = fopen(enc_path, "r+b");
    if (f) {
        _fseeki64(f, SECFILE_HEADER_SIZE + 2, SEEK_SET);
        int b = fgetc(f);
        _fseeki64(f, SECFILE_HEADER_SIZE + 2, SEEK_SET);
        fputc(b ^ 0xFF, f);
        fclose(f);
    }

    secfile_error_t err = secfile_decrypt_file(enc_path, dec_path, "Password5", false);
    int passed = (err == SECFILE_ERR_AUTH_FAILED) && !secfile_file_exists(dec_path);
    report_test(5, "Modified ciphertext tamper detection", passed,
        passed ? NULL : "Failed to detect modified ciphertext or leaked plaintext");
}

/* Test 6: Modified authentication tag */
static void test_6_modified_auth_tag(void) {
    const char *in_path = TEST_DIR "/test6_plain.txt";
    const char *enc_path = TEST_DIR "/test6.enc";
    const char *dec_path = TEST_DIR "/test6_dec.txt";

    create_test_file(in_path, "AuthTagTamperTest", 17);
    secfile_encrypt_file(in_path, enc_path, "Password6", false);

    /* Tamper one byte in the authentication tag at the end of the file */
    uint64_t sz = 0;
    secfile_get_file_size(enc_path, &sz);
    FILE *f = fopen(enc_path, "r+b");
    if (f) {
        _fseeki64(f, (int64_t)(sz - 1), SEEK_SET);
        int b = fgetc(f);
        _fseeki64(f, (int64_t)(sz - 1), SEEK_SET);
        fputc(b ^ 0x01, f);
        fclose(f);
    }

    secfile_error_t err = secfile_decrypt_file(enc_path, dec_path, "Password6", false);
    int passed = (err == SECFILE_ERR_AUTH_FAILED) && !secfile_file_exists(dec_path);
    report_test(6, "Modified authentication tag detection", passed,
        passed ? NULL : "Failed to detect modified tag or leaked plaintext");
}

/* Test 7: Modified header (AAD validation) */
static void test_7_modified_header(void) {
    const char *in_path = TEST_DIR "/test7_plain.txt";
    const char *enc_path = TEST_DIR "/test7.enc";
    const char *dec_path = TEST_DIR "/test7_dec.txt";

    create_test_file(in_path, "HeaderTamperTest", 16);
    secfile_encrypt_file(in_path, enc_path, "Password7", false);

    /* Tamper one byte in the salt/nonce within header */
    FILE *f = fopen(enc_path, "r+b");
    if (f) {
        _fseeki64(f, 20, SEEK_SET);
        int b = fgetc(f);
        _fseeki64(f, 20, SEEK_SET);
        fputc(b ^ 0x55, f);
        fclose(f);
    }

    secfile_error_t err = secfile_decrypt_file(enc_path, dec_path, "Password7", false);
    int passed = (err == SECFILE_ERR_AUTH_FAILED || err == SECFILE_ERR_FORMAT_INVALID) &&
                 !secfile_file_exists(dec_path);
    report_test(7, "Modified header (AAD authentication check)", passed,
        passed ? NULL : "Failed to detect header modification or leaked output");
}

/* Test 8: Truncated encrypted file */
static void test_8_truncated_file(void) {
    const char *in_path = TEST_DIR "/test8_plain.txt";
    const char *enc_path = TEST_DIR "/test8.enc";
    const char *dec_path = TEST_DIR "/test8_dec.txt";

    create_test_file(in_path, "TruncationDataPayload", 21);
    secfile_encrypt_file(in_path, enc_path, "Password8", false);

    /* Truncate file to 40 bytes (smaller than 76 bytes minimum) */
    FILE *f = fopen(enc_path, "rb");
    uint8_t mini[40];
    if (f) {
        size_t r = fread(mini, 1, 40, f);
        (void)r;
        fclose(f);
    }
    create_test_file(enc_path, mini, 40);

    secfile_error_t err = secfile_decrypt_file(enc_path, dec_path, "Password8", false);
    int passed = (err == SECFILE_ERR_FORMAT_INVALID) && !secfile_file_exists(dec_path);
    report_test(8, "Truncated file rejection", passed,
        passed ? NULL : "Did not reject truncated header or leaked output");
}

/* Test 9: Unsupported file version */
static void test_9_unsupported_version(void) {
    const char *in_path = TEST_DIR "/test9_plain.txt";
    const char *enc_path = TEST_DIR "/test9.enc";
    const char *dec_path = TEST_DIR "/test9_dec.txt";

    create_test_file(in_path, "VersionTestData", 15);
    secfile_encrypt_file(in_path, enc_path, "Password9", false);

    /* Modify version field at offset 8 to 999 (0x000003E7) */
    FILE *f = fopen(enc_path, "r+b");
    if (f) {
        _fseeki64(f, 8, SEEK_SET);
        uint8_t bad_ver[4] = {0xE7, 0x03, 0x00, 0x00};
        fwrite(bad_ver, 1, 4, f);
        fclose(f);
    }

    secfile_error_t err = secfile_decrypt_file(enc_path, dec_path, "Password9", false);
    int passed = (err == SECFILE_ERR_VERSION_UNSUPPORTED) && !secfile_file_exists(dec_path);
    report_test(9, "Unsupported file version rejection", passed,
        passed ? NULL : "Failed to return SECFILE_ERR_VERSION_UNSUPPORTED");
}

/* Test 10: Missing input file */
static void test_10_missing_input(void) {
    const char *missing_in = TEST_DIR "/does_not_exist.txt";
    const char *out_path = TEST_DIR "/test10_out.enc";

    secfile_error_t err = secfile_encrypt_file(missing_in, out_path, "Password10", false);
    int passed = (err == SECFILE_ERR_FILE_NOT_FOUND) && !secfile_file_exists(out_path);
    report_test(10, "Missing input file handling", passed,
        passed ? NULL : "Did not return SECFILE_ERR_FILE_NOT_FOUND");
}

/* Test 11: Existing output file refusal */
static void test_11_existing_output_refusal(void) {
    const char *in_path = TEST_DIR "/test11_in.txt";
    const char *out_path = TEST_DIR "/test11_out.txt";

    create_test_file(in_path, "Data11", 6);
    create_test_file(out_path, "PreExisting", 11);

    secfile_error_t err = secfile_encrypt_file(in_path, out_path, "Password11", false);
    int passed = (err == SECFILE_ERR_FILE_EXISTS);

    /* Verify original output was not overwritten */
    char check[16] = {0};
    read_test_file(out_path, check, 11);
    passed = passed && (strcmp(check, "PreExisting") == 0);

    report_test(11, "Refusal to overwrite existing output file", passed,
        passed ? NULL : "Did not return SECFILE_ERR_FILE_EXISTS or modified output");
}

/* Test 12: Input and output referring to the same file */
static void test_12_same_file_rejection(void) {
    const char *path = TEST_DIR "/test12_same.txt";
    create_test_file(path, "DoNotDestroyMe", 14);

    secfile_error_t err = secfile_encrypt_file(path, path, "Password12", true);
    int passed = (err == SECFILE_ERR_SAME_FILE);

    char check[32] = {0};
    read_test_file(path, check, 14);
    passed = passed && (strcmp(check, "DoNotDestroyMe") == 0);

    report_test(12, "Input and output referring to the same file", passed,
        passed ? NULL : "Did not reject identical path or damaged file");
}

/* Test 13: File read/write error handling */
static void test_13_io_error_handling(void) {
    const char *in_path = TEST_DIR "/test13_in.txt";
    const char *bad_out_path = "Z:/NonExistentDrive/bad:dir/test13.enc";

    create_test_file(in_path, "IOData", 6);
    secfile_error_t err = secfile_encrypt_file(in_path, bad_out_path, "Password13", true);
    int passed = (err == SECFILE_ERR_FILE_IO || err == SECFILE_ERR_INVALID_PARAM);
    report_test(13, "I/O error handling on invalid destination", passed,
        passed ? NULL : "Did not return I/O error on invalid path");
}

/* Test 14: Memory and cleanup behavior on failures */
static void test_14_temp_file_cleanup(void) {
    const char *in_path = TEST_DIR "/test14_in.txt";
    const char *enc_path = TEST_DIR "/test14.enc";
    const char *dec_path = TEST_DIR "/test14_dec.txt";

    create_test_file(in_path, "CleanupValidationData", 21);
    secfile_encrypt_file(in_path, enc_path, "Password14", false);

    /* Attempt decryption with wrong password */
    secfile_decrypt_file(enc_path, dec_path, "WrongPasswordForCleanup", false);

    /* Scan directory to ensure NO .tmp files are left behind */
    WIN32_FIND_DATAA fd;
    char pattern[MAX_PATH + 32];
    snprintf(pattern, sizeof(pattern), "%s/*tmp*", TEST_DIR);
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    int dangling_found = 0;
    if (hFind != INVALID_HANDLE_VALUE) {
        dangling_found = 1;
        FindClose(hFind);
    }

    int passed = (!dangling_found) && (!secfile_file_exists(dec_path));
    report_test(14, "Zero temporary file leaks on failure", passed,
        passed ? NULL : "Dangling temporary files were detected in directory");
}

/* ========================================================================= */
/* ADDITIONAL SECURITY AUDIT TESTS (15 - 22)                                 */
/* ========================================================================= */

/* Test 15: Nonce & Salt Uniqueness Across Repeated Runs */
static void test_15_nonce_salt_uniqueness(void) {
    const char *in_path = TEST_DIR "/test15_in.txt";
    create_test_file(in_path, "NonceUniquenessTest", 19);

    uint8_t salts[5][SECFILE_SALT_SIZE];
    uint8_t nonces[5][SECFILE_NONCE_SIZE];

    for (int i = 0; i < 5; i++) {
        char enc_path[MAX_PATH];
        snprintf(enc_path, sizeof(enc_path), "%s/test15_%d.enc", TEST_DIR, i);
        secfile_encrypt_file(in_path, enc_path, "SamePassword", false);

        FILE *f = fopen(enc_path, "rb");
        if (!f) {
            report_test(15, "Nonce/salt uniqueness across repeated runs", TEST_FAIL, "Could not open enc file");
            return;
        }

        uint8_t header_buf[SECFILE_HEADER_SIZE];
        size_t r = fread(header_buf, 1, SECFILE_HEADER_SIZE, f);
        fclose(f);
        if (r != SECFILE_HEADER_SIZE) {
            report_test(15, "Nonce/salt uniqueness across repeated runs", TEST_FAIL, "Could not read header");
            return;
        }

        secfile_header_t h;
        secfile_header_deserialize(header_buf, SECFILE_HEADER_SIZE, &h);
        memcpy(salts[i], h.salt, SECFILE_SALT_SIZE);
        memcpy(nonces[i], h.nonce, SECFILE_NONCE_SIZE);
    }

    /* Verify all 5 salts and nonces are mutually distinct */
    bool all_distinct = true;
    for (int i = 0; i < 5; i++) {
        for (int j = i + 1; j < 5; j++) {
            if (memcmp(salts[i], salts[j], SECFILE_SALT_SIZE) == 0 ||
                memcmp(nonces[i], nonces[j], SECFILE_NONCE_SIZE) == 0) {
                all_distinct = false;
                break;
            }
        }
    }

    report_test(15, "Nonce/salt uniqueness across repeated runs", all_distinct ? TEST_PASS : TEST_FAIL,
        all_distinct ? NULL : "Identical salt or nonce generated across runs");
}

/* Test 16: Extreme and Corrupted KDF Metadata Rejection */
static void test_16_extreme_kdf_metadata(void) {
    secfile_header_t h;
    secfile_header_init(&h);
    uint8_t buf[SECFILE_HEADER_SIZE];
    secfile_header_serialize(&h, buf, sizeof(buf));

    secfile_header_t test_h;

    /* 1. Opslimit = 0 */
    buf[16] = 0; buf[17] = 0; buf[18] = 0; buf[19] = 0;
    buf[20] = 0; buf[21] = 0; buf[22] = 0; buf[23] = 0;
    secfile_error_t err1 = secfile_header_deserialize(buf, sizeof(buf), &test_h);

    /* 2. Opslimit = 999999 */
    buf[16] = 0x3F; buf[17] = 0x42; buf[18] = 0x0F;
    secfile_error_t err2 = secfile_header_deserialize(buf, sizeof(buf), &test_h);

    /* 3. Memlimit = 100 bytes (far below 8 MiB) */
    secfile_header_serialize(&h, buf, sizeof(buf));
    buf[24] = 100; buf[25] = 0; buf[26] = 0; buf[27] = 0;
    secfile_error_t err3 = secfile_header_deserialize(buf, sizeof(buf), &test_h);

    /* 4. Memlimit = 100 GiB (far above 1 GiB) */
    buf[24] = 0; buf[25] = 0; buf[26] = 0; buf[27] = 0;
    buf[28] = 0x19; /* 100 GB */
    secfile_error_t err4 = secfile_header_deserialize(buf, sizeof(buf), &test_h);

    int passed = (err1 == SECFILE_ERR_FORMAT_INVALID &&
                  err2 == SECFILE_ERR_FORMAT_INVALID &&
                  err3 == SECFILE_ERR_FORMAT_INVALID &&
                  err4 == SECFILE_ERR_FORMAT_INVALID);

    report_test(16, "Extreme & corrupted KDF metadata rejection", passed,
        passed ? NULL : "Failed to reject invalid KDF parameters");
}

/* Test 17: Unicode UTF-8 Path Support */
static void test_17_unicode_paths(void) {
    const char *in_path = TEST_DIR "/test_unicode_lock_\xF0\x9F\x94\x92.txt";
    const char *enc_path = TEST_DIR "/test_unicode_\xD1\x84\xD0\xB0\xD0\xB9\xD0\xBB.enc";
    const char *dec_path = TEST_DIR "/test_unicode_\xC3\xBC_dec.txt";
    const char *secret_data = "Unicode paths supported seamlessly in UTF-8!";
    size_t len = strlen(secret_data);

    create_test_file(in_path, secret_data, len);
    secfile_error_t err = secfile_encrypt_file(in_path, enc_path, "UnicodePass123", false);
    if (err != SECFILE_OK) {
        report_test(17, "Unicode UTF-8 path handling", TEST_FAIL, "Encryption failed with Unicode path");
        return;
    }

    err = secfile_decrypt_file(enc_path, dec_path, "UnicodePass123", false);
    if (err != SECFILE_OK) {
        report_test(17, "Unicode UTF-8 path handling", TEST_FAIL, "Decryption failed with Unicode path");
        return;
    }

    char buf[128] = {0};
    bool ok = read_test_file(dec_path, buf, len) && (memcmp(buf, secret_data, len) == 0);
    secfile_remove_file(in_path);
    secfile_remove_file(enc_path);
    secfile_remove_file(dec_path);
    report_test(17, "Unicode UTF-8 path handling", ok ? TEST_PASS : TEST_FAIL,
        ok ? NULL : "Content mismatch on Unicode file round-trip");
}

/* Test 18: Temporary File Exclusive Creation (Collision Resistance) */
static void test_18_temp_collision_resistance(void) {
    const char *out_path = TEST_DIR "/test18_out.txt";
    char temp_path1[MAX_PATH] = {0};
    char temp_path2[MAX_PATH] = {0};
    FILE *f1 = NULL;
    FILE *f2 = NULL;

    secfile_error_t err1 = secfile_open_unique_temp_file(out_path, temp_path1, sizeof(temp_path1), &f1);
    secfile_error_t err2 = secfile_open_unique_temp_file(out_path, temp_path2, sizeof(temp_path2), &f2);

    int passed = (err1 == SECFILE_OK && err2 == SECFILE_OK &&
                  f1 != NULL && f2 != NULL &&
                  strcmp(temp_path1, temp_path2) != 0);

    if (f1) fclose(f1);
    if (f2) fclose(f2);
    secfile_remove_file(temp_path1);
    secfile_remove_file(temp_path2);

    report_test(18, "Exclusive temp file creation & collision avoidance", passed,
        passed ? NULL : "Temporary file paths collided or failed exclusive open");
}

/* Test 19: Large File Streaming Across Many Chunks (1 MiB / 16 chunks) */
static void test_19_large_file_streaming(void) {
    const char *in_path = TEST_DIR "/test19_1mb.bin";
    const char *enc_path = TEST_DIR "/test19.enc";
    const char *dec_path = TEST_DIR "/test19_dec.bin";

    #define LARGE_SZ (1024 * 1024) /* 1 MiB */
    uint8_t *orig = malloc(LARGE_SZ);
    uint8_t *dec = malloc(LARGE_SZ);
    if (!orig || !dec) {
        free(orig); free(dec);
        report_test(19, "Large file streaming (1 MiB / 16 chunks)", TEST_FAIL, "Host OOM");
        return;
    }

    for (size_t i = 0; i < LARGE_SZ; i++) {
        orig[i] = (uint8_t)((i * 131 + 17) & 0xFF);
    }

    create_test_file(in_path, orig, LARGE_SZ);
    secfile_error_t err = secfile_encrypt_file(in_path, enc_path, "LargeFilePass", false);
    if (err != SECFILE_OK) {
        free(orig); free(dec);
        report_test(19, "Large file streaming (1 MiB / 16 chunks)", TEST_FAIL, "Encryption failed");
        return;
    }

    err = secfile_decrypt_file(enc_path, dec_path, "LargeFilePass", false);
    if (err != SECFILE_OK) {
        free(orig); free(dec);
        report_test(19, "Large file streaming (1 MiB / 16 chunks)", TEST_FAIL, "Decryption failed");
        return;
    }

    bool match = read_test_file(dec_path, dec, LARGE_SZ) && (memcmp(orig, dec, LARGE_SZ) == 0);
    free(orig);
    free(dec);

    report_test(19, "Large file streaming (1 MiB / 16 chunks)", match ? TEST_PASS : TEST_FAIL,
        match ? NULL : "Decrypted data mismatch across chunks");
}

/* Test 20: Overwrite Permission Handling */
static void test_20_overwrite_permission(void) {
    const char *in_path = TEST_DIR "/test20_in.txt";
    const char *out_path = TEST_DIR "/test20_out.txt";

    create_test_file(in_path, "FreshPayload", 12);
    create_test_file(out_path, "OldStaleContent", 15);

    /* Encrypt with overwrite = true */
    secfile_error_t err = secfile_encrypt_file(in_path, out_path, "Pass20", true);
    int passed = (err == SECFILE_OK);

    uint64_t new_sz = 0;
    secfile_get_file_size(out_path, &new_sz);
    passed = passed && (new_sz == (12 + SECFILE_HEADER_SIZE + SECFILE_TAG_SIZE));

    report_test(20, "Explicit overwrite permission handling", passed,
        passed ? NULL : "Failed to overwrite when permission was granted");
}

/* Test 21: Zero Plaintext Published on Auth Tag Truncation */
static void test_21_truncated_auth_tag(void) {
    const char *in_path = TEST_DIR "/test21_in.txt";
    const char *enc_path = TEST_DIR "/test21.enc";
    const char *dec_path = TEST_DIR "/test21_dec.txt";

    create_test_file(in_path, "ZeroPlaintextOnTagTruncation", 28);
    secfile_encrypt_file(in_path, enc_path, "Pass21", false);

    /* Truncate last 8 bytes of the auth tag */
    uint64_t sz = 0;
    secfile_get_file_size(enc_path, &sz);
    FILE *f = fopen(enc_path, "rb");
    uint8_t *cut_buf = malloc((size_t)sz - 8);
    if (f && cut_buf) {
        size_t r = fread(cut_buf, 1, (size_t)sz - 8, f);
        (void)r;
        fclose(f);
        create_test_file(enc_path, cut_buf, (size_t)sz - 8);
    }
    free(cut_buf);

    secfile_error_t err = secfile_decrypt_file(enc_path, dec_path, "Pass21", false);
    int passed = (err == SECFILE_ERR_AUTH_FAILED || err == SECFILE_ERR_FORMAT_INVALID) &&
                 !secfile_file_exists(dec_path);

    report_test(21, "Zero plaintext published on auth tag truncation", passed,
        passed ? NULL : "Decrypted output published despite truncated auth tag");
}

/* Test 22: Non-existent Output Directory Error Handling */
static void test_22_nonexistent_dest_directory(void) {
    const char *in_path = TEST_DIR "/test22_in.txt";
    const char *bad_dest = "tests/nonexistent_folder_abc123/output.enc";

    create_test_file(in_path, "ValidData", 9);
    secfile_error_t err = secfile_encrypt_file(in_path, bad_dest, "Pass22", false);

    int passed = (err == SECFILE_ERR_FILE_IO || err == SECFILE_ERR_INVALID_PARAM) &&
                 !secfile_file_exists(bad_dest);

    report_test(22, "Non-existent output directory failure handling", passed,
        passed ? NULL : "Did not fail gracefully on non-existent directory");
}

/* ========================================================================= */
/* MAIN RUNNER                                                               */
/* ========================================================================= */

int main(void) {
    printf("====================================================\n");
    printf("    SecureFile Automated Verification Suite         \n");
    printf("====================================================\n");

    if (secfile_crypto_subsystem_init() != SECFILE_OK) {
        fprintf(stderr, "Fatal error: Failed to initialize crypto subsystem.\n");
        return 1;
    }

    setup_test_dir();

    /* Functional Test Suite (1 - 14) */
    test_1_normal_text();
    test_2_binary_file();
    test_3_empty_file();
    test_4_incorrect_password();
    test_5_modified_ciphertext();
    test_6_modified_auth_tag();
    test_7_modified_header();
    test_8_truncated_file();
    test_9_unsupported_version();
    test_10_missing_input();
    test_11_existing_output_refusal();
    test_12_same_file_rejection();
    test_13_io_error_handling();
    test_14_temp_file_cleanup();

    /* Security Audit & In-Depth Hardening Tests (15 - 22) */
    test_15_nonce_salt_uniqueness();
    test_16_extreme_kdf_metadata();
    test_17_unicode_paths();
    test_18_temp_collision_resistance();
    test_19_large_file_streaming();
    test_20_overwrite_permission();
    test_21_truncated_auth_tag();
    test_22_nonexistent_dest_directory();

    cleanup_test_dir();

    printf("----------------------------------------------------\n");
    printf("Summary: %d / %d tests passed (%.1f%%)\n",
           g_tests_passed, g_tests_run,
           (float)g_tests_passed / (float)g_tests_run * 100.0f);
    printf("====================================================\n");

    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
