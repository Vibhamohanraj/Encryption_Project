/**
 * @file file_handler.c
 * @brief Windows filesystem utilities, safe exclusive temporary file creation,
 *        Unicode path support, and atomic publishing.
 */

#include "file_handler.h"
#include "kdf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <io.h>
#include <windows.h>

/**
 * @brief Helper to convert UTF-8 char* string to Windows wchar_t* (UTF-16).
 * Caller must free the returned pointer if non-NULL.
 */
static wchar_t *utf8_to_utf16(const char *utf8) {
    if (!utf8) {
        return NULL;
    }

    /* Try UTF-8 first */
    int wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, NULL, 0);
    if (wlen <= 0) {
        /* Fall back to current ANSI code page for local legacy strings */
        wlen = MultiByteToWideChar(CP_ACP, 0, utf8, -1, NULL, 0);
        if (wlen <= 0) {
            return NULL;
        }
        wchar_t *wstr = malloc((size_t)wlen * sizeof(wchar_t));
        if (!wstr) return NULL;
        MultiByteToWideChar(CP_ACP, 0, utf8, -1, wstr, wlen);
        return wstr;
    }

    wchar_t *wstr = malloc((size_t)wlen * sizeof(wchar_t));
    if (!wstr) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wstr, wlen);
    return wstr;
}

bool secfile_file_exists(const char *path) {
    if (!path || *path == '\0') {
        return false;
    }

    wchar_t *wpath = utf8_to_utf16(path);
    if (!wpath) {
        return false;
    }

    DWORD attrib = GetFileAttributesW(wpath);
    free(wpath);
    return (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY));
}

secfile_error_t secfile_get_file_size(const char *path, uint64_t *size_out) {
    if (!path || !size_out) {
        return SECFILE_ERR_INVALID_PARAM;
    }

    wchar_t *wpath = utf8_to_utf16(path);
    if (!wpath) {
        return SECFILE_ERR_INVALID_PARAM;
    }

    HANDLE hFile = CreateFileW(
        wpath,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    free(wpath);

    if (hFile == INVALID_HANDLE_VALUE) {
        return SECFILE_ERR_FILE_NOT_FOUND;
    }

    LARGE_INTEGER liSize;
    if (!GetFileSizeEx(hFile, &liSize)) {
        CloseHandle(hFile);
        return SECFILE_ERR_FILE_IO;
    }

    CloseHandle(hFile);
    *size_out = (uint64_t)liSize.QuadPart;
    return SECFILE_OK;
}

FILE *secfile_open_read(const char *path) {
    if (!path) {
        return NULL;
    }

    wchar_t *wpath = utf8_to_utf16(path);
    if (!wpath) {
        return NULL;
    }

    FILE *f = _wfopen(wpath, L"rb");
    free(wpath);
    return f;
}

bool secfile_is_same_file(const char *path1, const char *path2) {
    if (!path1 || !path2) {
        return false;
    }

    wchar_t *wpath1 = utf8_to_utf16(path1);
    wchar_t *wpath2 = utf8_to_utf16(path2);
    if (!wpath1 || !wpath2) {
        free(wpath1);
        free(wpath2);
        return false;
    }

    /* Check canonical normalized full paths */
    wchar_t full1[SECFILE_MAX_PATH] = {0};
    wchar_t full2[SECFILE_MAX_PATH] = {0};
    DWORD len1 = GetFullPathNameW(wpath1, SECFILE_MAX_PATH, full1, NULL);
    DWORD len2 = GetFullPathNameW(wpath2, SECFILE_MAX_PATH, full2, NULL);

    if (len1 > 0 && len2 > 0 && _wcsicmp(full1, full2) == 0) {
        free(wpath1);
        free(wpath2);
        return true;
    }

    /* Compare Windows file indexes and volume serial numbers */
    HANDLE h1 = CreateFileW(
        wpath1,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );

    if (h1 == INVALID_HANDLE_VALUE) {
        free(wpath1);
        free(wpath2);
        return false;
    }

    HANDLE h2 = CreateFileW(
        wpath2,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );

    free(wpath1);
    free(wpath2);

    if (h2 == INVALID_HANDLE_VALUE) {
        CloseHandle(h1);
        return false;
    }

    BY_HANDLE_FILE_INFORMATION info1, info2;
    BOOL ok1 = GetFileInformationByHandle(h1, &info1);
    BOOL ok2 = GetFileInformationByHandle(h2, &info2);

    CloseHandle(h1);
    CloseHandle(h2);

    if (ok1 && ok2) {
        if (info1.dwVolumeSerialNumber == info2.dwVolumeSerialNumber &&
            info1.nFileIndexHigh == info2.nFileIndexHigh &&
            info1.nFileIndexLow == info2.nFileIndexLow) {
            return true;
        }
    }

    return false;
}

secfile_error_t secfile_open_unique_temp_file(
    const char *dest_path,
    char *temp_path_out,
    size_t max_len,
    FILE **file_out
) {
    if (!dest_path || !temp_path_out || max_len < 32 || !file_out) {
        return SECFILE_ERR_INVALID_PARAM;
    }

    *file_out = NULL;
    DWORD pid = GetCurrentProcessId();

    /* Try up to 50 times with CSPRNG random suffixes to guarantee uniqueness */
    for (int attempt = 0; attempt < 50; attempt++) {
        uint32_t rand_val = 0;
        secfile_random_bytes((uint8_t *)&rand_val, sizeof(rand_val));

        int written = snprintf(
            temp_path_out,
            max_len,
            "%s.tmp.%lu.%08x",
            dest_path,
            (unsigned long)pid,
            rand_val
        );

        if (written < 0 || (size_t)written >= max_len) {
            return SECFILE_ERR_FILE_IO;
        }

        wchar_t *wtemp = utf8_to_utf16(temp_path_out);
        if (!wtemp) {
            return SECFILE_ERR_MEMORY;
        }

        /*
         * Open with CREATE_NEW and share mode 0 (exclusive):
         * - Guarantees file did not exist prior to this call.
         * - Prevents symlink/junction hijacking.
         * - Prevents collision with any existing file.
         */
        HANDLE hFile = CreateFileW(
            wtemp,
            GENERIC_READ | GENERIC_WRITE,
            0, /* Exclusive access: no other process can open or modify */
            NULL,
            CREATE_NEW, /* Fails if file or link already exists */
            FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_POSIX_SEMANTICS,
            NULL
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            free(wtemp);
            if (err == ERROR_FILE_EXISTS || err == ERROR_ALREADY_EXISTS) {
                /* Collision detected; retry with fresh random value */
                continue;
            }
            return SECFILE_ERR_FILE_IO;
        }

        /* Convert native OS HANDLE to C runtime FILE* */
        int fd = _open_osfhandle((intptr_t)hFile, _O_RDWR | _O_BINARY);
        if (fd == -1) {
            CloseHandle(hFile);
            DeleteFileW(wtemp);
            free(wtemp);
            continue;
        }

        FILE *f = _fdopen(fd, "w+b");
        if (!f) {
            _close(fd);
            DeleteFileW(wtemp);
            free(wtemp);
            continue;
        }

        free(wtemp);
        *file_out = f;
        return SECFILE_OK;
    }

    return SECFILE_ERR_FILE_IO;
}

secfile_error_t secfile_publish_file(const char *temp_path, const char *dest_path, bool overwrite) {
    if (!temp_path || !dest_path) {
        return SECFILE_ERR_INVALID_PARAM;
    }

    if (!overwrite && secfile_file_exists(dest_path)) {
        return SECFILE_ERR_FILE_EXISTS;
    }

    wchar_t *wtemp = utf8_to_utf16(temp_path);
    wchar_t *wdest = utf8_to_utf16(dest_path);
    if (!wtemp || !wdest) {
        free(wtemp);
        free(wdest);
        return SECFILE_ERR_MEMORY;
    }

    DWORD flags = MOVEFILE_COPY_ALLOWED;
    if (overwrite) {
        flags |= MOVEFILE_REPLACE_EXISTING;
    }

    BOOL success = MoveFileExW(wtemp, wdest, flags);
    DWORD last_err = GetLastError();

    free(wtemp);
    free(wdest);

    if (!success) {
        if (!overwrite && (last_err == ERROR_FILE_EXISTS || last_err == ERROR_ALREADY_EXISTS)) {
            return SECFILE_ERR_FILE_EXISTS;
        }
        return SECFILE_ERR_FILE_IO;
    }

    return SECFILE_OK;
}

void secfile_remove_file(const char *path) {
    if (path && *path != '\0') {
        wchar_t *wpath = utf8_to_utf16(path);
        if (wpath) {
            DeleteFileW(wpath);
            free(wpath);
        }
    }
}
