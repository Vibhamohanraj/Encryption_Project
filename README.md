# SecureFile — C File Encryption Tool

A beginner-friendly, hardened command-line file encryption and decryption application in C, targeting Windows systems. SecureFile uses **AES-256-GCM** for authenticated encryption, **Argon2id** for password-based key derivation, and comprehensive Windows filesystem safety protections.

---

## 1. Features

- **Authenticated Encryption**: Uses **AES-256-GCM** with a 256-bit key and 128-bit authentication tag to protect both confidentiality (privacy) and integrity (tamper detection).
- **Memory-Hard Key Derivation**: Uses **Argon2id** via libsodium to derive high-entropy 256-bit keys from user passwords, protecting against GPU/ASIC brute-force dictionary attacks.
- **Cryptographic Randomness**: Fresh 128-bit salt and 96-bit nonce per file generated via libsodium's CSPRNG (`randombytes_buf`), providing collision resistance under NIST SP 800-38D.
- **Cryptographic Header Binding (AAD)**: Encrypted file headers are bound as Additional Authenticated Data into the AES-GCM tag. Any tampering with metadata triggers authentication rejection.
- **Chunked Streaming I/O & 64-Bit Offsets**: Files are processed in bounded 64 KiB chunks with `_fseeki64`, supporting files exceeding 2 GiB without memory exhaustion.
- **Hardened Windows Filesystem Protections**:
  - Exclusive temporary file creation using `CreateFileW` with **`CREATE_NEW`** and `0` sharing mode to prevent symlink/junction hijacking and race conditions.
  - Never overwrites input files.
  - Refuses to overwrite existing output files by default (requires `--overwrite` or `-f`).
  - Deep same-file detection using Windows volume serial numbers and 64-bit file IDs.
  - Plaintext is published only after successful authentication tag verification. On failure, temporary decrypted files are deleted immediately and buffers are wiped.
  - Complete **Unicode (UTF-8)** file path support via Windows `*W` APIs.
- **Interactive & CLI Modes**: Supports an intuitive terminal menu as well as direct command-line arguments.
- **Masked Password Input**: Reads passwords securely without echoing to the terminal using Windows `_getch()`, with automatic fallback for non-interactive test pipes.

---

## 2. Directory Layout

```text
SecureFile/
├── src/                # Modular C source files
│   ├── main.c          # Application entry point, CLI parser, and interactive menu
│   ├── crypto.c        # AES-256-GCM chunked encryption/decryption
│   ├── format.c        # Binary container serialization & validation
│   ├── kdf.c           # Argon2id key derivation & secure memory wipe
│   ├── file_handler.c  # Safe file I/O, exclusive temp files, Unicode & same-file detection
│   ├── password.c      # Masked console password input for Windows
│   └── utils.c         # Error code description mappings
├── include/            # C header files (.h)
│   ├── common.h        # Constants, limits, and error codes
│   ├── crypto.h        # Encryption/decryption function declarations
│   ├── format.h        # Container header layout and serialize functions
│   ├── kdf.h           # Key derivation and memory zeroing declarations
│   ├── file_handler.h  # File existence, temp files, and publishing declarations
│   └── password.h      # Console password prompt declarations
├── tests/              # Automated verification & security regression test suite (22 tests)
│   └── test_main.c     # Comprehensive functional, security, and edge-case tests
├── docs/               # Technical specifications
│   ├── format.md       # Binary container layout & endianness rules
│   └── security.md     # Cryptographic threat model & safety assumptions
├── build/              # Generated binaries and object files (excluded from Git)
├── demo.bat            # Optional Windows CMD live demonstration script
├── Makefile            # Build configuration for MSYS2 UCRT64
├── AGENTS.md           # Mandatory rules for developers and AI agents
└── README.md           # Project documentation and guide
```

---

## 3. Prerequisites & Environment

The project is built using the **MSYS2 UCRT64** toolchain on Windows:
- **GCC**: 16.2+ (`mingw-w64-ucrt-x86_64-gcc`)
- **GNU Make**: 4.4+ (`mingw-w64-ucrt-x86_64-make`)
- **OpenSSL**: 3.x (`mingw-w64-ucrt-x86_64-openssl`)
- **libsodium**: 1.0.22+ (`mingw-w64-ucrt-x86_64-libsodium`)
- **pkgconf**: (`mingw-w64-ucrt-x86_64-pkgconf`)

### Setting Environment in Windows Command Prompt (CMD):
```cmd
set "PATH=C:\msys64\ucrt64\bin;C:\msys64\usr\bin;%PATH%"
```

### Setting Environment in Windows PowerShell:
```powershell
$env:PATH = "C:\msys64\ucrt64\bin;C:\msys64\usr\bin;$env:PATH"
```

---

## 4. Compilation & Build Instructions

Navigate to the `SecureFile` directory in Windows Command Prompt or PowerShell:

```cmd
cd "C:\Users\Nares\OneDrive\Desktop\New folder\Encryption_Project\SecureFile"
set "PATH=C:\msys64\ucrt64\bin;C:\msys64\usr\bin;%PATH%"

:: 1. Compile application binary (generates build\securefile.exe):
mingw32-make all

:: 2. Build and run automated 22-point security test suite:
mingw32-make test

:: 3. Clean build artifacts:
mingw32-make clean
```

---

## 5. Usage Guide

### Method A: Interactive Terminal Menu
Simply launch the binary without arguments:
```cmd
build\securefile.exe
```

The interactive menu will guide you step by step:
```text
========================================
      SecureFile - AES-256-GCM Tool     
========================================
1. Encrypt a file
2. Decrypt a file
3. Exit
----------------------------------------
Enter choice (1-3): 
```
- **Option 1 (Encrypt)**: Prompts for the source file path, destination path, and password (entered twice for confirmation without echoing characters).
- **Option 2 (Decrypt)**: Prompts for the encrypted file path, destination path, and decryption password.
- **Option 3 (Exit)**: Safely exits the program.

*(Tip: In Windows terminal, if you drag and drop a file or paste a path enclosed in quotes, SecureFile automatically trims surrounding quotes).*

### Method B: Command-Line (CLI) Mode
For scripting or fast terminal usage, arguments can be provided directly:

```cmd
:: 1. Encrypt a file:
build\securefile.exe --encrypt document.pdf document.pdf.sfe

:: 2. Encrypt and allow replacing an existing output file:
build\securefile.exe --encrypt document.pdf document.pdf.sfe --overwrite

:: 3. Decrypt a file:
build\securefile.exe --decrypt document.pdf.sfe restored_document.pdf

:: 4. View help/usage syntax:
build\securefile.exe --help
```

In CLI mode:
- Passwords are typed interactively without terminal echoing.
- Passwords can also be piped in automated environments (e.g. `type pass.txt | build\securefile.exe --decrypt test.sfe out.txt`).
- The program exits with status code `0` on success and `1` on failure, allowing automated error checking in Command Prompt (`%ERRORLEVEL%`) and PowerShell (`$LASTEXITCODE`).

---

## 6. Live Terminal Demonstration (Step-by-Step for CMD)

To demonstrate SecureFile live in front of a teacher, interviewer, or audience, you can either follow the manual terminal commands (Option A) or run the provided demonstration script (Option B).

### Option A: Step-by-Step Manual Demonstration (Windows CMD)

Run the following commands in Windows Command Prompt (`cmd.exe`) from the `SecureFile` directory:

#### Step 1: Ensure toolchain path is configured
```cmd
set "PATH=C:\msys64\ucrt64\bin;C:\msys64\usr\bin;%PATH%"
```

#### Step 2: Create and display the original readable plaintext
```cmd
echo MY SECRET MESSAGE 12345> demo_plain.txt
type demo_plain.txt
```
*Output*: Displays `MY SECRET MESSAGE 12345`.  
*Meaning*: Proves to the audience the original file content before encryption.

#### Step 3: Encrypt the file to an authenticated binary container
```cmd
build\securefile.exe --encrypt demo_plain.txt demo_encrypted.sfe
```
*(Enter and confirm your password when prompted; input characters are masked)*.  
*Meaning*: SecureFile derives a 256-bit key using Argon2id, generates a unique 16-byte salt and 12-byte nonce, encrypts the file using AES-256-GCM, and records a 16-byte authentication tag in the container.

#### Step 4: Display the actual encrypted bytes directly in the terminal
```cmd
certutil -encodehex demo_encrypted.sfe demo_hex.txt 4 >nul && type demo_hex.txt && del demo_hex.txt
```
*Meaning*: Displays the raw encrypted binary container in standard hexadecimal byte format directly on screen.  
> [!IMPORTANT]
> **Hexadecimal representation is NOT encryption**: Hexadecimal is simply a human-readable visual formatting of raw binary data. The actual cryptographic protection is provided by AES-256-GCM authenticated encryption and Argon2id key derivation. The container holds the 60-byte SecureFile header (magic bytes, version, Argon2id parameters, salt, and nonce), followed by ciphertext and the 16-byte GCM authentication tag.

#### Step 5: Decrypt the file with the correct password
```cmd
build\securefile.exe --decrypt demo_encrypted.sfe demo_recovered.txt
```
*(Enter the correct password used in Step 3)*.  
*Output*: `Success: File decrypted and authenticated successfully.`

#### Step 6: Display the recovered readable message
```cmd
type demo_recovered.txt
```
*Output*: Displays `MY SECRET MESSAGE 12345`.

#### Step 7: Compare original and recovered files byte-for-byte
```cmd
fc /b demo_plain.txt demo_recovered.txt
```
*Output*: `FC: no differences encountered`.  
*Meaning*: Proves 100% cryptographic data integrity and exact byte-for-byte recovery.

#### Step 8: Test security: reject incorrect password
```cmd
build\securefile.exe --decrypt demo_encrypted.sfe demo_wrong.txt
```
*(Type an intentional wrong password when prompted)*.  
*Output*: `Decryption failed: Authentication verification failed (incorrect password or corrupted/tampered file)`.  
*Meaning*: Demonstrates that AES-GCM authentication strictly rejects an invalid password without exposing decrypted data.

#### Step 9: Confirm no partial plaintext was published on failure
```cmd
if exist demo_wrong.txt (echo FAILED: Plaintext leaked) else (echo PASS: No plaintext created)
```
*Output*: `PASS: No plaintext created`.  
*Meaning*: Verifies SecureFile's atomic publishing design: decrypted plaintext is never written to the destination file unless the GCM authentication tag is completely verified.

#### Step 10: Clean up disposable demonstration files
```cmd
del demo_plain.txt demo_encrypted.sfe demo_recovered.txt
```
*Meaning*: Removes all disposable sample files created during the demonstration.

---

### Option B: Using the Included `demo.bat` Script

SecureFile provides an automated demonstration script (`demo.bat`) designed for live audience presentations and automated verification:

#### 1. Live Interactive Demonstration (Recommended for presentations):
Run `demo.bat` from Command Prompt or double-click `demo.bat` in Windows File Explorer:
```cmd
demo.bat
```
- Automatically checks compiler environment and builds `build\securefile.exe` if not already present.
- Detects existing demo files and prompts for confirmation before cleaning them up.
- Executes the complete demonstration workflow:
  1. Creates `demo_plain.txt` (`MY SECRET MESSAGE 12345`) and displays it with `type`.
  2. Runs encryption with masked interactive password prompts.
  3. Displays file metadata and hex byte dump using `certutil -encodehex ... 4`.
  4. Runs decryption with masked interactive password prompt.
  5. Displays the recovered plaintext with `type`.
  6. Executes `fc /b` to prove exact byte identity.
  7. Demonstrates wrong-password rejection and verifies non-zero exit code.
  8. Verifies that no plaintext file (`demo_wrong.txt`) was published.
  9. Offers prompt-confirmed cleanup of disposable demo files.
- **Terminal Window Persistence**: The script pauses at completion (`Press any key to exit...`) so the window remains open when launched via double-click from File Explorer.

#### 2. Automated Verification Mode (For fast CI / regression testing):
```cmd
demo.bat --auto
```
- Runs the full 9-step demonstration workflow non-interactively using self-contained test vectors.
- Verifies encryption, hex byte dump, decryption, `fc /b`, wrong-password rejection, zero plaintext leakage, and cleanup without manual prompts.
- Returns exit code 0 on complete success, or non-zero on any failure.

#### 3. Troubleshooting Demonstration Errors:
- **Terminal Closes Immediately**: Run `demo.bat` from an existing Command Prompt (`cmd.exe`) window, or ensure you are running the updated `demo.bat` which normalizes directories (`cd /d "%~dp0"`) and includes an end-of-script `pause`.
- **Missing DLL Error (`libcrypto-3-x64.dll` or `libsodium-26.dll`)**: Ensure MSYS2 UCRT64 is installed at `C:\msys64` or add its `bin` directory to your environment:
  ```cmd
  set "PATH=C:\msys64\ucrt64\bin;C:\msys64\usr\bin;%PATH%"
  ```
- **"certutil" Direct Output Error**: Direct invocation of `certutil -encodehex file CON 4` fails on modern Windows because `CON` redirection is unsupported by certutil. `demo.bat` reliably uses a temporary file (`demo_hex.txt`) to print the hex dump and immediately removes it.
- **Existing Demo Files**: If a prior run was interrupted, `demo.bat` detects existing demo files and asks before cleaning them, preventing accidental deletion of user data.

---

## 7. How the Code Works (Beginner-Friendly Explanation)

If you are new to C systems programming or cryptography, here is a simple overview of how SecureFile operates under the hood:

### 1. Key Derivation (`src/kdf.c`)
- **The Problem**: Human passwords (like `"MySecret123"`) have low entropy and can easily be guessed by specialized GPU clusters. Furthermore, AES requires a cryptographic 256-bit (32-byte) key.
- **The Solution**: SecureFile uses **Argon2id**, the modern standard for password hashing.
- **How It Works**:
  1. A fresh 16-byte random **salt** is generated for every encrypted file using a cryptographically secure random number generator (CSPRNG).
  2. Argon2id repeatedly mixes the password and salt across a 64 MiB memory block. Because it requires significant memory, attackers cannot run millions of parallel guesses on GPUs or ASICs.
  3. The result is an evenly distributed 32-byte binary key.
  4. Once the key is passed to OpenSSL, the key buffer in RAM is immediately wiped with `sodium_memzero()`.

### 2. Encryption and Authentication (`src/crypto.c`)
- **AES-256-GCM** (Galois/Counter Mode) performs **authenticated encryption**:
  - It encrypts the plaintext in 64 KiB chunks so files of any size (even multi-gigabyte files) can be processed without running out of RAM.
  - It computes a 16-byte cryptographic **Authentication Tag** at the end.
- **Header Binding via AAD (Additional Authenticated Data)**:
  - The 60-byte file header (magic identifier, version number, Argon2 parameters, salt, and nonce) is fed into AES-GCM as AAD.
  - The tag covers both the ciphertext **and** the header. If an attacker edits even one bit in the header or ciphertext, the tag will not match!

### 3. Verification Before Publishing (`src/crypto.c`)
- During decryption, SecureFile writes the decrypted data to a temporary file (`.tmp.<pid>.<random>`).
- Only after the entire file is decrypted does OpenSSL verify the authentication tag with `EVP_DecryptFinal_ex()`.
- **If authentication fails** (wrong password or corrupted/tampered file):
  - The temporary file is immediately deleted from disk.
  - All RAM buffers are wiped with zeroes.
  - **No unauthenticated plaintext is ever published to the destination file.**
- **If authentication succeeds**:
  - The temporary file is atomically moved to the final destination path via Windows `MoveFileExW`.

### 4. Windows Filesystem Safety (`src/file_handler.c`)
- **Exclusive Temporary Files**: Temporary files are created with Windows `CreateFileW` using `CREATE_NEW` and `0` sharing mode. This ensures that no existing file is clobbered, and malicious background processes cannot inject symlinks or race conditions.
- **Same-File Protection**: Before encrypting, SecureFile checks if the input and output refer to the same physical file (inspecting NTFS volume serial number and 64-bit file index), preventing accidental self-destruction.
- **Refuse to Overwrite by Default**: If an output file already exists, SecureFile will refuse to overwrite it unless you explicitly give permission.
- **Unicode Support**: All file paths support international characters (e.g., UTF-8 accented characters or emoji) through Windows wide-character (`wchar_t`) APIs.

---

## 8. Verification & Automated Testing

The automated test runner (`build\test_runner.exe`) executes 22 rigorous functional and security regression tests:

1. **Test 1**: Normal text file encryption and decryption round-trip.
2. **Test 2**: Binary file encryption spanning chunk boundaries (70 KiB).
3. **Test 3**: Empty (0-byte) file encryption and decryption.
4. **Test 4**: Incorrect password rejection and immediate temp file cleanup.
5. **Test 5**: Modified ciphertext tamper detection (auth tag failure).
6. **Test 6**: Modified authentication tag detection.
7. **Test 7**: Modified header metadata detection (AAD verification).
8. **Test 8**: Truncated encrypted file rejection.
9. **Test 9**: Unsupported file format version rejection.
10. **Test 10**: Missing input file error handling.
11. **Test 11**: Refusal to overwrite existing output files.
12. **Test 12**: Rejection when input and output refer to the same file.
13. **Test 13**: I/O error handling on invalid/unwritable destinations.
14. **Test 14**: Verification of zero dangling temporary files on failures.
15. **Test 15**: Nonce and salt uniqueness across repeated runs.
16. **Test 16**: Extreme and corrupted KDF metadata rejection.
17. **Test 17**: Unicode UTF-8 path handling.
18. **Test 18**: Exclusive temporary file creation & collision avoidance (`CREATE_NEW`).
19. **Test 19**: Large file streaming across many chunks (1 MiB / 16 chunks).
20. **Test 20**: Explicit overwrite permission handling (`--overwrite`).
21. **Test 21**: Zero plaintext published on truncated authentication tags.
22. **Test 22**: Non-existent output directory failure handling and cleanup.

### Actual Test Execution Output:
```text
====================================================
    SecureFile Automated Verification Suite         
====================================================
  [PASS] Test  1: Normal text encryption/decryption
  [PASS] Test  2: Binary file spanning chunk boundaries
  [PASS] Test  3: Empty file (0 bytes)
  [PASS] Test  4: Incorrect password rejection & cleanup
  [PASS] Test  5: Modified ciphertext tamper detection
  [PASS] Test  6: Modified authentication tag detection
  [PASS] Test  7: Modified header (AAD authentication check)
  [PASS] Test  8: Truncated file rejection
  [PASS] Test  9: Unsupported file version rejection
  [PASS] Test 10: Missing input file handling
  [PASS] Test 11: Refusal to overwrite existing output file
  [PASS] Test 12: Input and output referring to the same file
  [PASS] Test 13: I/O error handling on invalid destination
  [PASS] Test 14: Zero temporary file leaks on failure
  [PASS] Test 15: Nonce/salt uniqueness across repeated runs
  [PASS] Test 16: Extreme & corrupted KDF metadata rejection
  [PASS] Test 17: Unicode UTF-8 path handling
  [PASS] Test 18: Exclusive temp file creation & collision avoidance
  [PASS] Test 19: Large file streaming (1 MiB / 16 chunks)
  [PASS] Test 20: Explicit overwrite permission handling
  [PASS] Test 21: Zero plaintext published on auth tag truncation
  [PASS] Test 22: Non-existent output directory failure handling
----------------------------------------------------
Summary: 22 / 22 tests passed (100.0%)
====================================================
```

---

## 9. Limitations & Security Considerations

1. **Permanent Data Loss on Lost Password**:
   - SecureFile adheres strictly to modern cryptography standards. There are no backdoors, escrow keys, master passwords, or bypasses. If a password is lost or forgotten, the encrypted file is **permanently and irreversibly unrecoverable**.
2. **Single-File Operation**:
   - SecureFile is designed as a focused, lightweight mini project for individual files. It does not recurse into entire directory trees or create `.tar`/`.zip` archives. To encrypt an entire directory, compress the directory into an archive first (e.g. `.zip`) and then encrypt that archive.
3. **Temporary Disk Space Requirement**:
   - Because SecureFile verifies the authentication tag before publishing the final decrypted file, temporary disk space equal to the size of the decrypted file is needed during decryption.
4. **Toolchain Runtime DLL Dependency**:
   - On Windows, the binary depends on the MSYS2 UCRT64 dynamic libraries (`libcrypto-3-x64.dll`, `libsodium-26.dll`). Ensure `C:\msys64\ucrt64\bin` remains in your system or session `PATH` when executing the application.

---

## 10. Test Suite vs. Formal Security Audit

Passing an automated test suite is an essential engineering baseline, but it is important to understand the boundary:
- **What the 22 Automated Tests Prove**:
  - The software functions correctly according to its specifications.
  - Known edge cases (empty files, chunk boundary crossings, non-existent paths, invalid passwords, bit-flipped tags) behave as expected.
  - Regressions in memory management, error codes, and filesystem overwrite rules are caught.
- **What an Automated Test Suite Does Not Guarantee**:
  - It does not replace a **formal independent cryptographic audit**.
  - It cannot prove immunity against hardware-level side-channel analysis (such as CPU cache-timing or power consumption analysis), operating system kernel vulnerabilities, untrusted host processes (such as kernel keyloggers), or cold-boot memory extraction attacks.
- SecureFile implements audited, industry-standard cryptographic primitives (OpenSSL 3.x AES-GCM, libsodium Argon2id) following published NIST and cryptographic best practices, while maintaining realistic humility about what software-level unit tests can prove.
