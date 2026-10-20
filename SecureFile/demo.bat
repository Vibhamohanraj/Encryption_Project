@echo off
setlocal

:: Switch working directory to the folder containing this batch script
cd /d "%~dp0"

:: Ensure MSYS2 UCRT64 toolchain is in PATH
if exist "C:\msys64\ucrt64\bin" (
    set "PATH=C:\msys64\ucrt64\bin;C:\msys64\usr\bin;%PATH%"
)

:: Check for automated verification mode flag
set "AUTO_MODE=0"
if "%1"=="--auto" set "AUTO_MODE=1"
if "%1"=="-a" set "AUTO_MODE=1"

echo =================================================================
echo         SecureFile - Live Terminal Demonstration
echo =================================================================
echo.
if "%AUTO_MODE%"=="1" (
    echo [*] Mode: AUTOMATED verification
) else (
    echo [*] Mode: INTERACTIVE live demonstration
)
echo.

:: Check for required OpenSSL and libsodium runtime DLLs
where libcrypto-3-x64.dll >nul 2>nul
if errorlevel 1 (
    echo [!] WARNING: libcrypto-3-x64.dll was not found in PATH.
    echo [*] Ensure MSYS2 UCRT64 is installed or configured in PATH:
    echo     set "PATH=C:\msys64\ucrt64\bin;C:\msys64\usr\bin;%%PATH%%"
    echo.
)

where libsodium-26.dll >nul 2>nul
if errorlevel 1 (
    echo [!] WARNING: libsodium-26.dll was not found in PATH.
    echo [*] Ensure MSYS2 UCRT64 is installed or configured in PATH:
    echo     set "PATH=C:\msys64\ucrt64\bin;C:\msys64\usr\bin;%%PATH%%"
    echo.
)

:: Check if the executable is built; if not, compile it
if not exist "build\securefile.exe" (
    echo [*] Binary 'build\securefile.exe' was not found.
    echo [*] Attempting to compile SecureFile with mingw32-make...
    where mingw32-make >nul 2>nul
    if errorlevel 1 (
        echo [!] ERROR: mingw32-make was not found in PATH.
        echo [*] Please configure PATH to include your MSYS2 toolchain:
        echo     set "PATH=C:\msys64\ucrt64\bin;C:\msys64\usr\bin;%%PATH%%"
        goto err_build
    )
    call mingw32-make all
    if errorlevel 1 (
        echo [!] ERROR: Compilation failed. Please check build environment.
        goto err_build
    )
    echo [*] Compilation completed successfully.
    echo.
)

set "DEMO_IN=demo_plain.txt"
set "DEMO_ENC=demo_encrypted.sfe"
set "DEMO_DEC=demo_recovered.txt"
set "DEMO_BAD=demo_wrong.txt"
set "DEMO_HEX=demo_hex.txt"

:: Check for existing demo files from a previous run to avoid accidental overwrites
set "EXISTING_FOUND=0"
if exist "%DEMO_IN%" set "EXISTING_FOUND=1"
if exist "%DEMO_ENC%" set "EXISTING_FOUND=1"
if exist "%DEMO_DEC%" set "EXISTING_FOUND=1"
if exist "%DEMO_BAD%" set "EXISTING_FOUND=1"
if exist "%DEMO_HEX%" set "EXISTING_FOUND=1"

if "%EXISTING_FOUND%"=="1" (
    echo [!] Notice: Previous demonstration files were detected:
    if exist "%DEMO_IN%"  echo     - %DEMO_IN%
    if exist "%DEMO_ENC%" echo     - %DEMO_ENC%
    if exist "%DEMO_DEC%" echo     - %DEMO_DEC%
    if exist "%DEMO_BAD%" echo     - %DEMO_BAD%
    if exist "%DEMO_HEX%" echo     - %DEMO_HEX%
    if "%AUTO_MODE%"=="1" goto do_clean_prev
    echo.
    set /p "CLEAN_CONFIRM=Clean existing demonstration files and proceed? (Y/N): "
    if /i "%CLEAN_CONFIRM%"=="y" goto do_clean_prev
    if /i "%CLEAN_CONFIRM%"=="yes" goto do_clean_prev
    echo Demonstration cancelled to protect existing demonstration files.
    goto finish_clean

:do_clean_prev
    del /q "%DEMO_IN%" "%DEMO_ENC%" "%DEMO_DEC%" "%DEMO_BAD%" "%DEMO_HEX%" 2>nul
    echo [*] Previous demonstration files cleaned successfully.
    echo.
)

:: -------------------------------------------------------------
:: Step 1: Display the original readable message
:: -------------------------------------------------------------
echo ---------------------------------------------------------------
echo [Step 1] Original readable message (Plaintext)
echo ---------------------------------------------------------------
echo MY SECRET MESSAGE 12345 > "%DEMO_IN%"
echo File created: %DEMO_IN%
echo Original contents:
type "%DEMO_IN%"
echo.

:: -------------------------------------------------------------
:: Step 2: Encrypt the file
:: -------------------------------------------------------------
echo ---------------------------------------------------------------
echo [Step 2] Encrypting the file with AES-256-GCM + Argon2id
echo ---------------------------------------------------------------
if "%AUTO_MODE%"=="1" goto auto_encrypt
echo [*] Enter and confirm your encryption password [input is masked]:
build\securefile.exe --encrypt "%DEMO_IN%" "%DEMO_ENC%"
goto after_encrypt

:auto_encrypt
(echo DemoPassword123!& echo DemoPassword123!) | build\securefile.exe --encrypt "%DEMO_IN%" "%DEMO_ENC%"

:after_encrypt
if errorlevel 1 goto err_encrypt
if not exist "%DEMO_ENC%" goto err_enc_missing
echo [*] Encryption operation completed successfully.
echo [*] Encrypted file created: %DEMO_ENC%
dir "%DEMO_ENC%" | findstr /i "%DEMO_ENC%"
echo.

:: -------------------------------------------------------------
:: Step 3: Display actual encrypted bytes (Hexadecimal dump)
:: -------------------------------------------------------------
echo ---------------------------------------------------------------
echo [Step 3] Actual encrypted file data (Hexadecimal byte dump)
echo ---------------------------------------------------------------
echo [*] Inspecting the raw binary container with certutil -encodehex:
certutil -encodehex "%DEMO_ENC%" "%DEMO_HEX%" 4 >nul
if errorlevel 1 goto err_hex_dump
type "%DEMO_HEX%"
del /q "%DEMO_HEX%" 2>nul
echo.
echo [*] Note: The hexadecimal bytes above show the authenticated binary container:
echo     - Bytes 00-59: 60-byte container header (Magic 'SECFIL01', Version, Argon2id parameters, Salt, Nonce)
echo     - Middle bytes: AES-256-GCM ciphertext
echo     - Last 16 bytes: 128-bit cryptographic Authentication Tag
echo.

:: -------------------------------------------------------------
:: Step 4: Successful decryption
:: -------------------------------------------------------------
echo ---------------------------------------------------------------
echo [Step 4] Decrypting the file with the CORRECT password
echo ---------------------------------------------------------------
if "%AUTO_MODE%"=="1" goto auto_decrypt
echo [*] Enter the SAME password you chose in Step 2:
build\securefile.exe --decrypt "%DEMO_ENC%" "%DEMO_DEC%"
goto after_decrypt

:auto_decrypt
(echo DemoPassword123!) | build\securefile.exe --decrypt "%DEMO_ENC%" "%DEMO_DEC%"

:after_decrypt
if errorlevel 1 goto err_decrypt
if not exist "%DEMO_DEC%" goto err_dec_missing
echo [*] Decryption and authentication tag verification succeeded!
echo.

:: -------------------------------------------------------------
:: Step 5: Display recovered readable message
:: -------------------------------------------------------------
echo ---------------------------------------------------------------
echo [Step 5] Recovered readable message (Plaintext)
echo ---------------------------------------------------------------
echo Recovered contents:
type "%DEMO_DEC%"
echo.

:: -------------------------------------------------------------
:: Step 6: Byte-for-byte binary verification
:: -------------------------------------------------------------
echo ---------------------------------------------------------------
echo [Step 6] Byte-for-byte binary comparison (fc /b)
echo ---------------------------------------------------------------
echo Comparing '%DEMO_IN%' and '%DEMO_DEC%':
fc /b "%DEMO_IN%" "%DEMO_DEC%"
if errorlevel 1 goto err_compare
echo.
echo [*] PASS: Recovered file is 100%% identical to original (byte-for-byte match).
echo.

:: -------------------------------------------------------------
:: Step 7: Demonstrate incorrect-password rejection
:: -------------------------------------------------------------
echo ---------------------------------------------------------------
echo [Step 7] Security test: Attempting decryption with INCORRECT password
echo ---------------------------------------------------------------
if "%AUTO_MODE%"=="1" goto auto_wrong
echo [*] Type an intentional INCORRECT password when prompted:
build\securefile.exe --decrypt "%DEMO_ENC%" "%DEMO_BAD%"
goto after_wrong

:auto_wrong
(echo WrongPasswordXYZ!) | build\securefile.exe --decrypt "%DEMO_ENC%" "%DEMO_BAD%"

:after_wrong
if not errorlevel 1 goto err_wrong_accepted
echo.
echo [*] PASS: Decryption failed as expected [process returned non-zero error code].
echo.

:: -------------------------------------------------------------
:: Step 8: Confirm failed decryption did not publish plaintext
:: -------------------------------------------------------------
echo ---------------------------------------------------------------
echo [Step 8] Verifying no unauthenticated plaintext was published
echo ---------------------------------------------------------------
if exist "%DEMO_BAD%" goto err_plaintext_leaked
echo [*] PASS: Destination file '%DEMO_BAD%' was NOT created on disk.
echo [*] Verified: Zero unauthenticated plaintext is published on failure.
echo.

:: -------------------------------------------------------------
:: Step 9: Safe cleanup of temporary demonstration files
:: -------------------------------------------------------------
echo ---------------------------------------------------------------
echo [Step 9] Safe cleanup of temporary demonstration files
echo ---------------------------------------------------------------
del /q "%DEMO_IN%" "%DEMO_ENC%" "%DEMO_DEC%" "%DEMO_BAD%" "%DEMO_HEX%" 2>nul
echo [*] Removed all disposable demo files:
echo     - %DEMO_IN%
echo     - %DEMO_ENC%
echo     - %DEMO_DEC%
echo.

echo =================================================================
echo         Demonstration Completed Successfully!
echo =================================================================
set "EXIT_CODE=0"
goto finish

:: -------------------------------------------------------------
:: Error Handlers
:: -------------------------------------------------------------
:err_build
echo.
echo [!] ERROR: Could not locate or build 'build\securefile.exe'.
goto error_cleanup

:err_encrypt
echo.
echo [!] ERROR: Encryption failed or was cancelled by user.
goto error_cleanup

:err_enc_missing
echo.
echo [!] ERROR: Encrypted output file '%DEMO_ENC%' was not found on disk.
goto error_cleanup

:err_hex_dump
echo.
echo [!] ERROR: Failed to generate hexadecimal representation of encrypted file.
goto error_cleanup

:err_decrypt
echo.
echo [!] ERROR: Decryption failed with the correct password.
goto error_cleanup

:err_dec_missing
echo.
echo [!] ERROR: Decrypted output file '%DEMO_DEC%' was not found on disk.
goto error_cleanup

:err_compare
echo.
echo [!] ERROR: Binary comparison failed. Recovered file does not match original!
goto error_cleanup

:err_wrong_accepted
echo.
echo [!] SECURITY ALERT: Wrong password was accepted unexpectedly!
goto error_cleanup

:err_plaintext_leaked
echo.
echo [!] SECURITY ALERT: Plaintext file '%DEMO_BAD%' was created despite wrong password!
goto error_cleanup

:error_cleanup
del /q "%DEMO_IN%" "%DEMO_ENC%" "%DEMO_DEC%" "%DEMO_BAD%" "%DEMO_HEX%" 2>nul
echo.
echo =================================================================
echo         Demonstration Encountered An Error
echo =================================================================
set "EXIT_CODE=1"
goto finish

:finish_clean
set "EXIT_CODE=0"

:finish
if not "%AUTO_MODE%"=="1" (
    echo.
    echo Press any key to exit...
    pause >nul
)
exit /b %EXIT_CODE%
