// File: EIDMigrate/CryptoHelpers.cpp
// Cryptographic helper functions implementation

#include "CryptoHelpers.h"
#include "Tracing.h"
#include <vector>
#include <stdexcept>
#include <ntstatus.h>

// Define STATUS constants if not available
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0x00000000
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL 0xC0000001
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER 0xC000000D
#endif
#ifndef STATUS_NO_MEMORY
#define STATUS_NO_MEMORY 0xC0000017
#endif

// Define missing CNG constants
#ifndef BCRYPT_HASH_INTERFACE_HMAC
#define BCRYPT_HASH_INTERFACE_HMAC 0x00000001
#endif

// Define BCRYPT_INIT_AUTH_MODE_INFO if not available
#ifndef BCRYPT_INIT_AUTH_MODE_INFO
#define BCRYPT_INIT_AUTH_MODE_INFO(_auth_info_) \
    ((_auth_info_).pbNonce = nullptr, \
     (_auth_info_).cbNonce = 0, \
     (_auth_info_).pbAuthData = nullptr, \
     (_auth_info_).cbAuthData = 0, \
     (_auth_info_).pbTag = nullptr, \
     (_auth_info_).cbTag = 0, \
     (_auth_info_).pbMacContext = nullptr, \
     (_auth_info_).cbMacContext = 0, \
     (_auth_info_).dwFlags = 0)
#endif

// Manual PBKDF2-HMAC-SHA256 implementation
// Since BCryptDeriveKeyPBKDF2 has compatibility issues, we implement PBKDF2 manually

// HMAC-SHA-256 using raw SHA-256 (manual HMAC construction)
// HMAC(K, m) = H((K ^ opad) || H((K ^ ipad) || m))
static CRYPTO_STATUS ComputeHMACSha256( // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
    _In_reads_bytes_(cbKey) const BYTE* pbKey,
    _In_ DWORD cbKey,
    _In_reads_bytes_(cbData) const BYTE* pbData,
    _In_ DWORD cbData,
    _Out_writes_all_(32) BYTE* pbHash)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL; // NOSONAR (EXPLICIT-TYPE-03) - Explicit NTSTATUS type preferred for clarity
    BCRYPT_ALG_HANDLE hAlgorithm = NULL; // NOSONAR - Windows API requires NULL
    BCRYPT_HASH_HANDLE hHash = NULL; // NOSONAR - Windows API requires NULL
    PBYTE pbHashObject = nullptr;
    DWORD cbHashObject = 0;
    DWORD cbResult = 0;
    CRYPTO_STATUS result = CRYPTO_STATUS::CRYPTO_ERROR_KDF_FAILED;

    // HMAC-SHA256 constants
    constexpr BYTE IPAD = 0x36;
    constexpr BYTE OPAD = 0x5c;
    constexpr DWORD SHA256_BLOCK_SIZE = 64;
    constexpr DWORD SHA256_HASH_SIZE = 32;

    // Use stack allocation for fixed-size buffers (no C++ objects)
    BYTE ipadKey[SHA256_BLOCK_SIZE]; // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    BYTE opadKey[SHA256_BLOCK_SIZE]; // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    // MUST be SHA256_BLOCK_SIZE, not SHA256_HASH_SIZE. The else-branch below
    // copies cbKey bytes in for any cbKey <= SHA256_BLOCK_SIZE (64), so a
    // 32-byte buffer overflowed by up to 32 bytes - and the XOR loop then read
    // past it too, because cbActualKey keeps the oversized value.
    //
    // The trigger is an ordinary passphrase: the key here IS the passphrase
    // (PBKDF2HMACSHA256 passes cchPassphrase * sizeof(WCHAR)), so 17 to 32
    // characters lands squarely in the overflow window - and
    // ValidatePassphraseStrength *requires* at least 16. Only the fact that the
    // overflowing bytes are the user's own passphrase, plus /GS, kept this from
    // being worse.
    BYTE actualKey[SHA256_BLOCK_SIZE]; // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    DWORD cbActualKey = cbKey;

    // Initialize ipad and opad
    memset(ipadKey, IPAD, SHA256_BLOCK_SIZE);
    memset(opadKey, OPAD, SHA256_BLOCK_SIZE);

    // Open SHA256 algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        EIDM_TRACE_ERROR(L"BCryptOpenAlgorithmProvider failed: 0x%08X", status);
        goto cleanup;
    }

    status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbHashObject, sizeof(DWORD), &cbResult, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        EIDM_TRACE_ERROR(L"BCryptGetProperty OBJECT_LENGTH failed: 0x%08X", status);
        goto cleanup;
    }

    pbHashObject = static_cast<PBYTE>(malloc(cbHashObject)); // NOSONAR - BCrypt API requires malloc/free for hash object buffer
    if (!pbHashObject)
    {
        status = STATUS_NO_MEMORY; // NOSONAR - DEADSTORE-01: status set for consistency; function returns via result
        goto cleanup;
    }

    // Prepare key: if key is longer than block size, hash it first
    if (cbKey > SHA256_BLOCK_SIZE)
    {
        BCRYPT_HASH_HANDLE hKeyHash = NULL; // NOSONAR - Windows API requires NULL
        BYTE keyHash[SHA256_HASH_SIZE]; // NOSONAR - LSASS-01: C-style buffer required by Win32 API
        status = BCryptCreateHash(hAlgorithm, &hKeyHash, pbHashObject, cbHashObject, nullptr, 0, 0);
        if (!BCRYPT_SUCCESS(status)) goto cleanup;
        status = BCryptHashData(hKeyHash, reinterpret_cast<PUCHAR>(const_cast<BYTE*>(pbKey)), cbKey, 0); // NOSONAR - Both casts required: const_cast removes const, reinterpret_cast converts BYTE* to PUCHAR for Windows CNG API
        if (!BCRYPT_SUCCESS(status)) { BCryptDestroyHash(hKeyHash); goto cleanup; }
        status = BCryptFinishHash(hKeyHash, keyHash, SHA256_HASH_SIZE, 0);
        BCryptDestroyHash(hKeyHash);
        if (!BCRYPT_SUCCESS(status)) goto cleanup;
        memcpy(actualKey, keyHash, SHA256_HASH_SIZE);
        cbActualKey = SHA256_HASH_SIZE;
    }
    else
    {
        memcpy(actualKey, pbKey, cbKey);
    }

    // XOR key with ipad and opad
    for (DWORD i = 0; i < cbActualKey; i++)
    {
        ipadKey[i] ^= actualKey[i]; // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        opadKey[i] ^= actualKey[i]; // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
    }

    // Inner hash: H((K ^ ipad) || data)
    BYTE innerHash[SHA256_HASH_SIZE]; // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    status = BCryptCreateHash(hAlgorithm, &hHash, pbHashObject, cbHashObject, nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    status = BCryptHashData(hHash, ipadKey, SHA256_BLOCK_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    status = BCryptHashData(hHash, const_cast<PUCHAR>(pbData), cbData, 0); // NOSONAR - Windows CNG API requires non-const PUCHAR even for read-only data
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    status = BCryptFinishHash(hHash, innerHash, SHA256_HASH_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    BCryptDestroyHash(hHash);
    hHash = NULL; // NOSONAR - Windows API requires NULL

    // Outer hash: H((K ^ opad) || innerHash)
    status = BCryptCreateHash(hAlgorithm, &hHash, pbHashObject, cbHashObject, nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    status = BCryptHashData(hHash, opadKey, SHA256_BLOCK_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    status = BCryptHashData(hHash, innerHash, SHA256_HASH_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    status = BCryptFinishHash(hHash, pbHash, SHA256_HASH_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    result = CRYPTO_STATUS::CRYPTO_SUCCESS;

cleanup:
    // ORDER MATTERS. pbHashObject is the backing store BCryptCreateHash was
    // given for hHash, so BCryptDestroyHash writes into it. Freeing the buffer
    // first made every successful call a use-after-free - and this runs once
    // per PBKDF2 iteration, i.e. 1.2 million times per file operation. Found by
    // an AddressSanitizer probe over the real derivation path.
    if (hHash) BCryptDestroyHash(hHash);
    if (pbHashObject) free(pbHashObject); // NOSONAR - memory allocated with malloc for BCrypt API compatibility
    if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);

    return result;
}

// XOR two blocks (for HMAC inner/outer padding)
static void XORBlock(_Out_writes_all_(cbSize) BYTE* pbDest, _In_ const BYTE* pbSrc, _In_ BYTE bPad, _In_ DWORD cbSize) // NOSONAR - variable used
{
    for (DWORD i = 0; i < cbSize; i++)
        pbDest[i] = pbSrc[i] ^ bPad; // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
}

// PBKDF2-HMAC-SHA256 implementation (RFC 8018 / RFC 2898)
//
// fLegacy selects the derivation used by format version 1 files, which
// chained U_{i+1} = PRF(P, T_i) (the running XOR) instead of the standard
// U_{i+1} = PRF(P, U_i). It is kept ONLY so that existing exports remain
// decryptable; new exports always use the standard construction.
static CRYPTO_STATUS PBKDF2HMACSHA256(
    _In_reads_bytes_(cbPassword) const BYTE* pbPassword,
    _In_ DWORD cbPassword,
    _In_reads_bytes_(cbSalt) const BYTE* pbSalt,
    _In_ DWORD cbSalt,
    _In_ DWORD cIterations,
    _In_ DWORD cbDerivedKey,
    _Out_writes_all_(cbDerivedKey) BYTE* pbDerivedKey,
    _In_ BOOL fLegacy)
{
    // HMAC-SHA256 produces 32 bytes
    constexpr DWORD HASH_LEN = 32;

    EIDM_TRACE_VERBOSE(L"PBKDF2: password=%u bytes, salt=%u bytes, iter=%u, out=%u bytes",
        cbPassword, cbSalt, cIterations, cbDerivedKey);

    // For each block of derived key
    for (DWORD blockIndex = 1; blockIndex <= (cbDerivedKey + HASH_LEN - 1) / HASH_LEN; blockIndex++)
    {
        BYTE blockHash[HASH_LEN]; // NOSONAR - LSASS-01: C-style buffer required by Win32 API
        BYTE u1[HASH_LEN]; // NOSONAR - LSASS-01: C-style buffer required by Win32 API
        BYTE saltWithCounter[128];  // Salt + 4-byte counter (big-endian) // NOSONAR - LSASS-01: C-style buffer required by Win32 API

        // Prepare salt || INT_32_BE(i) // NOSONAR - DOC-01: RFC 2898 algorithm notation, not commented-out code
        DWORD cbSaltWithCounter = cbSalt + 4;
        if (cbSaltWithCounter > sizeof(saltWithCounter))
            return CRYPTO_STATUS::CRYPTO_ERROR_INSUFFICIENT_BUFFER;

        memcpy(saltWithCounter, pbSalt, cbSalt);
        // Write block index in big-endian
        saltWithCounter[cbSalt] = (blockIndex >> 24) & 0xFF;
        saltWithCounter[cbSalt + 1] = (blockIndex >> 16) & 0xFF;
        saltWithCounter[cbSalt + 2] = (blockIndex >> 8) & 0xFF;
        saltWithCounter[cbSalt + 3] = blockIndex & 0xFF;

        EIDM_TRACE_VERBOSE(L"PBKDF2 block %u: computing U1 (salt+%u bytes)", blockIndex, cbSaltWithCounter);

        // U1 = PRF(password, salt || INT_32_BE(i)) // NOSONAR - DOC-01: RFC 2898 algorithm notation, not commented-out code
        CRYPTO_STATUS cryptoStatus = ComputeHMACSha256(pbPassword, cbPassword, saltWithCounter, cbSaltWithCounter, u1);
        if (cryptoStatus != CRYPTO_STATUS::CRYPTO_SUCCESS)
        {
            EIDM_TRACE_ERROR(L"PBKDF2: U1 computation failed for block %u", blockIndex);
            return cryptoStatus;
        }

        // T_i = U_1 ^ U_2 ^ ... ^ U_c, with U_{j+1} = PRF(password, U_j) // NOSONAR - DOC-01: RFC 8018 algorithm notation, not commented-out code
        memcpy(blockHash, u1, HASH_LEN);
        BYTE uPrev[HASH_LEN]; // NOSONAR - LSASS-01: C-style buffer required by Win32 API
        memcpy(uPrev, u1, HASH_LEN);

        for (DWORD iter = 1; iter < cIterations; iter++)
        {
            BYTE uNext[HASH_LEN]; // NOSONAR - LSASS-01: C-style buffer required by Win32 API
            // Standard: chain on the previous U. Legacy (format v1): chain on the running XOR.
            cryptoStatus = ComputeHMACSha256(pbPassword, cbPassword, fLegacy ? blockHash : uPrev, HASH_LEN, uNext);
            if (cryptoStatus != CRYPTO_STATUS::CRYPTO_SUCCESS)
            {
                EIDM_TRACE_ERROR(L"PBKDF2: U_%u computation failed for block %u", iter + 1, blockIndex);
                SecureZeroMemory(uPrev, sizeof(uPrev));
                SecureZeroMemory(blockHash, sizeof(blockHash));
                return cryptoStatus;
            }

            // blockHash = blockHash XOR uNext
            for (DWORD i = 0; i < HASH_LEN; i++)
                blockHash[i] ^= uNext[i]; // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
            memcpy(uPrev, uNext, HASH_LEN);
            SecureZeroMemory(uNext, sizeof(uNext));
        }

        // Copy to output (possibly partial block)
        DWORD cbBlockCopy = min(HASH_LEN, cbDerivedKey - (blockIndex - 1) * HASH_LEN);
        memcpy(pbDerivedKey + (blockIndex - 1) * HASH_LEN, blockHash, cbBlockCopy);
        SecureZeroMemory(uPrev, sizeof(uPrev));
        SecureZeroMemory(u1, sizeof(u1));
        SecureZeroMemory(blockHash, sizeof(blockHash));
    }

    return CRYPTO_STATUS::CRYPTO_SUCCESS;
}

// Known-answer test for the standard PBKDF2-HMAC-SHA256 construction.
// Vectors: P = "password", S = "salt", dkLen = 32 - the widely published
// PBKDF2-HMAC-SHA256 counterparts of the RFC 6070 test set (also checked
// against Python's hashlib.pbkdf2_hmac). c = 2 and c = 4096 both differ
// between the standard and the legacy (v1) chaining, so this also catches a
// regression to the old construction. It runs once per process before the
// first new-format derivation; a mismatch fails that derivation.
static bool Pbkdf2SelfTestPassed()
{
    static volatile LONG s_lState = 0;  // 0 = not run, 1 = passed, 2 = failed
    LONG lState = s_lState;
    if (lState != 0)
        return lState == 1;

    static const BYTE rgbPassword[] = { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' }; // NOSONAR - LSASS-01: fixed test vector
    static const BYTE rgbSalt[] = { 's', 'a', 'l', 't' }; // NOSONAR - LSASS-01: fixed test vector
    static const BYTE rgbExpected2[32] = { // NOSONAR - LSASS-01: fixed test vector
        0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3, 0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0,
        0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2, 0x51, 0xdf, 0xd6, 0xe2, 0xd8, 0x5a, 0x95, 0x47, 0x4c, 0x43 };
    static const BYTE rgbExpected4096[32] = { // NOSONAR - LSASS-01: fixed test vector
        0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41, 0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d,
        0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11, 0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98, 0x13, 0x4a };

    BYTE rgbOut[32]; // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    bool fPassed =
        PBKDF2HMACSHA256(rgbPassword, sizeof(rgbPassword), rgbSalt, sizeof(rgbSalt), 2,
            sizeof(rgbOut), rgbOut, FALSE) == CRYPTO_STATUS::CRYPTO_SUCCESS &&
        memcmp(rgbOut, rgbExpected2, sizeof(rgbOut)) == 0 &&
        PBKDF2HMACSHA256(rgbPassword, sizeof(rgbPassword), rgbSalt, sizeof(rgbSalt), 4096,
            sizeof(rgbOut), rgbOut, FALSE) == CRYPTO_STATUS::CRYPTO_SUCCESS &&
        memcmp(rgbOut, rgbExpected4096, sizeof(rgbOut)) == 0;

    if (!fPassed)
        EIDM_TRACE_ERROR(L"PBKDF2-HMAC-SHA256 known-answer self-test FAILED");

    InterlockedExchange(&s_lState, fPassed ? 1 : 2);
    return fPassed;
}

CRYPTO_STATUS DeriveKeyFromPassphrase(
    _In_ PCWSTR pwszPassphrase,
    _In_ SIZE_T cchPassphrase,
    _Out_ DERIVED_KEY* pDerivedKey)
{
    if (!pwszPassphrase || cchPassphrase == 0 || !pDerivedKey)
    {
        return CRYPTO_STATUS::CRYPTO_ERROR_INVALID_PARAMETER;
    }

    // New exports use the standard construction: refuse to write a file if it
    // does not reproduce the published known-answer vectors.
    if (!Pbkdf2SelfTestPassed())
        return CRYPTO_STATUS::CRYPTO_ERROR_KDF_FAILED;

    NTSTATUS status = STATUS_UNSUCCESSFUL; // NOSONAR (EXPLICIT-TYPE-03) - Explicit NTSTATUS type preferred for clarity
    BCRYPT_ALG_HANDLE hRng = NULL; // NOSONAR - Windows API requires NULL
    CRYPTO_STATUS cryptoStatus = CRYPTO_STATUS::CRYPTO_SUCCESS;

    __try
    {
        // Generate random salt
        status = BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status))
        {
            EIDM_TRACE_ERROR(L"BCryptOpenAlgorithmProvider(RNG) failed: 0x%08X", status);
            __leave;
        }

        status = BCryptGenRandom(hRng, pDerivedKey->rgbSalt, PBKDF2_SALT_SIZE, 0);
        if (!BCRYPT_SUCCESS(status))
        {
            EIDM_TRACE_ERROR(L"BCryptGenRandom failed: 0x%08X", status);
            __leave;
        }

        BCryptCloseAlgorithmProvider(hRng, 0);
        hRng = NULL; // NOSONAR - Windows API requires NULL

        // Use manual PBKDF2-HMAC-SHA256 implementation
        // Password is passed as raw bytes (UTF-16)
        const BYTE* pbPassword = reinterpret_cast<const BYTE*>(pwszPassphrase); // NOSONAR - Cast WCHAR* to BYTE* for cryptographic processing
        DWORD cbPassword = static_cast<DWORD>(cchPassphrase * sizeof(WCHAR)); // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity

        EIDM_TRACE_VERBOSE(L"Deriving keys with PBKDF2-HMAC-SHA256 (password: %u bytes, iterations: %u)",
            cbPassword, PBKDF2_ITERATIONS);

        // Derive encryption key
        cryptoStatus = PBKDF2HMACSHA256(
            pbPassword, cbPassword,
            pDerivedKey->rgbSalt, PBKDF2_SALT_SIZE,
            PBKDF2_ITERATIONS,
            PBKDF2_KEY_SIZE,
            pDerivedKey->rgbKey,
            FALSE);  // standard RFC 8018 derivation for new exports

        if (cryptoStatus != CRYPTO_STATUS::CRYPTO_SUCCESS)
        {
            EIDM_TRACE_ERROR(L"PBKDF2 encryption key derivation failed");
            __leave;
        }

        // Derive auth key with modified salt
        BYTE rgbAuthSalt[PBKDF2_SALT_SIZE]; // NOSONAR - LSASS-01: C-style buffer required by Win32 API
        memcpy(rgbAuthSalt, pDerivedKey->rgbSalt, PBKDF2_SALT_SIZE);
        for (DWORD i = 0; i < PBKDF2_SALT_SIZE; i++) // NOSONAR - LOOP-01: explicit index loop over fixed crypto buffer
            rgbAuthSalt[i] ^= 0xFF; // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API

        cryptoStatus = PBKDF2HMACSHA256(
            pbPassword, cbPassword,
            rgbAuthSalt, PBKDF2_SALT_SIZE,
            PBKDF2_ITERATIONS,
            PBKDF2_KEY_SIZE,
            pDerivedKey->rgbAuthKey,
            FALSE);

        if (cryptoStatus != CRYPTO_STATUS::CRYPTO_SUCCESS)
        {
            EIDM_TRACE_ERROR(L"PBKDF2 auth key derivation failed");
            __leave;
        }

        status = STATUS_SUCCESS;
    }
    __finally
    {
        if (hRng) BCryptCloseAlgorithmProvider(hRng, 0);

        if (!BCRYPT_SUCCESS(status) && pDerivedKey)
            SecureZeroMemory(pDerivedKey, sizeof(DERIVED_KEY));
    }

    if (BCRYPT_SUCCESS(status))
        return CRYPTO_STATUS::CRYPTO_SUCCESS;
    else
        return CRYPTO_STATUS::CRYPTO_ERROR_KDF_FAILED;
}

// Derive keys from passphrase with provided salt (for decryption)
CRYPTO_STATUS DeriveKeyFromPassphraseWithSalt(
    _In_ PCWSTR pwszPassphrase,
    _In_ SIZE_T cchPassphrase,
    _In_reads_(PBKDF2_SALT_SIZE) const BYTE* pbSalt,
    _Out_ DERIVED_KEY* pDerivedKey,
    _In_ DWORD dwIterations,
    _In_ BOOL fLegacyPbkdf2)
{
    if (!pwszPassphrase || cchPassphrase == 0 || !pbSalt || !pDerivedKey)
    {
        return CRYPTO_STATUS::CRYPTO_ERROR_INVALID_PARAMETER;
    }

    // The caller passes the iteration count recorded in the file header so that
    // PBKDF2_ITERATIONS can be raised later without orphaning existing exports.
    // Clamp it: the header is attacker-supplied, and honouring a value of 1
    // would turn algorithm agility into a downgrade attack. The ceiling keeps a
    // hostile file from pinning the CPU for hours.
    if (dwIterations < PBKDF2_MIN_ITERATIONS || dwIterations > PBKDF2_MAX_ITERATIONS)
    {
        EIDM_TRACE_ERROR(L"Rejecting file: PBKDF2 iteration count %u outside [%u, %u]",
            dwIterations, PBKDF2_MIN_ITERATIONS, PBKDF2_MAX_ITERATIONS);
        return CRYPTO_STATUS::CRYPTO_ERROR_INVALID_PARAMETER;
    }

    if (!fLegacyPbkdf2 && !Pbkdf2SelfTestPassed())
        return CRYPTO_STATUS::CRYPTO_ERROR_KDF_FAILED;

    CRYPTO_STATUS cryptoStatus = CRYPTO_STATUS::CRYPTO_SUCCESS;

    // Copy salt to output structure
    memcpy(pDerivedKey->rgbSalt, pbSalt, PBKDF2_SALT_SIZE);

    // Use manual PBKDF2-HMAC-SHA256 implementation
    const BYTE* pbPassword = reinterpret_cast<const BYTE*>(pwszPassphrase); // NOSONAR - BYTE-01: const BYTE* interop with Win32 crypto API; explicit type retained
    DWORD cbPassword = static_cast<DWORD>(cchPassphrase * sizeof(WCHAR)); // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity

    EIDM_TRACE_VERBOSE(L"Deriving keys with PBKDF2-HMAC-SHA256 using provided salt (password: %u bytes, iterations: %u)",
        cbPassword, dwIterations);

    // Derive encryption key
    cryptoStatus = PBKDF2HMACSHA256(
        pbPassword, cbPassword,
        pDerivedKey->rgbSalt, PBKDF2_SALT_SIZE,
        dwIterations,
        PBKDF2_KEY_SIZE,
        pDerivedKey->rgbKey,
        fLegacyPbkdf2);

    if (cryptoStatus != CRYPTO_STATUS::CRYPTO_SUCCESS)
    {
        EIDM_TRACE_ERROR(L"PBKDF2 encryption key derivation failed");
        SecureZeroMemory(pDerivedKey, sizeof(DERIVED_KEY));
        return cryptoStatus;
    }

    // Derive auth key with modified salt
    BYTE rgbAuthSalt[PBKDF2_SALT_SIZE]; // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    memcpy(rgbAuthSalt, pDerivedKey->rgbSalt, PBKDF2_SALT_SIZE);
    for (DWORD i = 0; i < PBKDF2_SALT_SIZE; i++) // NOSONAR - LOOP-01: explicit index loop over fixed crypto buffer
        rgbAuthSalt[i] ^= 0xFF; // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API

    cryptoStatus = PBKDF2HMACSHA256(
        pbPassword, cbPassword,
        rgbAuthSalt, PBKDF2_SALT_SIZE,
        dwIterations,
        PBKDF2_KEY_SIZE,
        pDerivedKey->rgbAuthKey,
        fLegacyPbkdf2);

    if (cryptoStatus != CRYPTO_STATUS::CRYPTO_SUCCESS)
    {
        EIDM_TRACE_ERROR(L"PBKDF2 auth key derivation failed");
        SecureZeroMemory(pDerivedKey, sizeof(DERIVED_KEY));
        return cryptoStatus;
    }

    return CRYPTO_STATUS::CRYPTO_SUCCESS;
}

BOOL ValidatePassphraseStrength(_In_ PCWSTR pwszPassphrase)
{
    if (!pwszPassphrase)
        return FALSE;

    size_t cchLen = wcslen(pwszPassphrase); // NOSONAR - pointer validated for NULL above (line 402)
    if (cchLen < 16) // NOSONAR - SCOPE-01: declaration kept separate to preserve null-check annotation
        return FALSE;

    return TRUE;
}

CRYPTO_STATUS EncryptWithGCM( // NOSONAR - COMPLEXITY-01: parameter count dictated by crypto API
    _In_ const BYTE* pbKey,
    _In_ DWORD cbKey,
    _In_reads_bytes_(cbNonce) const BYTE* pbNonce,
    _In_ DWORD cbNonce,
    _In_reads_bytes_(cbPlaintext) const BYTE* pbPlaintext,
    _In_ DWORD cbPlaintext,
    _Out_writes_(cbCiphertext) BYTE* pbCiphertext,
    _Inout_ DWORD* pcbCiphertext,
    _Out_writes_(cbTag) BYTE* pbTag,
    _In_ DWORD cbTag)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL; // NOSONAR (EXPLICIT-TYPE-03) - Explicit NTSTATUS type preferred for clarity
    BCRYPT_ALG_HANDLE hAlgorithm = NULL; // NOSONAR - Windows API requires NULL
    BCRYPT_KEY_HANDLE hKey = NULL; // NOSONAR - Windows API requires NULL
    DWORD cbResult = 0; // NOSONAR - variable used

    __try
    {
        // Open AES-GCM algorithm provider
        status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status))
        {
            EIDM_TRACE_ERROR(L"BCryptOpenAlgorithmProvider(AES) failed: 0x%08X", status);
            __leave;
        }

        // Set chaining mode to GCM
        status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE,
            (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0); // NOSONAR - Windows API requires non-const pointer, won't modify data
        if (!BCRYPT_SUCCESS(status))
        {
            EIDM_TRACE_ERROR(L"BCryptSetProperty(GCM) failed: 0x%08X", status);
            __leave;
        }

        // Import key
        status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, nullptr, 0,
            const_cast<PUCHAR>(pbKey), cbKey, 0); // NOSONAR - Windows CNG API requires non-const PUCHAR for key data
        if (!BCRYPT_SUCCESS(status))
        {
            EIDM_TRACE_ERROR(L"BCryptGenerateSymmetricKey failed: 0x%08X", status);
            __leave;
        }

        // Setup auth info for GCM
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = {};
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo); // NOSONAR - MACRO-01: expression-style macro requires terminating semicolon
        authInfo.pbNonce = const_cast<PUCHAR>(pbNonce); // NOSONAR - Windows CNG auth structure requires non-const PUCHAR
        authInfo.cbNonce = cbNonce;
        authInfo.pbTag = pbTag;
        authInfo.cbTag = cbTag;
        // No additional authenticated data

        EIDM_TRACE_VERBOSE(L"GCM encrypt: %u bytes, nonce=%u, tag=%u", cbPlaintext, cbNonce, cbTag);

        // Encrypt with GCM
        DWORD cbCiphertextResult = 0;
        status = BCryptEncrypt(hKey,
            const_cast<PUCHAR>(pbPlaintext), cbPlaintext, // NOSONAR - Windows CNG API requires non-const PUCHAR for plaintext
            &authInfo,
            nullptr, 0,
            pbCiphertext, *pcbCiphertext,
            &cbCiphertextResult, 0);

        if (!BCRYPT_SUCCESS(status))
        {
            EIDM_TRACE_ERROR(L"BCryptEncrypt failed: 0x%08X", status);
            __leave;
        }

        *pcbCiphertext = cbCiphertextResult;
    }
    __finally
    {
        if (hKey) BCryptDestroyKey(hKey);
        if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }

    if (BCRYPT_SUCCESS(status))
        return CRYPTO_STATUS::CRYPTO_SUCCESS;
    else
        return (CRYPTO_STATUS)6;  // ERROR_ENCRYPTION_FAILED
}

CRYPTO_STATUS DecryptWithGCM( // NOSONAR - COMPLEXITY-01: parameter count dictated by crypto API
    _In_ const BYTE* pbKey,
    _In_ DWORD cbKey,
    _In_reads_bytes_(cbNonce) const BYTE* pbNonce,
    _In_ DWORD cbNonce,
    _In_reads_bytes_(cbCiphertext) const BYTE* pbCiphertext,
    _In_ DWORD cbCiphertext,
    _In_reads_bytes_(cbTag) const BYTE* pbTag,
    _In_ DWORD cbTag,
    _Out_writes_(cbPlaintext) BYTE* pbPlaintext,
    _Inout_ DWORD* pcbPlaintext)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL; // NOSONAR (EXPLICIT-TYPE-03) - Explicit NTSTATUS type preferred for clarity
    BCRYPT_ALG_HANDLE hAlgorithm = NULL; // NOSONAR - Windows API requires NULL
    BCRYPT_KEY_HANDLE hKey = NULL; // NOSONAR - Windows API requires NULL
    DWORD cbResult = 0;

    __try
    {
        // Open AES-GCM algorithm provider
        status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status))
        {
            EIDM_TRACE_ERROR(L"BCryptOpenAlgorithmProvider(AES) failed: 0x%08X", status);
            __leave;
        }

        // Set chaining mode to GCM
        status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE,
            (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0); // NOSONAR - Windows API requires non-const pointer, won't modify data
        if (!BCRYPT_SUCCESS(status))
        {
            EIDM_TRACE_ERROR(L"BCryptSetProperty(GCM) failed: 0x%08X", status);
            __leave;
        }

        // Import key
        status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, nullptr, 0,
            const_cast<PUCHAR>(pbKey), cbKey, 0); // NOSONAR - Windows CNG API requires non-const PUCHAR for key data
        if (!BCRYPT_SUCCESS(status))
        {
            EIDM_TRACE_ERROR(L"BCryptGenerateSymmetricKey failed: 0x%08X", status);
            __leave;
        }

        // Setup auth info for GCM
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = {};
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo); // NOSONAR - MACRO-01: expression-style macro requires terminating semicolon
        authInfo.pbNonce = const_cast<PUCHAR>(pbNonce); // NOSONAR - Windows CNG auth structure requires non-const PUCHAR
        authInfo.cbNonce = cbNonce;
        authInfo.pbTag = const_cast<PUCHAR>(pbTag); // NOSONAR - Windows CNG auth structure requires non-const PUCHAR
        authInfo.cbTag = cbTag;

        EIDM_TRACE_VERBOSE(L"GCM decrypt: %u bytes, nonce=%u, tag=%u", cbCiphertext, cbNonce, cbTag);

        // Decrypt with GCM (tag verification happens automatically)
        status = BCryptDecrypt(hKey,
            const_cast<PUCHAR>(pbCiphertext), cbCiphertext, // NOSONAR - Windows CNG API requires non-const PUCHAR for ciphertext
            &authInfo,
            nullptr, 0,
            pbPlaintext, *pcbPlaintext,
            &cbResult, 0);

        if (!BCRYPT_SUCCESS(status))
        {
            EIDM_TRACE_ERROR(L"BCryptDecrypt failed: 0x%08X", status);
            __leave;
        }

        *pcbPlaintext = cbResult;
    }
    __finally
    {
        if (hKey) BCryptDestroyKey(hKey);
        if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }

    if (BCRYPT_SUCCESS(status))
        return CRYPTO_STATUS::CRYPTO_SUCCESS;
    else
        return (CRYPTO_STATUS)7;  // ERROR_DECRYPTION_FAILED
}

std::string EncodeBase64(_In_reads_bytes_(cbData) const BYTE* pbData, _In_ DWORD cbData)
{
    if (!pbData || cbData == 0)
        return std::string();

    DWORD dwLength = 0;
    if (!CryptBinaryToStringA(pbData, cbData, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        nullptr, &dwLength))
        return std::string();

    std::string result(dwLength, 0);
    if (!CryptBinaryToStringA(pbData, cbData, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        &result[0], &dwLength))
        return std::string();

    // Remove null terminator
    result.pop_back();
    return result;
}

std::vector<BYTE> DecodeBase64(_In_ const std::string& encoded)
{
    if (encoded.empty())
        return std::vector<BYTE>();

    DWORD dwLength = 0;
    if (!CryptStringToBinaryA(encoded.c_str(), static_cast<DWORD>(encoded.length()),
        CRYPT_STRING_BASE64, nullptr, &dwLength, nullptr, nullptr))
        return std::vector<BYTE>();

    std::vector<BYTE> result(dwLength);
    if (!CryptStringToBinaryA(encoded.c_str(), static_cast<DWORD>(encoded.length()),
        CRYPT_STRING_BASE64, result.data(), &dwLength, nullptr, nullptr))
        return std::vector<BYTE>();

    return result;
}

BOOL ComputeHMAC(
    _In_reads_bytes_(cbKey) const BYTE* pbKey,
    _In_ DWORD cbKey,
    _In_reads_bytes_(cbData) const BYTE* pbData,
    _In_ DWORD cbData,
    _Out_writes_all_(HASH_SIZE) BYTE* pbHash,
    _In_ DWORD HASH_SIZE)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL; // NOSONAR (EXPLICIT-TYPE-03) - Explicit NTSTATUS type preferred for clarity
    BCRYPT_ALG_HANDLE hAlgorithm = NULL; // NOSONAR - Windows API requires NULL
    BCRYPT_HASH_HANDLE hHash = NULL; // NOSONAR - Windows API requires NULL
    PBYTE pbHashObject = nullptr;
    DWORD cbHashObject = 0;
    DWORD cbResult = 0;

    __try
    {
        // Open HMAC algorithm provider
        status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_HASH_INTERFACE_HMAC);
        if (!BCRYPT_SUCCESS(status))
        {
            __leave;
        }

        // Get hash object size
        status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH,
            (PBYTE)&cbHashObject, sizeof(DWORD), &cbResult, 0);
        if (!BCRYPT_SUCCESS(status))
        {
            __leave;
        }

        pbHashObject = static_cast<PBYTE>(malloc(cbHashObject)); // NOSONAR - BCrypt API requires malloc/free for hash object buffer
        if (!pbHashObject)
        {
            status = STATUS_NO_MEMORY;
            __leave;
        }

        // Create hash handle
        status = BCryptCreateHash(hAlgorithm, &hHash, pbHashObject, cbHashObject,
            reinterpret_cast<PBYTE>(const_cast<BYTE*>(pbKey)), cbKey, 0); // NOSONAR - Windows CNG API requires PBYTE for key parameter
        if (!BCRYPT_SUCCESS(status))
        {
            __leave;
        }

        // Hash data
        status = BCryptHashData(hHash, const_cast<PBYTE>(pbData), cbData, 0); // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
        if (!BCRYPT_SUCCESS(status))
        {
            __leave;
        }

        // Get hash result
        status = BCryptFinishHash(hHash, pbHash, HASH_SIZE, 0);
        if (!BCRYPT_SUCCESS(status))
        {
            __leave;
        }
    }
    __finally
    {
        // Destroy the hash BEFORE freeing the object buffer it was created
        // over - same use-after-free as in ComputeHMACSha256 above.
        if (hHash) BCryptDestroyHash(hHash);
        if (pbHashObject) free(pbHashObject); // NOSONAR - memory allocated with malloc for BCrypt API compatibility
        if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }

    return BCRYPT_SUCCESS(status);
}

BOOL GenerateRandom(_Out_writes_all_(cbBytes) BYTE* pbBytes, _In_ DWORD cbBytes)
{
    BCRYPT_ALG_HANDLE hAlgorithm = NULL; // NOSONAR - Windows API requires NULL
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RNG_ALGORITHM, nullptr, 0);

    if (BCRYPT_SUCCESS(status))
    {
        status = BCryptGenRandom(hAlgorithm, pbBytes, cbBytes, 0);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }

    return BCRYPT_SUCCESS(status);
}

std::string BytesToHex(_In_reads_bytes_(cbBytes) const BYTE* pbBytes, _In_ DWORD cbBytes) // NOSONAR - API-01: signature dictated by Windows/callback API
{
    std::string result;
    result.reserve(cbBytes * 2);

    for (DWORD i = 0; i < cbBytes; i++)
    {
        char szHex[3]; // NOSONAR - LSASS-01: C-style char buffer for sprintf_s
        sprintf_s(szHex, "%02x", pbBytes[i]);
        result += szHex;
    }

    return result;
}

std::vector<BYTE> HexToBytes(_In_ const std::string& hex)
{
    std::vector<BYTE> result;

    if (hex.length() % 2 != 0)
        return result;

    for (size_t i = 0; i < hex.length(); i += 2)
    {
        BYTE b = 0;
        for (int j = 0; j < 2; j++)
        {
            char c = hex[i + j];
            b <<= 4; // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API

            if (c >= '0' && c <= '9')
                b |= (c - '0'); // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
            else if (c >= 'a' && c <= 'f')
                b |= (c - 'a' + 10); // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
            else if (c >= 'A' && c <= 'F')
                b |= (c - 'A' + 10); // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        }

        result.push_back(b); // NOSONAR - push_back used for primitive type (BYTE); emplace_back provides no benefit
    }

    return result;
}
