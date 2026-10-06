#pragma once

// File: EIDMigrate/CryptoHelpers.h
// Cryptographic helper functions for key derivation, encryption, and encoding

#include "FileFormat.h"
#include <Windows.h>
#include <bcrypt.h>
#include <string>
#include <vector>

// Crypto operation status codes
enum class CRYPTO_STATUS : DWORD
{
    CRYPTO_SUCCESS = 0,
    CRYPTO_ERROR_ALG_HANDLE_FAILED = 1,
    CRYPTO_ERROR_KDF_FAILED = 2,
    CRYPTO_ERROR_INVALID_PARAMETER = 3,
    CRYPTO_ERROR_INSUFFICIENT_BUFFER = 4,
    CRYPTO_ERROR_RANDOM_FAILED = 5,
    CRYPTO_ERROR_ENCRYPTION_FAILED = 6,
    CRYPTO_ERROR_DECRYPTION_FAILED = 7,
    CRYPTO_ERROR_AUTH_FAILED = 8,
};

// Derive encryption and authentication keys from passphrase
// Generates a new random salt
CRYPTO_STATUS DeriveKeyFromPassphrase(
    _In_ PCWSTR pwszPassphrase,
    _In_ SIZE_T cchPassphrase,
    _Out_ DERIVED_KEY* pDerivedKey);

// Derive encryption and authentication keys from passphrase with provided salt
// Used for decryption where salt comes from file header
// dwIterations is the count recorded in the file being imported, so that
// PBKDF2_ITERATIONS can be raised without orphaning existing exports. It is
// clamped to [PBKDF2_MIN_ITERATIONS, PBKDF2_MAX_ITERATIONS] because the header
// is attacker-supplied.
// fLegacyPbkdf2 selects the non-standard PBKDF2 chaining used by format
// version 1 files (EIDMIGRATE_VERSION_LEGACY_PBKDF2); pass FALSE otherwise.
CRYPTO_STATUS DeriveKeyFromPassphraseWithSalt(
    _In_ PCWSTR pwszPassphrase,
    _In_ SIZE_T cchPassphrase,
    _In_reads_(PBKDF2_SALT_SIZE) const BYTE* pbSalt,
    _Out_ DERIVED_KEY* pDerivedKey,
    _In_ DWORD dwIterations,
    _In_ BOOL fLegacyPbkdf2);

// Validate passphrase strength
BOOL ValidatePassphraseStrength(_In_ PCWSTR pwszPassphrase);

// Encrypt data with AES-256-GCM
CRYPTO_STATUS EncryptWithGCM(
    _In_ const BYTE* pbKey,
    _In_ DWORD cbKey,
    _In_reads_bytes_(cbNonce) const BYTE* pbNonce,
    _In_ DWORD cbNonce,
    _In_reads_bytes_(cbPlaintext) const BYTE* pbPlaintext,
    _In_ DWORD cbPlaintext,
    _Out_writes_(cbCiphertext) BYTE* pbCiphertext,
    _Inout_ DWORD* pcbCiphertext,
    _Out_writes_(cbTag) BYTE* pbTag,
    _In_ DWORD cbTag);

// Decrypt data with AES-256-GCM
CRYPTO_STATUS DecryptWithGCM(
    _In_ const BYTE* pbKey,
    _In_ DWORD cbKey,
    _In_reads_bytes_(cbNonce) const BYTE* pbNonce,
    _In_ DWORD cbNonce,
    _In_reads_bytes_(cbCiphertext) const BYTE* pbCiphertext,
    _In_ DWORD cbCiphertext,
    _In_reads_bytes_(cbTag) const BYTE* pbTag,
    _In_ DWORD cbTag,
    _Out_writes_(cbPlaintext) BYTE* pbPlaintext,
    _Inout_ DWORD* pcbPlaintext);

// Base64 encode binary data
std::string EncodeBase64(
    _In_reads_bytes_(cbData) const BYTE* pbData,
    _In_ DWORD cbData);

// Base64 decode to binary data
std::vector<BYTE> DecodeBase64(_In_ const std::string& encoded);

// Compute HMAC-SHA256 of data
BOOL ComputeHMAC(
    _In_reads_bytes_(cbKey) const BYTE* pbKey,
    _In_ DWORD cbKey,
    _In_reads_bytes_(cbData) const BYTE* pbData,
    _In_ DWORD cbData,
    _Out_writes_all_(HASH_SIZE) BYTE* pbHash,
    _In_ DWORD HASH_SIZE = 32);

// Generate random bytes
BOOL GenerateRandom(
    _Out_writes_all_(cbBytes) BYTE* pbBytes,
    _In_ DWORD cbBytes);

// Convert bytes to hex string
std::string BytesToHex(
    _In_reads_bytes_(cbBytes) const BYTE* pbBytes,
    _In_ DWORD cbBytes);

// Convert hex string to bytes
std::vector<BYTE> HexToBytes(_In_ const std::string& hex);
