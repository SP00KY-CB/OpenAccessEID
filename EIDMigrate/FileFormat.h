#pragma once

// File: EIDMigrate/FileFormat.h
// Binary file format definitions for EIDMigrate encrypted export files

#include <Windows.h>
#include <cstdint>

// Magic number for .eidm files
constexpr char EIDMIGRATE_MAGIC[16] = {  // NOSONAR - LSASS-01: C-style buffer for fixed binary file-format layout
    'E', 'I', 'D', 'M', 'I', 'G', 'R', 'A', 'T', 'E',
    '\0', '\0', '\0', '\0', '\0', '\0'
};

// File format version written by this build.
//   1 - PBKDF2 used a non-standard chaining (U_{i+1} = PRF(P, T_i)).
//       Still accepted on import, with the legacy derivation.
//   2 - Standard PBKDF2-HMAC-SHA256 (RFC 8018). Header layout unchanged.
constexpr uint32_t EIDMIGRATE_VERSION = 2;
constexpr uint32_t EIDMIGRATE_VERSION_LEGACY_PBKDF2 = 1;

// File header offsets and sizes
constexpr size_t HEADER_MAGIC_OFFSET = 0x00;
constexpr size_t HEADER_MAGIC_SIZE = 16;
constexpr size_t HEADER_VERSION_OFFSET = 0x10;
constexpr size_t HEADER_VERSION_SIZE = 4;
constexpr size_t HEADER_SALT_OFFSET = 0x14;
constexpr size_t HEADER_SALT_SIZE = 16;
constexpr size_t HEADER_NONCE_OFFSET = 0x24;
constexpr size_t HEADER_NONCE_SIZE = 12;
constexpr size_t HEADER_RESERVED_OFFSET = 0x30;
constexpr size_t HEADER_RESERVED_SIZE = 16;
constexpr size_t HEADER_ITERATIONS_OFFSET = 0x40;
constexpr size_t HEADER_ITERATIONS_SIZE = 4;
constexpr size_t HEADER_TAG_LENGTH_OFFSET = 0x44;
constexpr size_t HEADER_TAG_LENGTH_SIZE = 4;
constexpr size_t HEADER_PAYLOAD_LENGTH_OFFSET = 0x48;
constexpr size_t HEADER_PAYLOAD_LENGTH_SIZE = 8;
constexpr size_t HEADER_TAG_OFFSET = 0x50;
constexpr size_t HEADER_TAG_SIZE = 16;
constexpr size_t HEADER_TOTAL_SIZE = 0x60;  // 96 bytes

// Crypto parameters
constexpr DWORD PBKDF2_ITERATIONS = 600000;  // OWASP 2024 recommendation
// Bounds applied to the iteration count read from a file header on import.
// Honouring the header lets PBKDF2_ITERATIONS be raised later without making
// existing exports unreadable - but the header is attacker-supplied, so a floor
// is required or "agility" becomes a downgrade attack, and a ceiling stops a
// hostile file from pinning a CPU for hours.
constexpr DWORD PBKDF2_MIN_ITERATIONS = 100000;
constexpr DWORD PBKDF2_MAX_ITERATIONS = 10000000;
constexpr DWORD PBKDF2_SALT_SIZE = 16;
constexpr DWORD PBKDF2_KEY_SIZE = 32;        // 256 bits
constexpr DWORD GCM_NONCE_SIZE = 12;         // 96 bits (GCM recommendation)
constexpr DWORD GCM_TAG_SIZE = 16;           // 128 bits (maximum security)
constexpr DWORD HMAC_SIZE = 32;              // SHA-256

// Derived key structure
#pragma pack(push, 1)
struct DERIVED_KEY
{
    BYTE rgbKey[PBKDF2_KEY_SIZE];            // AES-256 encryption key // NOSONAR - LSASS-01: C-style buffer for fixed binary file-format layout
    BYTE rgbAuthKey[PBKDF2_KEY_SIZE];        // HMAC authentication key // NOSONAR - LSASS-01: C-style buffer for fixed binary file-format layout
    BYTE rgbSalt[PBKDF2_SALT_SIZE];          // Random salt // NOSONAR - LSASS-01: C-style buffer for fixed binary file-format layout
};
#pragma pack(pop)

// Encrypted file header
#pragma pack(push, 1)
struct EIDMIGRATE_FILE_HEADER
{
    UCHAR Magic[16];                         // "EIDMIGRATE\x00\x00\x00\x00\x00\x00" // NOSONAR - LSASS-01: C-style buffer for fixed binary file-format layout
    uint32_t FormatVersion;                  // Little-endian, EIDMIGRATE_VERSION (2) or legacy 1
    UCHAR PBKDF2Salt[16];                    // PBKDF2 salt // NOSONAR - LSASS-01: C-style buffer for fixed binary file-format layout
    UCHAR GCMNonce[12];                      // GCM nonce/IV // NOSONAR - LSASS-01: C-style buffer for fixed binary file-format layout
    UCHAR Reserved[16];                      // Future use (zero) // NOSONAR - LSASS-01: C-style buffer for fixed binary file-format layout
    uint32_t PBKDF2Iterations;               // 600000 (0x000927C0)
    uint32_t GCMTagLength;                   // 16 (0x00000010)
    uint64_t PayloadLength;                  // Encrypted JSON size
    UCHAR GCMTag[16];                        // GCM authentication tag // NOSONAR - LSASS-01: C-style buffer for fixed binary file-format layout
};
static_assert(sizeof(EIDMIGRATE_FILE_HEADER) == 0x60, "Header must be 96 bytes");
#pragma pack(pop)

// File extension
constexpr wchar_t EIDMIGRATE_FILE_EXTENSION[] = L".eidm";

// Error codes for file operations
enum class EIDMIGRATE_FILE_ERROR : DWORD
{
    EIDM_SUCCESS = 0,
    EIDM_ERROR_INVALID_MAGIC = 1,
    EIDM_ERROR_UNSUPPORTED_VERSION = 2,
    EIDM_ERROR_INVALID_HEADER = 3,
    EIDM_ERROR_DECRYPTION_FAILED = 4,
    EIDM_ERROR_INVALID_PASSPHRASE = 5,
    EIDM_ERROR_CORRUPTED_FILE = 6,
    EIDM_ERROR_HMAC_MISMATCH = 7,
    EIDM_ERROR_JSON_PARSE_FAILED = 8,
    EIDM_ERROR_INVALID_SCHEMA = 9,
};
