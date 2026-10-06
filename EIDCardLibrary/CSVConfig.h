/*
    OpenAccess EID - Smart card authentication for Windows
    Copyright (C) 2009 Vincent Le Toux
    Copyright (C) 2026 Contributors

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License version 2.1 as published by the Free Software Foundation.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, see <https://www.gnu.org/licenses/>.
*/

/**
 *  CSV Logging Configuration
 *
 *  Defines configuration structures and functions for CSV logging.
 *  All structures use stack-allocated buffers for LSASS safety.
 */

#pragma once

#include <Windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <string>
#include "EventDefinitions.h"

// Undefine Windows macros that conflict with enum values
#ifdef ERROR
#undef ERROR  // NOSONAR - INCLUDE-01: #undef required to avoid Windows macro/enum collision
#endif
#ifdef DOMAIN
#undef DOMAIN  // NOSONAR - INCLUDE-01: #undef required to avoid Windows macro/enum collision
#endif
#ifdef SEVERITY
#undef SEVERITY  // NOSONAR - INCLUDE-01: #undef required to avoid Windows macro/enum collision
#endif
#ifdef OUTCOME
#undef OUTCOME  // NOSONAR - INCLUDE-01: #undef required to avoid Windows macro/enum collision
#endif
#ifdef TARGET
#undef TARGET  // NOSONAR - INCLUDE-01: #undef required to avoid Windows macro/enum collision
#endif
#ifdef ALL
#undef ALL  // NOSONAR - INCLUDE-01: #undef required to avoid Windows macro/enum collision
#endif
#ifdef MESSAGE
#undef MESSAGE  // NOSONAR - INCLUDE-01: #undef required to avoid Windows macro/enum collision
#endif

// ================================================================
// CSV Column Flags (bitmask for efficient storage)
// ================================================================
enum EID_CSV_COLUMN : DWORD  // NOSONAR - ENUM-01: enum kept for Win32/ABI compatibility
{
    NONE            = 0x00000000,

    // Standard columns
    COL_TIMESTAMP   = 0x00000001,
    COL_EVENT_ID    = 0x00000002,
    COL_CATEGORY    = 0x00000004,
    COL_SEVERITY    = 0x00000008,
    COL_OUTCOME     = 0x00000010,
    COL_USERNAME    = 0x00000020,
    COL_ACTION      = 0x00000040,
    COL_MESSAGE     = 0x00000080,

    // Extended columns
    COL_DOMAIN      = 0x00000100,
    COL_CLIENT_IP   = 0x00000200,
    COL_PROCESS_ID  = 0x00000400,
    COL_THREAD_ID  = 0x00000800,
    COL_LOGIN_SESS  = 0x00001000,
    COL_TARGET      = 0x00002000,
    COL_REASON      = 0x00004000,

    // All columns mask
    COL_ALL         = 0x00007FFF,

    // Backward-compatible aliases (without COL_ prefix)
    TIMESTAMP       = COL_TIMESTAMP,
    EVENT_ID        = COL_EVENT_ID,
    CATEGORY        = COL_CATEGORY,
    SEVERITY        = COL_SEVERITY,
    OUTCOME         = COL_OUTCOME,
    USERNAME        = COL_USERNAME,
    ACTION          = COL_ACTION,
    MESSAGE         = COL_MESSAGE,
    DOMAIN          = COL_DOMAIN,
    CLIENT_IP       = COL_CLIENT_IP,
    SOURCE_IP       = COL_CLIENT_IP,    // Alias
    PROCESS_ID      = COL_PROCESS_ID,
    THREAD_ID       = COL_THREAD_ID,
    LOGIN_SESSION   = COL_LOGIN_SESS,
    SESSION_ID      = COL_LOGIN_SESS,    // Alias
    TARGET          = COL_TARGET,
    RESOURCE        = COL_TARGET,       // Alias
    REASON          = COL_REASON,
    ALL             = COL_ALL
};

// Bitwise operators for EID_CSV_COLUMN enum class
constexpr EID_CSV_COLUMN operator|(EID_CSV_COLUMN a, EID_CSV_COLUMN b) noexcept
{
    return static_cast<EID_CSV_COLUMN>(static_cast<DWORD>(a) | static_cast<DWORD>(b));  // NOSONAR - ENUM-01: enum cast retained for Win32/ABI compatibility
}

inline EID_CSV_COLUMN& operator|=(EID_CSV_COLUMN& a, EID_CSV_COLUMN b) noexcept
{
    a = a | b;
    return a;
}

constexpr EID_CSV_COLUMN operator&(EID_CSV_COLUMN a, EID_CSV_COLUMN b) noexcept
{
    return static_cast<EID_CSV_COLUMN>(static_cast<DWORD>(a) & static_cast<DWORD>(b));  // NOSONAR - ENUM-01: enum cast retained for Win32/ABI compatibility
}

inline EID_CSV_COLUMN& operator&=(EID_CSV_COLUMN& a, EID_CSV_COLUMN b) noexcept
{
    a = a & b;
    return a;
}

// ================================================================
// Column Presets
// ================================================================
namespace EID_CSV_PRESETS
{
    // Standard: 8 columns for typical security auditing
    constexpr EID_CSV_COLUMN STANDARD =
        EID_CSV_COLUMN::COL_TIMESTAMP | EID_CSV_COLUMN::COL_EVENT_ID |
        EID_CSV_COLUMN::COL_CATEGORY | EID_CSV_COLUMN::COL_SEVERITY |
        EID_CSV_COLUMN::COL_OUTCOME | EID_CSV_COLUMN::COL_USERNAME |
        EID_CSV_COLUMN::COL_ACTION | EID_CSV_COLUMN::COL_MESSAGE;

    // Extended: All available columns
    constexpr EID_CSV_COLUMN EXTENDED =
        EID_CSV_COLUMN::COL_TIMESTAMP | EID_CSV_COLUMN::COL_EVENT_ID |
        EID_CSV_COLUMN::COL_CATEGORY | EID_CSV_COLUMN::COL_SEVERITY |
        EID_CSV_COLUMN::COL_OUTCOME | EID_CSV_COLUMN::COL_USERNAME |
        EID_CSV_COLUMN::COL_DOMAIN | EID_CSV_COLUMN::COL_CLIENT_IP |
        EID_CSV_COLUMN::COL_ACTION | EID_CSV_COLUMN::COL_TARGET |
        EID_CSV_COLUMN::COL_REASON | EID_CSV_COLUMN::COL_LOGIN_SESS |
        EID_CSV_COLUMN::COL_PROCESS_ID | EID_CSV_COLUMN::COL_MESSAGE;

    // Minimal: 5 columns for compliance reporting
    constexpr EID_CSV_COLUMN MINIMAL =
        EID_CSV_COLUMN::COL_TIMESTAMP | EID_CSV_COLUMN::COL_EVENT_ID |
        EID_CSV_COLUMN::COL_OUTCOME | EID_CSV_COLUMN::COL_USERNAME |
        EID_CSV_COLUMN::COL_ACTION;
}

// ================================================================
// Severity Levels (for CSV logging)
// ================================================================
enum class EID_SEVERITY : UCHAR
{
    CRITICAL = 1,   // System-level failure
    ERROR    = 2,   // Operational failure
    WARNING  = 3,   // Recoverable issue
    INFO     = 4,   // Normal operation
    VERBOSE  = 5    // Detailed diagnostics
};

// ================================================================
// Outcome Values
// ================================================================
enum class EID_OUTCOME : UCHAR
{
    SUCCESS   = 0,   // Operation completed successfully
    FAILURE   = 1,   // Operation failed
    PARTIAL   = 2,   // Partial success (some sub-operations failed)
    UNKNOWN   = 3,   // Outcome unknown
    SKIPPED   = 4,   // Operation skipped
    CANCELLED = 5    // Operation cancelled by user
};

// ================================================================
// CSV Configuration Structure
// ================================================================
// Stack-allocated, no dynamic memory for LSASS safety
struct EID_CSV_CONFIG
{
    BOOL                  fEnabled;         // CSV logging enabled
    WCHAR                 szLogPath[MAX_PATH];  // Path to CSV log file // NOSONAR - LSASS-01: C-style buffer for LSASS safety
    EID_CSV_COLUMN        dwColumns;        // Column bitmask
    DWORD                 dwMaxFileSizeMB;  // Max file size before rotation
    DWORD                 dwFileCount;      // Number of rotated files to keep
    DWORD                 dwCategoryFilter; // Category filter bitmask (bit N = category N enabled)
    BOOL                  fVerboseEvents;   // Include verbose-level events
    BOOL                  fDiagnosticsEnabled; // Capture free-text provider diagnostic traces
    DWORD                 dwDiagnosticsLevel;  // WINEVENT level ceiling for diagnostics (4=INFO, 5=VERBOSE)

    // Default constructor
    EID_CSV_CONFIG()
    {
        fEnabled = FALSE;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
        szLogPath[0] = L'\0';
        dwColumns = EID_CSV_PRESETS::STANDARD;
        dwMaxFileSizeMB = 64;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
        dwFileCount = 5;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
        dwCategoryFilter = 0x0000FFFF;  // All categories enabled (bits 0-15) // NOSONAR - INIT-01: member initialized in body for clarity/ordering
        fVerboseEvents = FALSE;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
        fDiagnosticsEnabled = FALSE;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
        dwDiagnosticsLevel = 4; // WINEVENT_LEVEL_INFO // NOSONAR - INIT-01: member initialized in body for clarity/ordering
    }
};

// ================================================================
// Configuration Paths
// ================================================================
#define EID_CSV_CONFIG_DIR          L"C:\\ProgramData\\OpenAccessEID"  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use
#define EID_CSV_CONFIG_PATH         L"C:\\ProgramData\\OpenAccessEID\\logging.json"  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use
#define EID_CSV_DEFAULT_LOG_PATH    L"C:\\ProgramData\\OpenAccessEID\\logs\\events.csv"  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use
#define EID_CSV_CONFIG_KEY          L"SOFTWARE\\OpenAccessEID\\LogManager"  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use
// Group Policy key: values present here override the local file/registry config (ADMX-managed).
#define EID_CSV_POLICY_KEY          L"SOFTWARE\\Policies\\OpenAccessEID\\LogManager"  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use

#include "LogDirSecurity.h"

// ================================================================
// Configuration Management Functions
// ================================================================

// Load configuration (tries JSON file, then registry, then defaults; then applies GPO overrides)
HRESULT EID_CSV_LoadConfig(EID_CSV_CONFIG& config);

// Apply Group Policy overrides from HKLM\SOFTWARE\Policies\OpenAccessEID\LogManager on top of
// an already-loaded config. Any value present under the policy key wins over local file/registry config.
void EID_CSV_ApplyPolicyOverrides(EID_CSV_CONFIG& config);

// Save configuration (saves to both JSON file and registry)
HRESULT EID_CSV_SaveConfig(const EID_CSV_CONFIG& config);

// Load from specific file
HRESULT EID_CSV_LoadConfigFromFile(PCWSTR pwszPath, EID_CSV_CONFIG& config);

// Save to specific file
HRESULT EID_CSV_SaveConfigToFile(PCWSTR pwszPath, const EID_CSV_CONFIG& config);

// Load from registry
HRESULT EID_CSV_LoadConfigFromRegistry(EID_CSV_CONFIG& config);

// Save to registry
HRESULT EID_CSV_SaveConfigToRegistry(const EID_CSV_CONFIG& config);

// Helper: Convert config to JSON string
std::string EID_CSV_ConfigToJson(const EID_CSV_CONFIG& config);

// Helper: Convert JSON string to config
HRESULT EID_CSV_JsonToConfig(const std::string& json, EID_CSV_CONFIG& config);

// ================================================================
// Helper Functions for Category Filtering
// ================================================================

// Check if a category is enabled in the filter
inline BOOL IsCategoryEnabled(DWORD dwCategoryFilter, EID_EVENT_CATEGORY category)
{
    DWORD dwCatBit = (static_cast<DWORD>(category) / 1000);  // NOSONAR - ENUM-01: enum cast retained for Win32/ABI compatibility
    return (dwCategoryFilter & (1UL << dwCatBit)) != 0;
}

// Enable a category in the filter
inline DWORD EnableCategory(DWORD dwCategoryFilter, EID_EVENT_CATEGORY category)
{
    DWORD dwCatBit = (static_cast<DWORD>(category) / 1000);  // NOSONAR - ENUM-01: enum cast retained for Win32/ABI compatibility
    return dwCategoryFilter | (1UL << dwCatBit);
}

// Disable a category in the filter
inline DWORD DisableCategory(DWORD dwCategoryFilter, EID_EVENT_CATEGORY category)
{
    DWORD dwCatBit = (static_cast<DWORD>(category) / 1000);  // NOSONAR - ENUM-01: enum cast retained for Win32/ABI compatibility
    return dwCategoryFilter & ~(1UL << dwCatBit);
}



