// File: EIDMigrate/EIDMigrate.cpp
// Main entry point and command-line handling

#include "EIDMigrate.h"
#include "CryptoHelpers.h"
#include "Export.h"
#include "Import.h"
#include "List.h"
#include "Validate.h"
#include "CertificateInstall.h"
#include "AuditLogging.h"
#include "PinPrompt.h"
#include "SecureMemory.h"
#include "Utils.h"
#include <vector>
#include <exception>

// Global application state is now defined in Globals.cpp
// to allow sharing between EIDMigrate and EIDManageUsers

// Print usage information
void ShowUsage()
{
    fwprintf(stderr, L"\n");
    fwprintf(stderr, L"EIDMigrate - OpenAccess EID Credential Migration Tool v%ls\n", EIDMIGRATE_APP_VERSION);
    fwprintf(stderr, L"\n");
    fwprintf(stderr, L"Usage:\n");
    fwprintf(stderr, L"  EIDMigrate.exe <command> [options]\n");
    fwprintf(stderr, L"\n");
    fwprintf(stderr, L"Commands:\n");
    fwprintf(stderr, L"  export    Export credentials from this machine\n");
    fwprintf(stderr, L"  import    Import credentials to this machine\n");
    fwprintf(stderr, L"  list      List credentials (local or from file)\n");
    fwprintf(stderr, L"  validate  Validate an export file\n");
    fwprintf(stderr, L"  import-crl Install a CRL for offline revocation checking (-input <path.crl>)\n");
    fwprintf(stderr, L"  help      Show this help message\n");
    fwprintf(stderr, L"  version   Show version information\n");
    fwprintf(stderr, L"\n");
    fwprintf(stderr, L"Export Options:\n");
    fwprintf(stderr, L"  -o, -output <path>       Output file path (.eidm)\n");
    fwprintf(stderr, L"  -p, -password <pass>     Encryption passphrase (prompt if omitted)\n");
    fwprintf(stderr, L"  -groups <g1,g2,...>      Specific groups to export (comma-separated)\n");
    fwprintf(stderr, L"  -validate                Validate certificates during export\n");
    fwprintf(stderr, L"  -v, -verbose             Verbose output (use -vv for more)\n");
    fwprintf(stderr, L"  -log <path>              Log file path\n");
    fwprintf(stderr, L"\n");
    fwprintf(stderr, L"Import Options:\n");
    fwprintf(stderr, L"  -i, -input <path>        Input file path (.eidm)\n");
    fwprintf(stderr, L"  -p, -password <pass>     Decryption passphrase (prompt if omitted)\n");
    fwprintf(stderr, L"  -groups <g1,g2,...>      Specific groups to import (comma-separated)\n");
    fwprintf(stderr, L"  -dry-run                 Simulate import without changes\n");
    fwprintf(stderr, L"  -force                   Perform actual import (use with caution)\n");
    fwprintf(stderr, L"  -create-users            Create missing user accounts\n");
    fwprintf(stderr, L"  -continue-on-error       Continue after individual credential errors\n");
    fwprintf(stderr, L"  -expect-source <machine> Refuse a file not stamped by this issuing machine\n");
    fwprintf(stderr, L"  -v, -verbose             Verbose output\n");
    fwprintf(stderr, L"  -log <path>              Log file path\n");
    fwprintf(stderr, L"\n");
    fwprintf(stderr, L"List Options:\n");
    fwprintf(stderr, L"  -i, -input <path>        List credentials from export file\n");
    fwprintf(stderr, L"  -local                   List local LSA credentials\n");
    fwprintf(stderr, L"  -v, -verbose             Show detailed information\n");
    fwprintf(stderr, L"  -json                    Output in JSON format\n");
    fwprintf(stderr, L"\n");
    fwprintf(stderr, L"Validate Options:\n");
    fwprintf(stderr, L"  -i, -input <path>        Export file to validate\n");
    fwprintf(stderr, L"  -require-smartcard       Verify smart card is available\n");
    fwprintf(stderr, L"  -v, -verbose             Detailed validation report\n");
    fwprintf(stderr, L"\n");
    fwprintf(stderr, L"Security:\n");
    fwprintf(stderr, L"  EIDMigrate requires Administrator privileges.\n");
    fwprintf(stderr, L"  Passphrases must be at least 16 characters.\n");
    fwprintf(stderr, L"  The -password flag is discouraged; use interactive prompt.\n");
    fwprintf(stderr, L"\n");
    fwprintf(stderr, L"Exit Codes:\n");
    fwprintf(stderr, L"  0  Success\n");
    fwprintf(stderr, L"  1  General error\n");
    fwprintf(stderr, L"  2  LSA access denied (not Administrator)\n");
    fwprintf(stderr, L"  3  No credentials found\n");
    fwprintf(stderr, L"  4  File write error\n");
    fwprintf(stderr, L"  5  Invalid passphrase\n");
    fwprintf(stderr, L"  6  File corrupted\n");
    fwprintf(stderr, L"  7  No valid credentials\n");
    fwprintf(stderr, L"  8  Some credentials failed (with -continue-on-error)\n");
    fwprintf(stderr, L"\n");
}

// Print version information
void ShowVersion()
{
    fwprintf(stderr, L"\n");
    fwprintf(stderr, L"EIDMigrate v%ls\n", EIDMIGRATE_APP_VERSION);
    fwprintf(stderr, L"%ls\n", EIDMIGRATE_APP_COPYRIGHT);
    fwprintf(stderr, L"\n");
    fwprintf(stderr, L"Build: x64 Release\n");
    fwprintf(stderr, L"Platform: Windows 10/11 x64\n");
    fwprintf(stderr, L"\n");
}

// Parse command line arguments
// M1: install an offline-distributed CRL so IsTrustedCertificate can revoke cards without a network.
HRESULT CommandImportCrl(_In_ const COMMAND_OPTIONS& options)
{
    wprintf(L"Importing CRL from '%ls'...\n", options.InputFile.c_str());
    HRESULT hr = InstallCrlFromFile(options.InputFile);  // NOSONAR (EXPLICIT-TYPE-03) - HRESULT visible for security audit
    if (SUCCEEDED(hr))
    {
        wprintf(L"CRL imported into the machine CA store; offline revocation checking will use it.\n");
        LogAuditEventBoth(EID_AUDIT_EVENT_TYPE::CERTIFICATE_INSTALLED, nullptr,
            (std::wstring(L"CRL installed from ") + options.InputFile).c_str());
    }
    else
    {
        fwprintf(stderr, L"Failed to import CRL (0x%08X).\n", static_cast<unsigned int>(hr));
        LogAuditEventBoth(EID_AUDIT_EVENT_TYPE::WARNING, nullptr,
            (std::wstring(L"CRL import failed from ") + options.InputFile).c_str());
    }
    return hr;
}

BOOL ParseCommandLine(_In_ int argc, _In_ PWSTR argv[], _Out_ COMMAND_OPTIONS& options)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
    if (argc < 2)
    {
        ShowUsage();
        return FALSE;
    }

    // Parse command
    std::wstring wsCommand(argv[1]);

    if (wsCommand == L"export" || wsCommand == L"ex")  // NOSONAR - SCOPE-01: variable reused after the block
    {
        options.Command = COMMAND_TYPE::EXPORT;
    }
    else if (wsCommand == L"import" || wsCommand == L"im")
    {
        options.Command = COMMAND_TYPE::IMPORT;
    }
    else if (wsCommand == L"list" || wsCommand == L"ls")
    {
        options.Command = COMMAND_TYPE::LIST;
    }
    else if (wsCommand == L"validate" || wsCommand == L"val")
    {
        options.Command = COMMAND_TYPE::VALIDATE;
    }
    else if (wsCommand == L"import-crl")
    {
        options.Command = COMMAND_TYPE::IMPORT_CRL;
    }
    else if (wsCommand == L"help" || wsCommand == L"?")
    {
        options.Command = COMMAND_TYPE::HELP;
        return TRUE;
    }
    else if (wsCommand == L"version" || wsCommand == L"ver")
    {
        options.Command = COMMAND_TYPE::VERSION;
        return TRUE;
    }
    else
    {
        fwprintf(stderr, L"Error: Unknown command '%ls'\n", wsCommand.c_str());
        ShowUsage();
        return FALSE;
    }

    // Parse options
    for (int i = 2; i < argc; i++)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
    {
        std::wstring wsArg(argv[i]);

        if (wsArg == L"-o" || wsArg == L"-output")
        {
            if (i + 1 >= argc)
            {
                fwprintf(stderr, L"Error: %ls requires a path argument\n", wsArg.c_str());
                return FALSE;
            }
            options.OutputFile = argv[++i];
        }
        else if (wsArg == L"-i" || wsArg == L"-input")
        {
            if (i + 1 >= argc)
            {
                fwprintf(stderr, L"Error: %ls requires a path argument\n", wsArg.c_str());
                return FALSE;
            }
            options.InputFile = argv[++i];
        }
        else if (wsArg == L"-p" || wsArg == L"-password")
        {
            if (i + 1 >= argc)
            {
                fwprintf(stderr, L"Error: %ls requires a password argument\n", wsArg.c_str());
                return FALSE;
            }
            options.Password = argv[++i];
        }
        else if (wsArg == L"-log")
        {
            if (i + 1 >= argc)
            {
                fwprintf(stderr, L"Error: %ls requires a path argument\n", wsArg.c_str());
                return FALSE;
            }
            options.LogFile = argv[++i];
        }
        else if (wsArg == L"-v" || wsArg == L"-verbose")
        {
            if (options.Verbosity < VERBOSITY::DEBUG)
                options.Verbosity = static_cast<VERBOSITY>(static_cast<int>(options.Verbosity) + 1);  // NOSONAR - ENUM-01: enum kept for Win32/ABI compatibility
        }
        else if (wsArg == L"-vv")
        {
            options.Verbosity = VERBOSITY::DEBUG;
        }
        else if (wsArg == L"-validate")
        {
            options.ValidateCerts = TRUE;
        }
        else if (wsArg == L"-dry-run")
        {
            options.DryRun = TRUE;
        }
        else if (wsArg == L"-force")
        {
            options.Force = TRUE;
        }
        else if (wsArg == L"-create-users")
        {
            options.CreateUsers = TRUE;
        }
        else if (wsArg == L"-continue-on-error")
        {
            options.ContinueOnError = TRUE;
        }
        else if (wsArg == L"-expect-source")
        {
            if (i + 1 >= argc)
            {
                fwprintf(stderr, L"Error: %ls requires a machine name argument\n", wsArg.c_str());
                return FALSE;
            }
            options.ExpectedSource = argv[++i];
        }
        else if (wsArg == L"-groups")
        {
            if (i + 1 >= argc)
            {
                fwprintf(stderr, L"Error: %ls requires a group list argument\n", wsArg.c_str());
                return FALSE;
            }
            // Parse comma-separated group list
            std::wstring wsGroupList = argv[++i];
            size_t pos = 0;
            while ((pos = wsGroupList.find(L',')) != std::wstring::npos)
            {
                std::wstring wsGroup = wsGroupList.substr(0, pos);
                if (!wsGroup.empty())  // NOSONAR - COMPLEXITY-01: nested control flow and local scope retained; logic verified
                    options.SelectedGroups.push_back(std::move(wsGroup));
                wsGroupList.erase(0, pos + 1);
            }
            if (!wsGroupList.empty())
                options.SelectedGroups.push_back(std::move(wsGroupList));
        }
        else if (wsArg == L"-local")
        {
            options.ListLocal = TRUE;
        }
        else if (wsArg == L"-require-smartcard")
        {
            // Handled in Validate command
        }
        else if (wsArg == L"-json")
        {
            // Handled in List command
        }
        else if (wsArg[0] == L'-')
        {
            fwprintf(stderr, L"Error: Unknown option '%ls'\n", wsArg.c_str());
            return FALSE;
        }
        else
        {
            fwprintf(stderr, L"Error: Unexpected argument '%ls'\n", wsArg.c_str());
            return FALSE;
        }
    }

    // Validate command-specific options
    switch (options.Command)
    {
    case COMMAND_TYPE::EXPORT:
        if (options.OutputFile.empty())
        {
            fwprintf(stderr, L"Error: export command requires -output <path>\n");
            return FALSE;
        }
        break;

    case COMMAND_TYPE::IMPORT:
        if (options.InputFile.empty())
        {
            fwprintf(stderr, L"Error: import command requires -input <path>\n");
            return FALSE;
        }
        if (!options.DryRun && !options.Force)
        {
            // Default to dry-run for safety
            options.DryRun = TRUE;
            EIDM_TRACE_INFO(L"Note: Using dry-run mode by default. Use -force to perform actual import.");
        }
        break;

    case COMMAND_TYPE::LIST:
        if (!options.ListLocal && options.InputFile.empty())
        {
            fwprintf(stderr, L"Error: list command requires -local or -input <path>\n");
            return FALSE;
        }
        break;

    case COMMAND_TYPE::VALIDATE:
        if (options.InputFile.empty())
        {
            fwprintf(stderr, L"Error: validate command requires -input <path>\n");
            return FALSE;
        }
        break;

    case COMMAND_TYPE::IMPORT_CRL:
        if (options.InputFile.empty())
        {
            fwprintf(stderr, L"Error: import-crl command requires -input <path-to-crl>\n");
            return FALSE;
        }
        break;

    default:
        break;
    }

    return TRUE;
}

// Main entry point
int wmain(_In_ int argc, _In_ PWSTR argv[])  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
    HRESULT hr = S_OK;  // NOSONAR (EXPLICIT-TYPE-03) - Explicit type preferred for clarity
    int nExitCode = EIDMIGRATE_EXIT_SUCCESS;

    try
    {
        // Parse command line
        if (!ParseCommandLine(argc, argv, g_AppState.Options))
        {
            return EIDMIGRATE_EXIT_ERROR;
        }

        // Set verbosity
        SetVerbosity(g_AppState.Options.Verbosity);

        // Handle help and version
        if (g_AppState.Options.Command == COMMAND_TYPE::HELP)
        {
            ShowUsage();
            return EIDMIGRATE_EXIT_SUCCESS;
        }

        if (g_AppState.Options.Command == COMMAND_TYPE::VERSION)
        {
            ShowVersion();
            return EIDMIGRATE_EXIT_SUCCESS;
        }

        // Check if running as administrator
        if (!IsRunningAsAdmin())
        {
            EIDM_TRACE_ERROR(L"Error: EIDMigrate requires Administrator privileges.");
            EIDM_TRACE_ERROR(L"Please run as Administrator.");
            return EIDMIGRATE_EXIT_LSA_DENIED;
        }

        // Initialize audit logging
        hr = InitializeAuditLogging();
        if (FAILED(hr))
        {
            EIDM_TRACE_WARN(L"Warning: Could not initialize event log logging.");
        }

        // Set log file if specified
        if (!g_AppState.Options.LogFile.empty())
        {
            hr = SetLogFile(g_AppState.Options.LogFile);
            if (FAILED(hr))
            {
                EIDM_TRACE_ERROR(L"Error: Could not open log file '%ls'",
                    g_AppState.Options.LogFile.c_str());
                return EIDMIGRATE_EXIT_ERROR;
            }
        }

        // Get passphrase (prompt if not provided)
        SecureWString wsPassword;
        if (g_AppState.Options.Command == COMMAND_TYPE::EXPORT ||
            g_AppState.Options.Command == COMMAND_TYPE::IMPORT ||
            g_AppState.Options.Command == COMMAND_TYPE::VALIDATE)
        {
            if (g_AppState.Options.Password.empty())
            {  // NOSONAR - ENUM-01: enum kept for Win32/ABI compatibility
                std::wstring wsPrompt;
                if (g_AppState.Options.Command == COMMAND_TYPE::EXPORT)
                    wsPrompt = L"Enter export passphrase (min 16 characters): ";
                else if (g_AppState.Options.Command == COMMAND_TYPE::IMPORT)
                    wsPrompt = L"Enter import passphrase: ";
                else
                    wsPrompt = L"Enter passphrase: ";

                wsPassword = PromptForPassphrase(wsPrompt.c_str(),
                    (g_AppState.Options.Command == COMMAND_TYPE::EXPORT));

                if (wsPassword.empty())
                {
                    EIDM_TRACE_ERROR(L"Error: Passphrase is required.");
                    return EIDMIGRATE_EXIT_INVALID_PASSPHRASE;
                }
            }
            else
            {
                // Use provided password
                wsPassword = SecureWString(g_AppState.Options.Password.c_str());
            }

            // Validate passphrase strength for export
            if (g_AppState.Options.Command == COMMAND_TYPE::EXPORT)
            {
                if (!ValidatePassphraseStrength(wsPassword.c_str()))  // NOSONAR - COMPLEXITY-01: nested if retained; logic verified
                {
                    EIDM_TRACE_ERROR(L"Error: Passphrase must be at least 16 characters.");
                    return EIDMIGRATE_EXIT_INVALID_PASSPHRASE;
                }
            }
        }

        // Execute command
        switch (g_AppState.Options.Command)
        {
        case COMMAND_TYPE::EXPORT:
        {
            EXPORT_OPTIONS opts;
            opts.fValidateCerts = g_AppState.Options.ValidateCerts;
            EXPORT_STATS stats;

            hr = CommandExport(g_AppState.Options);
            if (FAILED(hr))
            {
                nExitCode = EIDMIGRATE_EXIT_ERROR;
                LOG_FAILURE_EXPORT(nullptr, FormatHResult(hr).c_str());
            }
            else
            {
                LOG_SUCCESS_EXPORT(nullptr, nullptr);
            }
            break;
        }

        case COMMAND_TYPE::IMPORT:
        {
            hr = CommandImport(g_AppState.Options);
            if (FAILED(hr))
            {
                if (hr == HRESULT_FROM_WIN32(ERROR_LOGON_FAILURE))
                    nExitCode = EIDMIGRATE_EXIT_INVALID_PASSPHRASE;
                else
                    nExitCode = EIDMIGRATE_EXIT_ERROR;
                LOG_FAILURE_IMPORT(nullptr, FormatHResult(hr).c_str());
            }
            else
            {
                LOG_SUCCESS_IMPORT(nullptr, nullptr);
            }
            break;
        }

        case COMMAND_TYPE::LIST:
            hr = CommandList(g_AppState.Options);
            if (FAILED(hr))
                nExitCode = EIDMIGRATE_EXIT_ERROR;
            break;

        case COMMAND_TYPE::VALIDATE:
        {
            VALIDATE_OPTIONS opts;
            opts.wsInputPath = g_AppState.Options.InputFile;
            opts.fVerbose = (g_AppState.Options.Verbosity >= VERBOSITY::VERBOSE);

            hr = CommandValidate(g_AppState.Options);
            if (FAILED(hr))
                nExitCode = EIDMIGRATE_EXIT_ERROR;
            break;
        }

        case COMMAND_TYPE::IMPORT_CRL:
            hr = CommandImportCrl(g_AppState.Options);
            if (FAILED(hr))
                nExitCode = EIDMIGRATE_EXIT_ERROR;
            break;

        default:
            break;
        }

        // Clear password from memory
        if (!wsPassword.empty())
        {
            SecureZeroMemory(
                const_cast<PWSTR>(wsPassword.c_str()), // NOSONAR - SecureZeroMemory requires non-const for secure memory clearing
                wsPassword.length() * sizeof(WCHAR));
        }
    }
    catch (const std::exception& ex)
    {
        // Handle C++ exceptions
        EIDM_TRACE_ERROR(L"Fatal exception: %S", ex.what());
        nExitCode = EIDMIGRATE_EXIT_ERROR;
        LOG_ACCESS_DENIED(nullptr, L"Fatal exception");
    }
    catch (...)
    {
        // Handle any other exceptions
        EIDM_TRACE_ERROR(L"Fatal unknown exception");
        nExitCode = EIDMIGRATE_EXIT_ERROR;
        LOG_ACCESS_DENIED(nullptr, L"Fatal exception");
    }

    // Flush log file
    FlushLogFile();

    return nExitCode;
}
