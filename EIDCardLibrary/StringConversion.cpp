#include "StringConversion.h"
#include <stdarg.h>
#include <algorithm>
#include <climits>
#include <cstring>

namespace EID {

    std::wstring LoadStringW(HINSTANCE hInst, UINT uID)
    {
        wchar_t buffer[512] = { 0 };  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
        int result = ::LoadStringW(hInst, uID, buffer, ARRAYSIZE(buffer) - 1);
        if (result > 0) {  // NOSONAR - SCOPE-01: declaration kept in enclosing scope
            return std::wstring(buffer);
        }
        return std::wstring();
    }

    std::wstring GetWindowTextW(HWND hWnd)
    {
        if (!hWnd || !IsWindow(hWnd)) {
            return std::wstring();
        }

        int len = ::GetWindowTextLengthW(hWnd);
        if (len <= 0) {
            return std::wstring();
        }

        std::wstring result(len + 1, L'\0');
        ::GetWindowTextW(hWnd, &result[0], len + 1);
        result.resize(len);
        return result;
    }

    BOOL SetWindowTextW(HWND hWnd, const std::wstring& text)
    {
        if (!hWnd || !IsWindow(hWnd)) {
            return FALSE;
        }
        return ::SetWindowTextW(hWnd, text.c_str());
    }

    std::wstring Format(const wchar_t* format, ...)  // NOSONAR - VARIADIC-01: Format function requires variadic arguments
    {
        if (!format) {
            return std::wstring();
        }

        va_list args;
        va_start(args, format);

        // First pass: get the required length. It consumes a va_list, so it
        // works on a copy - reusing args itself for the second pass is
        // undefined behaviour.
        va_list argsCopy;
        va_copy(argsCopy, args);
        const int cch = _vscwprintf(format, argsCopy);
        va_end(argsCopy);
        // -1 is a formatting error; INT_MAX would overflow the +1 below.
        if (cch <= 0 || cch >= INT_MAX) {
            va_end(args);
            return std::wstring();
        }

        // Allocate and format. _TRUNCATE: never the CRT invalid-parameter
        // handler (which terminates the process) if the two passes disagree.
        std::vector<wchar_t> buffer(static_cast<size_t>(cch) + 1);
        const int written = _vsnwprintf_s(buffer.data(), buffer.size(), _TRUNCATE, format, args);
        va_end(args);
        if (written < 0) {
            return std::wstring();
        }

        return std::wstring(buffer.data(), static_cast<size_t>(written));
    }

    std::wstring BuildContainerNameFromReader(const std::wstring& readerName)
    {
        return L"\\\\.\\" + readerName + L"\\";  // NOSONAR - STRING-01: escaped literal retained to preserve device path
    }

    std::wstring SafeConvert(const char* src, size_t maxLen)
    {
        if (!src || maxLen == 0) {
            return std::wstring();
        }

        // Find actual length (null-terminated or max length)
        size_t len = strnlen(src, maxLen);

        // Convert from UTF-8 to Unicode
        int wideCharCount = MultiByteToWideChar(CP_UTF8, 0, src, (int)len, nullptr, 0);
        if (wideCharCount <= 0) {
            return std::wstring();
        }

        std::wstring result(wideCharCount, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, src, (int)len, &result[0], wideCharCount);
        return result;
    }

    std::wstring SafeConvert(const wchar_t* src, size_t maxLen)
    {
        if (!src || maxLen == 0) {
            return std::wstring();
        }

        size_t len = wcsnlen(src, maxLen);
        return std::wstring(src, len);
    }

    std::wstring RegQueryStringW(HKEY hKey, const std::wstring& valueName)
    {
        if (!hKey) {
            return std::wstring();
        }

        wchar_t buffer[1024] = { 0 };  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
        DWORD bufferSize = sizeof(buffer);
        DWORD dataType = 0;

        LONG result = RegQueryValueExW(hKey, valueName.c_str(), nullptr, &dataType,
                                       (LPBYTE)buffer, &bufferSize);

        if (result != ERROR_SUCCESS || dataType != REG_SZ) {  // NOSONAR - SCOPE-01: declaration kept in enclosing scope
            return std::wstring();
        }

        return std::wstring(buffer);
    }

    void ConvertToUnicodeString(const std::wstring& src, PUNICODE_STRING dst, PVOID buffer, ULONG bufferSize) // NOSONAR - PVOID (void*) is standard Windows API type for generic pointers
    {
        if (!dst || !buffer) {
            return;
        }

        size_t charCount = src.length() + 1;
        if (charCount * sizeof(wchar_t) > bufferSize) {  // NOSONAR - SCOPE-01: declaration kept in enclosing scope
            // Buffer too small
            dst->Length = 0;
            dst->MaximumLength = 0;
            dst->Buffer = nullptr;
            return;
        }

        wchar_t* bufPtr = (wchar_t*)buffer;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
        errno_t err = wcscpy_s(bufPtr, bufferSize / sizeof(wchar_t), src.c_str());
        if (err == 0) {
            dst->Buffer = bufPtr;
            dst->Length = (USHORT)(src.length() * sizeof(wchar_t));
            dst->MaximumLength = (USHORT)bufferSize;
        } else {
            dst->Length = 0;
            dst->MaximumLength = 0;
            dst->Buffer = nullptr;
        }
    }

    void SecureZeroString(std::wstring& str)
    {
        // Overwrite string memory with zeros before deallocation
        if (!str.empty()) {
            SecureZeroMemory(&str[0], str.length() * sizeof(wchar_t));
        }
        str.clear();
        str.shrink_to_fit();
    }

    std::wstring ConvertCharToWString(const char* src)
    {
        if (!src || src[0] == '\0') {
            return std::wstring();
        }

        // Use strnlen with a reasonable max bound for safety (SonarQube cpp:S5813)
        // Max path + filename on Windows is ~260 characters, use 4096 as safe upper bound
        size_t len = strnlen(src, 4096);
        return SafeConvert(src, len);
    }

    std::string ConvertWStringToChar(const std::wstring& src)
    {
        if (src.empty()) {
            return std::string();
        }

        int charCount = WideCharToMultiByte(CP_UTF8, 0, src.c_str(), (int)src.length(), nullptr, 0, nullptr, nullptr);
        if (charCount <= 0) {
            return std::string();
        }

        std::string result(charCount, '\0');
        WideCharToMultiByte(CP_UTF8, 0, src.c_str(), (int)src.length(), &result[0], charCount, nullptr, nullptr);
        return result;
    }
}
