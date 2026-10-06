#pragma once

// File: EIDMigrate/SecureMemory.h
// Secure memory management classes that zero sensitive data on destruction

#include <Windows.h>
#include <string>
#include <vector>
#include <memory>

// Secure allocator that zeros memory on deallocation
template<typename T>
class SecureAllocator
{
public:
    using value_type = T;
    using pointer = T*;
    using const_pointer = const T*;
    using size_type = size_t;
    using difference_type = ptrdiff_t;

    // C++17/20 allocator propagation traits
    using propagate_on_container_copy_assignment = std::true_type;
    using propagate_on_container_move_assignment = std::true_type;
    using propagate_on_container_swap = std::true_type;
    using is_always_equal = std::true_type;

    // Rebind for C++14 and earlier (not needed in C++17+ but kept for compatibility)
    template<typename U>
    struct rebind
    {
        using other = SecureAllocator<U>;
    };

    // Default constructor
    SecureAllocator() = default;

    // Converting constructor (allows allocator<T> to construct allocator<U>)
    template<typename U>
    SecureAllocator(const SecureAllocator<U>&) noexcept {}  // NOSONAR - API-01: implicit converting constructor required by Allocator concept

    pointer allocate(size_type n)
    {
        pointer p = static_cast<pointer>(malloc(n * sizeof(T)));  // NOSONAR - ALLOC-01: malloc paired with free in deallocate
        if (!p)
        {
            throw std::bad_alloc();
        }
        return p;
    }

    void deallocate(pointer p, size_type n) noexcept // NOSONAR - allocator deallocates memory (clears and frees), cannot be const
    {
        if (p)
        {
            SecureZeroMemory(p, n * sizeof(T));
            free(p);  // NOSONAR - ALLOC-01: free paired with malloc in allocate
        }
    }
};

// Stateless allocator: all instances are interchangeable (required by the
// Allocator requirements; containers may compare allocators on assignment).
template<typename T, typename U>
inline bool operator==(const SecureAllocator<T>&, const SecureAllocator<U>&) noexcept { return true; }
template<typename T, typename U>
inline bool operator!=(const SecureAllocator<T>&, const SecureAllocator<U>&) noexcept { return false; }

// Secure wide string type that zeros on destruction
using SecureWString = std::basic_string<WCHAR, std::char_traits<WCHAR>, SecureAllocator<WCHAR>>;

// Secure ANSI string type that zeros on destruction
using SecureString = std::basic_string<CHAR, std::char_traits<CHAR>, SecureAllocator<CHAR>>;

// clear() keeps the buffer (and, for short strings, the inline small-string
// buffer that never reaches the allocator) with its old contents. Zero the
// characters first, then clear.
inline void SecureClear(_Inout_ SecureWString& s) noexcept
{
    if (!s.empty())
        SecureZeroMemory(&s[0], s.size() * sizeof(WCHAR));
    s.clear();
}

// Secure buffer for binary data
class SecureBuffer
{
private:
    PBYTE m_pbData;
    DWORD m_cbSize;
    BOOL m_fLocked;

public:
    SecureBuffer();
    explicit SecureBuffer(DWORD cbSize);
    ~SecureBuffer();

    // Delete copy
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // Move constructor/assignment
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    PBYTE data() { return m_pbData; }
    PBYTE data() const { return m_pbData; }
    DWORD size() const { return m_cbSize; }
    bool empty() const { return m_pbData == nullptr; }
    bool locked() const { return m_fLocked; }

    // Prevent swapping to disk
    BOOL Lock();
    void Unlock();

    // Resize buffer
    BOOL Resize(DWORD cbNewSize);

    // Clear contents
    void Clear();
};

// Secure PIN handling with automatic cleanup
class SecurePin
{
private:
    SecureWString m_wsPin;

public:
    SecurePin();
    explicit SecurePin(PCWSTR pwszPin);
    ~SecurePin();

    // Delete copy
    SecurePin(const SecurePin&) = delete;
    SecurePin& operator=(const SecurePin&) = delete;

    // Move
    SecurePin(SecurePin&& other) noexcept;
    SecurePin& operator=(SecurePin&& other) noexcept;

    PCWSTR c_str() const { return m_wsPin.c_str(); }
    size_t length() const { return m_wsPin.length(); }
    bool empty() const { return m_wsPin.empty(); }

    void Set(_In_z_ PCWSTR pwszPin);
    void Clear();
};

// Secure passphrase (same as SecurePin but with different semantics)
using SecurePassphrase = SecurePin;

// Exception-safe scope for crypto operations
class CryptoOperationScope  // NOSONAR - OWNERSHIP-01: manual Win32 lifetime management
{
private:
    std::vector<SecureBuffer> m_sensitiveBuffers;
    std::vector<SecureWString> m_sensitiveStrings;

public:
    // Allocate a secure buffer
    PBYTE AllocateBuffer(DWORD cbSize);

    // Allocate a secure string
    PWSTR AllocateString(size_t cchChars);

    // Clear all sensitive data
    void Clear();

    ~CryptoOperationScope() { Clear(); }
};

// Secure memory utility functions
void SecureFree(_In_ PVOID pvMem, _In_ SIZE_T cbSize);
PVOID SecureAlloc(_In_ SIZE_T cbSize);
