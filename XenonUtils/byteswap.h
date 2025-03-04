#pragma once 

#include <cassert>

#ifdef __clang__
#define _byte_swap16(value) __builtin_bswap16(static_cast<uint16_t>(value))
#define _byte_swap32(value) __builtin_bswap32(static_cast<uint32_t>(value))
#define _byte_swap64(value) __builtin_bswap64(static_cast<uint64_t>(value))
#elif defined(_MSC_VER)
#define _byte_swap16(value) _byteswap_ushort(static_cast<uint16_t>(value))
#define _byte_swap32(value) _byteswap_ulong(static_cast<uint32_t>(value))
#define _byte_swap64(value) _byteswap_uint64(static_cast<uint64_t>(value))
#endif

template<typename T> T ByteSwap(T value)
{
    if constexpr (sizeof(T) == 1)
        return value;
    if constexpr (sizeof(T) == 2)
        return static_cast<T>(_byte_swap16(value));
    if constexpr (sizeof(T) == 4)
        return static_cast<T>(_byte_swap32(value));
    if constexpr (sizeof(T) == 8)
        return static_cast<T>(_byte_swap64(value));

    assert(false && "Unexpected byte size.");
}

template<typename T> void ByteSwapInplace(T& value)
{
    value = ByteSwap(value);
}
