#pragma once
#include <cstdint>
#include <string>

enum SectionFlags : uint8_t
{
    SectionFlags_None = 0,
    SectionFlags_Data = 1,
    SectionFlags_Code = 2
};

struct Section
{
    std::string name {};
    size_t base {};
    uint32_t size {};
    SectionFlags flags {};
    uint8_t* data {};

    bool operator<(size_t address) const
    {
        return address < base;
    }

    bool operator>(size_t address) const
    {
        return address >= (base + size);
    }

    bool operator==(size_t address) const
    {
        return address >= base && address < base + size;
    }
};

struct SectionComparer
{
    using is_transparent = void;

    bool operator()(const Section& lhs, size_t rhs) const
    {
        return lhs.base < rhs;
    }

    bool operator()(size_t lhs, const Section& rhs) const
    {
        return lhs < rhs.base;
    }

    bool operator()(const Section& lhs, const Section& rhs) const
    {
        return lhs.base < rhs.base;
    }
};
