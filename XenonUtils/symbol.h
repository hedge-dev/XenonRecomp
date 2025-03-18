#pragma once
#include <cstdint>
#include <string>

enum SymbolType
{
    Symbol_None,
    Symbol_Section,
    Symbol_Function,
    Symbol_Comment,
};

struct Symbol
{
    mutable std::string name {};
    size_t address {};
    size_t size {};
    mutable SymbolType type {};

    Symbol()
    {
    }

    Symbol(std::string name, size_t address, size_t size, SymbolType type)
        : name(std::move(name)), address(address), size(size), type(type)
    {
    }
};

struct SymbolComparer
{
    using is_transparent = void;

    bool operator()(const Symbol& lhs, size_t rhs) const
    {
        return lhs.address < rhs;
    }

    bool operator()(size_t lhs, const Symbol& rhs) const
    {
        return lhs < rhs.address;
    }

    bool operator()(const Symbol& lhs, const Symbol& rhs) const
    {
        return lhs.address < rhs.address;
    }
};
