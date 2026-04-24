#pragma once

#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

#ifdef _DEBUG
#define DEBUG(X) X
#else
#define DEBUG(X)
#endif

// Optional switch-table map consumed by the block walker in
// Function::Analyze when it reaches an unconditional bctr at a known
// switch-dispatch site. When the caller hands in a populated map, the
// walker pushes every label (and the default) as a successor block
// instead of terminating, which grows `fn.size` to include switch-
// dispatched code that the legacy walker would discard via the end-
// of-Analyze discontinuity pass.
//
// The map is keyed by the BCTR guest VA — NOT by the first-instruction-
// of-pattern VA that XenonAnalyse's own switch-table TOML emits. The
// caller (typically XenonRecomp) performs the switch-base → bctr-VA
// offset math at map-construction time and hands us a pre-keyed map.
//
// Passing nullptr (the default) preserves the legacy walker behavior
// byte-for-byte. No existing callers need to change.
struct AnalyzerSwitchTable
{
    uint32_t defaultLabel{};
    std::vector<uint32_t> labels{};
};

using AnalyzerSwitchTableMap = std::unordered_map<uint32_t, AnalyzerSwitchTable>;

struct Function
{
    struct Block
    {
        size_t base{};
        size_t size{};
        size_t projectedSize{ static_cast<size_t>(-1) }; // scratch
        DEBUG(size_t parent{});

        Block()
        {
        }

        Block(size_t base, size_t size)
            : base(base), size(size)
        {
        }

        Block(size_t base, size_t size, size_t projectedSize)
            : base(base), size(size), projectedSize(projectedSize)
        {
        }
    };

    size_t base{};
    size_t size{};
    std::vector<Block> blocks{};

    Function()
    {
    }

    Function(size_t base, size_t size)
        : base(base), size(size)
    {
    }

    size_t SearchBlock(size_t address) const;
    static Function Analyze(const void* code, size_t size, size_t base,
                            const AnalyzerSwitchTableMap* switchMap = nullptr);
};
