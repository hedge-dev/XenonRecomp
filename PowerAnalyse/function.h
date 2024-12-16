#pragma once

#include <cstddef>
#include <vector>

#ifdef _DEBUG
#define DEBUG(X) X
#else
#define DEBUG(X)
#endif

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
    static Function Analyze(const void* code, size_t size, size_t base);
};
