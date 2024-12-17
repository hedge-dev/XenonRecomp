#include <cassert>
#include <iterator>
#include <file.h>
#include <disasm.h>
#include <image.h>
#include <xbox.h>
#include <fmt/core.h>
#include "function.h"

#define SWITCH_ABSOLUTE 0
#define SWITCH_COMPUTED 1
#define SWITCH_BYTEOFFSET 2
#define SWITCH_SHORTOFFSET 3

struct SwitchTable
{
    std::vector<size_t> labels{};
    size_t base{};
    size_t defaultLabel{};
    uint32_t r{};
    uint32_t type{};
};

void ReadTable(Image& image, SwitchTable& table)
{
    uint32_t pOffset;
    ppc_insn insn;
    auto* code = (uint32_t*)image.Find(table.base);
    ppc::Disassemble(code, table.base, insn);
    pOffset = insn.operands[1] << 16;

    ppc::Disassemble(code + 1, table.base + 4, insn);
    pOffset += insn.operands[2];

    if (table.type == SWITCH_ABSOLUTE)
    {
        const auto* offsets = (be<uint32_t>*)image.Find(pOffset);
        for (size_t i = 0; i < table.labels.size(); i++)
        {
            table.labels[i] = offsets[i];
        }
    }
    else if (table.type == SWITCH_COMPUTED)
    {
        uint32_t base;
        uint32_t shift;
        const auto* offsets = (uint8_t*)image.Find(pOffset);

        ppc::Disassemble(code + 4, table.base + 0x10, insn);
        base = insn.operands[1] << 16;

        ppc::Disassemble(code + 5, table.base + 0x14, insn);
        base += insn.operands[2];

        ppc::Disassemble(code + 3, table.base + 0x0C, insn);
        shift = insn.operands[2];

        for (size_t i = 0; i < table.labels.size(); i++)
        {
            table.labels[i] = base + (offsets[i] << shift);
        }
    }
    else if (table.type == SWITCH_BYTEOFFSET || table.type == SWITCH_SHORTOFFSET)
    {
        if (table.type == SWITCH_BYTEOFFSET)
        {
            const auto* offsets = (uint8_t*)image.Find(pOffset);
            uint32_t base;

            ppc::Disassemble(code + 3, table.base + 0x0C, insn);
            base = insn.operands[1] << 16;

            ppc::Disassemble(code + 4, table.base + 0x10, insn);
            base += insn.operands[2];

            for (size_t i = 0; i < table.labels.size(); i++)
            {
                table.labels[i] = base + offsets[i];
            }
        }
        else if (table.type == SWITCH_SHORTOFFSET)
        {
            const auto* offsets = (be<uint16_t>*)image.Find(pOffset);
            uint32_t base;

            ppc::Disassemble(code + 4, table.base + 0x10, insn);
            base = insn.operands[1] << 16;

            ppc::Disassemble(code + 5, table.base + 0x14, insn);
            base += insn.operands[2];

            for (size_t i = 0; i < table.labels.size(); i++)
            {
                table.labels[i] = base + offsets[i];
            }
        }
    }
    else
    {
        assert(false);
    }
}

void ScanTable(const uint32_t* code, size_t base, SwitchTable& table)
{
    ppc_insn insn;
    uint32_t cr{ (uint32_t)-1 };
    for (int i = 0; i < 32; i++)
    {
        ppc::Disassemble(&code[-i], base - (4 * i), insn);
        if (insn.opcode == nullptr)
        {
            continue;
        }

        if (cr == -1 && (insn.opcode->id == PPC_INST_BGT || insn.opcode->id == PPC_INST_BGTLR || insn.opcode->id == PPC_INST_BLE || insn.opcode->id == PPC_INST_BLELR))
        {
            cr = insn.operands[0];
            if (insn.opcode->operands[1] != 0)
            {
                table.defaultLabel = insn.operands[1];
            }
        }
        else if (cr != -1)
        {
            if (insn.opcode->id == PPC_INST_CMPLWI && insn.operands[0] == cr)
            {
                table.r = insn.operands[1];
                table.labels.resize(insn.operands[2] + 1);
                table.base = base;
                break;
            }
        }
    }
}

void MakeMask(const uint32_t* instructions, size_t count)
{
    ppc_insn insn;
    for (size_t i = 0; i < count; i++)
    {
        ppc::Disassemble(&instructions[i], 0, insn);
        fmt::println("0x{:X}, // {}", ByteSwap(insn.opcode->opcode | (insn.instruction & insn.opcode->mask)), insn.opcode->name);
    }
}

void* SearchMask(const void* source, const uint32_t* compare, size_t compareCount, size_t size)
{
    assert(size % 4 == 0);
    uint32_t* src = (uint32_t*)source;
    size_t count = size / 4;
    ppc_insn insn;

    for (size_t i = 0; i < count; i++)
    {
        size_t c = 0;
        for (c = 0; c < compareCount; c++)
        {
            ppc::Disassemble(&src[i + c], 0, insn);
            if (insn.opcode == nullptr || insn.opcode->id != compare[c])
            {
                break;
            }
        }

        if (c == compareCount)
        {
            return &src[i];
        }
    }

    return nullptr;
}

int main()
{
    const auto file = LoadFile("private/default.xex");
    auto image = Image::ParseImage(file.data(), file.size());

    std::string out;
    auto println = [&]<class... Args>(fmt::format_string<Args...> fmt, Args&&... args)
    {
        fmt::vformat_to(std::back_inserter(out), fmt.get(), fmt::make_format_args(args...));
        out += '\n';
    };
    //for (const auto& section : image.sections)
    //{
    //    image.symbols.emplace(section.name, section.base, section.size, Symbol_Section);
    //}

    // MakeMask((uint32_t*)image.Find(0x82C40D84), 6);

    //auto data = "\x4D\x99\x00\x20";
    //auto data2 = ByteSwap((2129));
    //ppc_insn insn;
    //ppc_insn insn2;
    //ppc::Disassemble(data, 0, insn);
    //ppc::Disassemble(&data2, 0, insn2);
    //auto op = PPC_OP(insn.instruction);
    //auto xop = PPC_XOP(insn.instruction);

    auto printTable = [&](const SwitchTable& table)
        {
            println("[[switch]]");
            println("base = 0x{:X}", table.base);
            println("r = {}", table.r);
            println("default = 0x{:X}", table.defaultLabel);
            println("labels = [");
            for (const auto& label : table.labels)
            {
                println("    0x{:X},", label);
            }

            println("]");
            println("");
        };

    std::vector<SwitchTable> switches{};

    auto insertTable = [&](size_t base, size_t defaultLabel, size_t r, size_t nLabels, uint32_t type)
        {
            auto& sw = switches.emplace_back();
            sw.base = base;
            sw.defaultLabel = defaultLabel;
            sw.r = r;
            sw.labels.resize(nLabels);
            sw.type = type;
        };

    println("# Generated by PowerAnalyse");
    insertTable(0x830ADAD8, 0x830ADB28, 11, 0x1B, SWITCH_COMPUTED);
    insertTable(0x830AE1B0, 0x830AE21C, 11, 0x1B, SWITCH_BYTEOFFSET);
    insertTable(0x82CFE120, 0x82CFDE68, 11, 0x10, SWITCH_SHORTOFFSET);

    println("# ---- MANUAL JUMPTABLE ----");
    for (auto& table : switches)
    {
        ReadTable(image, table);
        printTable(table);
    }

    auto scanPattern = [&](uint32_t* pattern, size_t count, size_t type)
        {
            for (const auto& section : image.sections)
            {
                if (!(section.flags & SectionFlags_Code))
                {
                    continue;
                }

                size_t base = section.base;
                uint8_t* data = section.data;
                uint8_t* dataStart = section.data;
                uint8_t* dataEnd = section.data + section.size;
                while (data < dataEnd && data != nullptr)
                {
                    data = (uint8_t*)SearchMask(data, pattern, count, dataEnd - data);

                    if (data != nullptr)
                    {
                        SwitchTable table{};
                        table.type = type;
                        ScanTable((uint32_t*)data, base + (data - dataStart), table);

                        // fmt::println("{:X} ; jmptable - {}", base + (data - dataStart), table.labels.size());
                        if (table.base != 0)
                        {
                            ReadTable(image, table);
                            printTable(table);
                            switches.emplace_back(std::move(table));
                        }

                        data += 4;
                    }
                    continue;
                }
            }
        };

    uint32_t absoluteSwitch[] =
    {
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_RLWINM,
        PPC_INST_LWZX,
        PPC_INST_MTCTR,
        PPC_INST_BCTR,
    };

    uint32_t computedSwitch[] =
    {
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_LBZX,
        PPC_INST_RLWINM,
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_ADD,
        PPC_INST_MTCTR,
    };

    uint32_t offsetSwitch[] =
    {
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_LBZX,
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_ADD,
        PPC_INST_MTCTR,
    };

    uint32_t wordOffsetSwitch[] =
    {
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_RLWINM,
        PPC_INST_LHZX,
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_ADD,
        PPC_INST_MTCTR,
    };

    println("# ---- ABSOLUTE JUMPTABLE ----");
    scanPattern(absoluteSwitch, std::size(absoluteSwitch), SWITCH_ABSOLUTE);

    println("# ---- COMPUTED JUMPTABLE ----");
    scanPattern(computedSwitch, std::size(computedSwitch), SWITCH_COMPUTED);

    println("# ---- OFFSETED JUMPTABLE ----");
    scanPattern(offsetSwitch, std::size(offsetSwitch), SWITCH_BYTEOFFSET);
    scanPattern(wordOffsetSwitch, std::size(wordOffsetSwitch), SWITCH_SHORTOFFSET);

    FILE* f = fopen("out/switches.toml", "w");
    fwrite(out.data(), 1, out.size(), f);
    fclose(f);

    uint32_t cxxFrameHandler = ByteSwap(0x831B1C90);
    uint32_t cSpecificFrameHandler = ByteSwap(0x8324B3BC);
    image.symbols.emplace("__CxxFrameHandler", 0x831B1C90, 0x38, Symbol_Function);
    image.symbols.emplace("__C_specific_handler", 0x8324B3BC, 0x38, Symbol_Function);
    image.symbols.emplace("memcpy", 0x831B0ED0, 0x488, Symbol_Function);
    image.symbols.emplace("memset", 0x831B0BA0, 0xA0, Symbol_Function);
    image.symbols.emplace("blkmov", 0x831B1358, 0xA8, Symbol_Function);

    image.symbols.emplace(fmt::format("sub_{:X}", 0x82EF5D78), 0x82EF5D78, 0x3F8, Symbol_Function);

    // auto fnd = Function::Analyze(image.Find(0x82C40D58), image.size, 0x82C40D58);

    std::vector<Function> functions;
    auto& pdata = *image.Find(".pdata");
    size_t count = pdata.size / sizeof(IMAGE_CE_RUNTIME_FUNCTION);
    auto* pf = (IMAGE_CE_RUNTIME_FUNCTION*)pdata.data;
    for (size_t i = 0; i < count; i++)
    {
        auto fn = pf[i];
        fn.BeginAddress = ByteSwap(fn.BeginAddress);
        fn.Data = ByteSwap(fn.Data);

        auto& f = functions.emplace_back();
        f.base = fn.BeginAddress;
        f.size = fn.FunctionLength * 4;

        if (f.base == 0x82BD7420)
        {
            __builtin_debugtrap();
        }

        image.symbols.emplace(fmt::format("sub_{:X}", f.base), f.base, f.size, Symbol_Function);
    }

    auto sym = image.symbols.find(0x82BD7420);

    std::vector<Function> missingFunctions;
    for (const auto& section : image.sections) 
    {
        if (!(section.flags & SectionFlags_Code))
        {
            continue;
        }
        size_t base = section.base;
        uint8_t* data = section.data;
        uint8_t* dataEnd = section.data + section.size;
        const Symbol* prevSymbol = nullptr;
        while (data < dataEnd)
        {
            if (*(uint32_t*)data == 0)
            {
                data += 4;
                base += 4;
                continue;
            }

            if (*(uint32_t*)data == cxxFrameHandler || *(uint32_t*)data == cSpecificFrameHandler)
            {
                data += 8;
                base += 8;
                continue;
            }

            auto fnSymbol = image.symbols.find(base);
            if (fnSymbol != image.symbols.end() && fnSymbol->type == Symbol_Function)
            {
                assert(fnSymbol->address == base);

                prevSymbol = &*fnSymbol;
                base += fnSymbol->size;
                data += fnSymbol->size;
            }
            else
            {
                auto& missingFn = missingFunctions.emplace_back(Function::Analyze(data, dataEnd - data, base));
                base += missingFn.size;
                data += missingFn.size;
                
                fmt::println("sub_{:X}", missingFn.base);
            }
        }
    }

    //ppc_insn insn;
    //uint8_t c[4] = { 0x10, 0x00, 0x59, 0xC3 };
    //ppc::Disassemble(c, 0x831D6C64, insn);
    //fmt::println("{:20}{}", insn.opcode->name, insn.op_str);


    const auto entrySymbol = image.symbols.find(image.entry_point);
    assert(entrySymbol != image.symbols.end());

    const auto entrySize = entrySymbol->size;
    image.symbols.erase(entrySymbol);

    image.symbols.emplace("_start", image.entry_point, entrySize, Symbol_Function);

    fmt::println("FUNCTIONS");
    for (const auto& fn : functions)
    {
        fmt::println("\tsub_{:X}", fn.base);
    }
    fmt::println("");
    

    fmt::println("SECTIONS");
    for (const auto& section : image.sections)
    {
        printf("Section %.8s\n", section.name.c_str());
        printf("\t%X-%X\n", section.base, section.base + section.size);
    }

    fmt::println("");
    return 0;
}
