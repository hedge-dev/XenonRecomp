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
    ppc_insn insn;
    auto* code = (uint32_t*)image.Find(table.base);

    // A jump-table dispatch builds its addresses with "lis rX, hi" / "addi rX,
    // rX, lo" pairs, but the compiler schedules other instructions between the
    // two halves and pads the sequence with nops, so the pieces are not at
    // fixed offsets. Locate them by opcode instead:
    //
    //   - the pair before the table load gives the table's address
    //   - the pair after it gives the base that the offsets are relative to
    //   - for a computed table, the shift is the rlwinm following the load
    constexpr int kWindow = 14;

    auto opcodeAt = [&](int i) -> const powerpc_opcode*
        {
            ppc::Disassemble(code + i, table.base + i * 4, insn);
            return insn.opcode;
        };

    // Complete the lis/addi pair whose lis sits at index i.
    auto resolvePair = [&](int i) -> uint32_t
        {
            ppc::Disassemble(code + i, table.base + i * 4, insn);
            uint32_t reg = insn.operands[0];
            uint32_t value = insn.operands[1] << 16;

            for (int j = i + 1; j < kWindow; j++)
            {
                ppc::Disassemble(code + j, table.base + j * 4, insn);
                if (insn.opcode == nullptr)
                    continue;
                if (insn.opcode->id == PPC_INST_LIS && insn.operands[0] == reg)
                    break;  // reloaded before this one was completed
                if (insn.opcode->id == PPC_INST_ADDI && insn.operands[0] == reg && insn.operands[1] == reg)
                {
                    value += insn.operands[2];
                    break;
                }
            }
            return value;
        };

    int loadIndex = -1;
    for (int i = 0; i < kWindow; i++)
    {
        const powerpc_opcode* op = opcodeAt(i);
        if (op != nullptr && (op->id == PPC_INST_LWZX || op->id == PPC_INST_LHZX || op->id == PPC_INST_LBZX))
        {
            loadIndex = i;
            break;
        }
    }

    uint32_t pOffset = 0;
    uint32_t base = 0;
    uint32_t shift = 0;
    bool haveOffset = false;
    bool haveBase = false;

    for (int i = 0; i < kWindow; i++)
    {
        const powerpc_opcode* op = opcodeAt(i);
        if (op == nullptr || op->id != PPC_INST_LIS)
            continue;

        if (loadIndex < 0 || i < loadIndex)
        {
            if (!haveOffset) { pOffset = resolvePair(i); haveOffset = true; }
        }
        else if (!haveBase)
        {
            base = resolvePair(i);
            haveBase = true;
        }
    }

    if (loadIndex >= 0)
    {
        for (int i = loadIndex + 1; i < kWindow; i++)
        {
            const powerpc_opcode* op = opcodeAt(i);
            if (op != nullptr && op->id == PPC_INST_RLWINM)
            {
                shift = insn.operands[2];
                break;
            }
        }
    }

    if (table.type == SWITCH_ABSOLUTE)
    {
        const auto* offsets = (be<uint32_t>*)image.Find(pOffset);
        for (size_t i = 0; i < table.labels.size(); i++)
            table.labels[i] = offsets[i];
    }
    else if (table.type == SWITCH_COMPUTED)
    {
        const auto* offsets = (uint8_t*)image.Find(pOffset);
        for (size_t i = 0; i < table.labels.size(); i++)
            table.labels[i] = base + (offsets[i] << shift);
    }
    else if (table.type == SWITCH_BYTEOFFSET)
    {
        const auto* offsets = (uint8_t*)image.Find(pOffset);
        for (size_t i = 0; i < table.labels.size(); i++)
            table.labels[i] = base + offsets[i];
    }
    else if (table.type == SWITCH_SHORTOFFSET)
    {
        const auto* offsets = (be<uint16_t>*)image.Find(pOffset);
        for (size_t i = 0; i < table.labels.size(); i++)
            table.labels[i] = base + offsets[i];
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
        size_t k = 0;
        for (c = 0; c < compareCount; c++, k++)
        {
            // These sequences get padded with nops; skip them so a scheduling
            // artefact does not hide an otherwise matching pattern.
            while (i + k < count)
            {
                ppc::Disassemble(&src[i + k], 0, insn);
                if (c > 0 && insn.opcode != nullptr && insn.opcode->id == PPC_INST_NOP)
                {
                    k++;
                    continue;
                }
                break;
            }

            if (i + k >= count || insn.opcode == nullptr || insn.opcode->id != compare[c])
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

static std::string out;

template<class... Args>
static void println(fmt::format_string<Args...> fmt, Args&&... args)
{
    fmt::vformat_to(std::back_inserter(out), fmt.get(), fmt::make_format_args(args...));
    out += '\n';
};

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        printf("Usage: XenonAnalyse [input XEX file path] [output jump table TOML file path]");
        return EXIT_SUCCESS;
    }

    const auto file = LoadFile(argv[1]);
    auto image = Image::ParseImage(file.data(), file.size());

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

    println("# Generated by XenonAnalyse");

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

    // Some XDK versions schedule the index shift between the lis and the addi.
    // Same tables, different instruction order.
    uint32_t absoluteSwitchShiftFirst[] =
    {
        PPC_INST_LIS, PPC_INST_RLWINM, PPC_INST_ADDI,
        PPC_INST_LWZX, PPC_INST_MTCTR, PPC_INST_BCTR,
    };

    uint32_t computedSwitchShiftFirst[] =
    {
        PPC_INST_LIS, PPC_INST_RLWINM, PPC_INST_ADDI, PPC_INST_LBZX,
        PPC_INST_LIS, PPC_INST_ADDI, PPC_INST_ADD, PPC_INST_MTCTR,
    };

    uint32_t wordOffsetSwitchShiftFirst[] =
    {
        PPC_INST_LIS, PPC_INST_RLWINM, PPC_INST_ADDI, PPC_INST_LHZX,
        PPC_INST_LIS, PPC_INST_ADDI, PPC_INST_ADD, PPC_INST_MTCTR,
    };

    println("# ---- ABSOLUTE JUMPTABLE ----");
    scanPattern(absoluteSwitch, std::size(absoluteSwitch), SWITCH_ABSOLUTE);
    scanPattern(absoluteSwitchShiftFirst, std::size(absoluteSwitchShiftFirst), SWITCH_ABSOLUTE);

    println("# ---- COMPUTED JUMPTABLE ----");
    scanPattern(computedSwitch, std::size(computedSwitch), SWITCH_COMPUTED);
    scanPattern(computedSwitchShiftFirst, std::size(computedSwitchShiftFirst), SWITCH_COMPUTED);

    println("# ---- OFFSETED JUMPTABLE ----");
    scanPattern(offsetSwitch, std::size(offsetSwitch), SWITCH_BYTEOFFSET);
    scanPattern(wordOffsetSwitch, std::size(wordOffsetSwitch), SWITCH_SHORTOFFSET);
    scanPattern(wordOffsetSwitchShiftFirst, std::size(wordOffsetSwitchShiftFirst), SWITCH_SHORTOFFSET);

    std::ofstream f(argv[2]);
    f.write(out.data(), out.size());

    return EXIT_SUCCESS;
}
