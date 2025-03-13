#include "fmt/xchar.h"
#include "function.h"
#include <algorithm>
#include <cassert>
#include <disasm.h>
#include <file.h>
#include <image.h>
#include <xbox.h>

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

static const uint8_t RESTGPRLR_14[] = { 0xe9, 0xc1, 0xff, 0x68 };
static const uint8_t SAVEGPRLR_14[] = { 0xf9, 0xc1, 0xff, 0x68 };
static const uint8_t RESTFPR_14[] = { 0xc9, 0xcc, 0xff, 0x70 };
static const uint8_t SAVEFPR_14[] = { 0xd9, 0xcc, 0xff, 0x70 };
static const uint8_t RESTVMX_14[] = { 0x39, 0x60, 0xfe, 0xe0, 0x7d, 0xcb, 0x60, 0xce };
static const uint8_t SAVEVMX_14[] = { 0x39, 0x60, 0xfe, 0xe0, 0x7d, 0xcb, 0x61, 0xce };
static const uint8_t RESTVMX_64[] = { 0x39, 0x60, 0xfc, 0x00, 0x10, 0x0b, 0x60, 0xcb };
static const uint8_t SAVEVMX_64[] = { 0x39, 0x60, 0xfc, 0x00, 0x10, 0x0b, 0x61, 0xcb };

uint32_t BytePatternSearch(uint8_t* data, const uint32_t dataSize, const uint32_t baseAddress, const uint8_t pattern[], const size_t patternSize)
{
    auto result = std::search(data, data + dataSize, pattern, pattern + patternSize);
    if (result != data + dataSize) {
        return baseAddress + std::distance(data, result);
    }

    return UINT32_MAX;
}

void RegisterFunctionsSearch(Image& image)
{
    uint32_t baseAddress = UINT32_MAX;

    for (const auto& section : image.sections) {
        if (section.name == ".text") {
            baseAddress = section.base;

            if (baseAddress == UINT32_MAX) {
                fmt::println("Could not find \".text\" section.");
                return;
            }

            uint32_t restgprlr_14 = BytePatternSearch(section.data, section.size, baseAddress, RESTGPRLR_14, sizeof(RESTGPRLR_14));
            uint32_t savegprlr_14 = BytePatternSearch(section.data, section.size, baseAddress, SAVEGPRLR_14, sizeof(SAVEGPRLR_14));
            uint32_t restfpr_14 = BytePatternSearch(section.data, section.size, baseAddress, RESTFPR_14, sizeof(RESTFPR_14));
            uint32_t savefpr_14 = BytePatternSearch(section.data, section.size, baseAddress, SAVEFPR_14, sizeof(SAVEFPR_14));
            uint32_t restvmx_14 = BytePatternSearch(section.data, section.size, baseAddress, RESTVMX_14, sizeof(RESTVMX_14));
            uint32_t savevmx_14 = BytePatternSearch(section.data, section.size, baseAddress, SAVEVMX_14, sizeof(SAVEVMX_14));
            uint32_t restvmx_64 = BytePatternSearch(section.data, section.size, baseAddress, RESTVMX_64, sizeof(RESTVMX_64));
            uint32_t savevmx_64 = BytePatternSearch(section.data, section.size, baseAddress, SAVEVMX_64, sizeof(SAVEVMX_64));

            fmt::println("restgprlr_14_address = 0x{:X}", restgprlr_14);
            fmt::println("savegprlr_14_address = 0x{:X}", savegprlr_14);
            fmt::println("restfpr_14_address = 0x{:X}", restfpr_14);
            fmt::println("savefpr_14_address = 0x{:X}", savefpr_14);
            fmt::println("restvmx_14_address = 0x{:X}", restvmx_14);
            fmt::println("savevmx_14_address = 0x{:X}", savevmx_14);
            fmt::println("restvmx_64_address = 0x{:X}", restvmx_64);
            fmt::println("savevmx_64_address = 0x{:X}", savevmx_64);
        }
    }
}

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

    RegisterFunctionsSearch(image);

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

    println("# ---- ABSOLUTE JUMPTABLE ----");
    scanPattern(absoluteSwitch, std::size(absoluteSwitch), SWITCH_ABSOLUTE);

    println("# ---- COMPUTED JUMPTABLE ----");
    scanPattern(computedSwitch, std::size(computedSwitch), SWITCH_COMPUTED);

    println("# ---- OFFSETED JUMPTABLE ----");
    scanPattern(offsetSwitch, std::size(offsetSwitch), SWITCH_BYTEOFFSET);
    scanPattern(wordOffsetSwitch, std::size(wordOffsetSwitch), SWITCH_SHORTOFFSET);

    std::ofstream f(argv[2]);
    f.write(out.data(), out.size());

    return EXIT_SUCCESS;
}
