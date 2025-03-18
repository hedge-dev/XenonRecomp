#pragma once
#include <dis-asm.h>
#include <ppc.h>

namespace ppc
{
struct DisassemblerEngine
{
    disassemble_info info {};
    DisassemblerEngine(const DisassemblerEngine&) = default;
    DisassemblerEngine& operator=(const DisassemblerEngine&) = delete;

    DisassemblerEngine(bfd_endian endian, const char* options);
    ~DisassemblerEngine() = default;

    /**
     * \return Numbers of bytes decoded
     */
    int Disassemble(const void* code, size_t size, uint64_t base, ppc_insn& out);
};

thread_local extern DisassemblerEngine gBigEndianDisassembler;

static int Disassemble(const void* code, size_t size, uint64_t base, ppc_insn& out)
{
    return gBigEndianDisassembler.Disassemble(code, size, base, out);
}

static int Disassemble(const void* code, uint64_t base, ppc_insn& out)
{
    return Disassemble(code, 4, base, out);
}

static int Disassemble(const void* code, uint64_t base, ppc_insn* out, size_t nOut);
} // namespace ppc
