// Tests for Function::Analyze's switch-aware block walker.
//
// Hand-crafted synthetic PPC bytecode; self-contained; no dependency
// on any particular test corpus.
//
// Three scenarios:
//   (1) happy path:      switchMap populated, walker pushes switch labels
//   (2) null-map safety: switchMap == nullptr, walker uses legacy path
//   (3) wrong-map miss:  switchMap populated but no entry for this bctr;
//                        walker uses legacy path
//
// See tests/README.md for the build command and expected output.

#include "function.h"
#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

namespace {

// Little helper to emit a big-endian 32-bit insn word into a byte vector.
// Xenon is big-endian PPC; our synthetic blobs must match for the walker
// to decode them correctly.
void emitBE(std::vector<uint8_t>& out, uint32_t insn)
{
    out.push_back((insn >> 24) & 0xFF);
    out.push_back((insn >> 16) & 0xFF);
    out.push_back((insn >>  8) & 0xFF);
    out.push_back((insn >>  0) & 0xFF);
}

// Encode a handful of PPC instructions we need for the synthetic
// fixtures. These are standard encodings; values are cross-checked
// against capstone decoding as a sanity step.
constexpr uint32_t PPC_BLR  = 0x4E800020; // blr
constexpr uint32_t PPC_BCTR = 0x4E800420; // bctr
constexpr uint32_t PPC_NOP  = 0x60000000; // ori r0, r0, 0 == nop

// cmplwi cr6, rA, imm16 — primary opcode 10, field cr=6, rA, imm.
// Encoding: 001010 (6) | 110 (cr=6) | 0 | rA(5) | imm(16)
// = 0x2B | (rA<<16) | imm
uint32_t cmplwi_cr6(uint32_t rA, uint32_t imm)
{
    return 0x2B000000u | (rA << 16) | (imm & 0xFFFF);
}

// bgt cr6, BD — primary opcode 16, BO=12 (branch if true), BI=25 (cr6 gt).
// BD is a signed 14-bit displacement in bytes (we pass the displacement).
uint32_t bgt_cr6(int32_t displacement)
{
    // Encoding: 010000 | 01100 | 11001 | BD(14) | 00
    return 0x41990000u | (uint32_t(displacement) & 0xFFFC);
}

// Build a minimal "switch function" synthetic fixture:
//
//   0x00: cmplwi cr6, r3, 3     ; 4 cases
//   0x04: bgt cr6, +0x30        ; default @ 0x34
//   0x08: (would be LIS/ADDI/RLWINM/LWZX/MTCTR — stubbed as nops here
//          because our walker treats mtctr/bctr by opcode; the prior
//          instructions only matter to XenonAnalyse's SCAN side, not
//          to Function::Analyze's block walker)
//   0x08: nop
//   0x0C: nop
//   0x10: nop
//   0x14: nop
//   0x18: mtctr r0 (synthesized as nop — Function::Analyze doesn't
//         check mtctr specifically)
//   0x18: bctr                  ; <-- switch-dispatch site
//   0x1C: label[0] target @ 0x1C: blr
//   0x20: label[1] target @ 0x20: blr
//   0x24: label[2] target @ 0x24: blr
//   0x28: label[3] target @ 0x28: blr
//   0x2C: (padding)
//   0x34: default target: blr
//
// The walker starts at offset 0, walks to the bctr at 0x18, consults
// switchMap, and (if populated) pushes all 5 successor blocks (4 labels
// + default). The walker then reaches each block, processes its `blr`,
// and terminates. fn.size should cover through 0x34 (the default block's
// blr).
//
// Base address: we use 0x10000 as a synthetic "guest VA" for these
// tests. Anything > 0 works; 0x10000 is arbitrary.

struct SyntheticSwitch
{
    std::vector<uint8_t> bytes;
    uint32_t baseVa;
    uint32_t bctrVa;
    std::vector<uint32_t> labelVas;
    uint32_t defaultVa;
};

SyntheticSwitch buildFourCaseSwitch()
{
    SyntheticSwitch s;
    s.baseVa = 0x10000;
    s.bctrVa = s.baseVa + 0x18;
    s.defaultVa = s.baseVa + 0x34;
    s.labelVas = { s.baseVa + 0x1C, s.baseVa + 0x20, s.baseVa + 0x24, s.baseVa + 0x28 };

    // Pre-switch head
    emitBE(s.bytes, cmplwi_cr6(3, 3));  // cmplwi cr6, r3, 3
    emitBE(s.bytes, bgt_cr6(0x30));     // bgt cr6, +0x30 (→ 0x34 default)
    for (int i = 0; i < 4; ++i) emitBE(s.bytes, PPC_NOP);  // filler
    emitBE(s.bytes, PPC_BCTR);          // 0x18: the bctr

    // Label blocks — each a single blr
    for (int i = 0; i < 4; ++i) emitBE(s.bytes, PPC_BLR);

    // Padding between the 4 labels (at 0x2C) and default (at 0x34)
    emitBE(s.bytes, PPC_NOP);
    emitBE(s.bytes, PPC_NOP);

    // Default block
    emitBE(s.bytes, PPC_BLR);           // 0x34: default blr

    return s;
}

// Helper to populate a switchMap entry from a SyntheticSwitch.
AnalyzerSwitchTableMap buildMap(const SyntheticSwitch& s)
{
    AnalyzerSwitchTableMap m;
    AnalyzerSwitchTable entry;
    entry.defaultLabel = s.defaultVa;
    entry.labels = s.labelVas;
    m.emplace(s.bctrVa, std::move(entry));
    return m;
}

int testHappyPath()
{
    auto s = buildFourCaseSwitch();
    auto m = buildMap(s);
    Function fn = Function::Analyze(s.bytes.data(), s.bytes.size(), s.baseVa, &m);

    // Expected: walker reaches every label + default, all their blocks
    // get size = 4 (single-blr). fn.size should extend to cover the
    // default block (0x34 + 4 = 0x38).
    if (fn.base != s.baseVa) {
        fprintf(stderr, "[FAIL happy-path] fn.base = 0x%zX, expected 0x%X\n",
                fn.base, s.baseVa);
        return 1;
    }
    if (fn.size < 0x38) {
        fprintf(stderr, "[FAIL happy-path] fn.size = 0x%zX, expected >= 0x38 "
                "(switch labels + default)\n", fn.size);
        return 1;
    }
    fprintf(stderr, "[ok   happy-path] fn.base=0x%zX, fn.size=0x%zX, blocks=%zu\n",
            fn.base, fn.size, fn.blocks.size());
    return 0;
}

int testNullMapSafety()
{
    auto s = buildFourCaseSwitch();
    Function fn = Function::Analyze(s.bytes.data(), s.bytes.size(), s.baseVa,
                                    /* switchMap = */ nullptr);

    // Expected: walker terminates at bctr without pushing successors,
    // discontinuity pass erases any blocks past the bctr, fn.size covers
    // only the pre-switch head (up to and including the bctr at 0x18,
    // so fn.size >= 0x1C, ≤ 0x20 or so).
    if (fn.size >= 0x38) {
        fprintf(stderr, "[FAIL null-map ] fn.size = 0x%zX, expected < 0x38 "
                "(switchMap=nullptr should use legacy walker)\n", fn.size);
        return 1;
    }
    fprintf(stderr, "[ok   null-map ] fn.base=0x%zX, fn.size=0x%zX "
            "(legacy walker truncation preserved)\n", fn.base, fn.size);
    return 0;
}

int testWrongMapMiss()
{
    auto s = buildFourCaseSwitch();
    // Build a map, but with an entry for a DIFFERENT bctr address.
    AnalyzerSwitchTableMap m;
    AnalyzerSwitchTable bogus;
    bogus.defaultLabel = 0x99999;
    bogus.labels = { 0xABCDEF };
    m.emplace(/* bctr VA */ 0xDEADBEEF, std::move(bogus));  // not our bctr

    Function fn = Function::Analyze(s.bytes.data(), s.bytes.size(), s.baseVa, &m);

    // Expected: walker looks up our bctr (0x10018), finds nothing in the
    // map, falls through to legacy behavior. Same result as null-map.
    if (fn.size >= 0x38) {
        fprintf(stderr, "[FAIL wrong-map] fn.size = 0x%zX, expected < 0x38 "
                "(unrelated switchMap entry should fall through to legacy)\n", fn.size);
        return 1;
    }
    fprintf(stderr, "[ok   wrong-map] fn.base=0x%zX, fn.size=0x%zX "
            "(unrelated map entry correctly ignored)\n", fn.base, fn.size);
    return 0;
}

} // anonymous

int main()
{
    int failures = 0;
    failures += testHappyPath();
    failures += testNullMapSafety();
    failures += testWrongMapMiss();

    if (failures) {
        fprintf(stderr, "\n%d test(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nAll 3 tests PASSED\n");
    return 0;
}
