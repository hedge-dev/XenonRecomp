#include "pch.h"
#include "recompiler.h"
#include <xex_patcher.h>

static uint64_t ComputeMask(uint32_t mstart, uint32_t mstop)
{
    mstart &= 0x3F;
    mstop &= 0x3F;
    uint64_t value = (UINT64_MAX >> mstart) ^ ((mstop >= 63) ? 0 : UINT64_MAX >> (mstop + 1));
    return mstart <= mstop ? value : ~value;
}

bool Recompiler::LoadConfig(const std::string_view& configFilePath)
{
    config.Load(configFilePath);

    std::vector<uint8_t> file;
    if (!config.patchedFilePath.empty())
        file = LoadFile((config.directoryPath + config.patchedFilePath).c_str());

    if (file.empty())
    {
        file = LoadFile((config.directoryPath + config.filePath).c_str());

        if (!config.patchFilePath.empty())
        {
            const auto patchFile = LoadFile((config.directoryPath + config.patchFilePath).c_str());
            if (!patchFile.empty())
            {
                std::vector<uint8_t> outBytes;
                auto result = XexPatcher::apply(file.data(), file.size(), patchFile.data(), patchFile.size(), outBytes, false);
                if (result == XexPatcher::Result::Success)
                {
                    std::exchange(file, outBytes);

                    if (!config.patchedFilePath.empty())
                    {
                        std::ofstream stream(config.directoryPath + config.patchedFilePath, std::ios::binary);
                        if (stream.good())
                        {
                            stream.write(reinterpret_cast<const char*>(file.data()), file.size());
                            stream.close();
                        }
                    }
                }
                else
                {
                    fmt::print("ERROR: Unable to apply the patch file, ");

                    switch (result)
                    {
                    case XexPatcher::Result::XexFileUnsupported:
                        fmt::println("XEX file unsupported");
                        break;

                    case XexPatcher::Result::XexFileInvalid:
                        fmt::println("XEX file invalid");
                        break;

                    case XexPatcher::Result::PatchFileInvalid:
                        fmt::println("patch file invalid");
                        break;

                    case XexPatcher::Result::PatchIncompatible:
                        fmt::println("patch file incompatible");
                        break;

                    case XexPatcher::Result::PatchFailed:
                        fmt::println("patch failed");
                        break;

                    case XexPatcher::Result::PatchUnsupported:
                        fmt::println("patch unsupported");
                        break;

                    default:
                        fmt::println("reason unknown");
                        break;
                    }

                    return false;
                }
            }
            else
            {
                fmt::println("ERROR: Unable to load the patch file");
                return false;
            }
        }
    }

    image = Image::ParseImage(file.data(), file.size());
    return true;
}

void Recompiler::Analyse()
{
    for (size_t i = 14; i < 128; i++)
    {
        if (i < 32)
        {
            if (config.restGpr14Address != 0)
            {
                auto& restgpr = functions.emplace_back();
                restgpr.base = config.restGpr14Address + (i - 14) * 4;
                restgpr.size = (32 - i) * 4 + 12;
                image.symbols.emplace(Symbol{ fmt::format("__restgprlr_{}", i), restgpr.base, restgpr.size, Symbol_Function });
            }

            if (config.saveGpr14Address != 0)
            {
                auto& savegpr = functions.emplace_back();
                savegpr.base = config.saveGpr14Address + (i - 14) * 4;
                savegpr.size = (32 - i) * 4 + 8;
                image.symbols.emplace(fmt::format("__savegprlr_{}", i), savegpr.base, savegpr.size, Symbol_Function);
            }

            if (config.restFpr14Address != 0)
            {
                auto& restfpr = functions.emplace_back();
                restfpr.base = config.restFpr14Address + (i - 14) * 4;
                restfpr.size = (32 - i) * 4 + 4;
                image.symbols.emplace(fmt::format("__restfpr_{}", i), restfpr.base, restfpr.size, Symbol_Function);
            }

            if (config.saveFpr14Address != 0)
            {
                auto& savefpr = functions.emplace_back();
                savefpr.base = config.saveFpr14Address + (i - 14) * 4;
                savefpr.size = (32 - i) * 4 + 4;
                image.symbols.emplace(fmt::format("__savefpr_{}", i), savefpr.base, savefpr.size, Symbol_Function);
            }

            if (config.restVmx14Address != 0)
            {
                auto& restvmx = functions.emplace_back();
                restvmx.base = config.restVmx14Address + (i - 14) * 8;
                restvmx.size = (32 - i) * 8 + 4;
                image.symbols.emplace(fmt::format("__restvmx_{}", i), restvmx.base, restvmx.size, Symbol_Function);
            }

            if (config.saveVmx14Address != 0)
            {
                auto& savevmx = functions.emplace_back();
                savevmx.base = config.saveVmx14Address + (i - 14) * 8;
                savevmx.size = (32 - i) * 8 + 4;
                image.symbols.emplace(fmt::format("__savevmx_{}", i), savevmx.base, savevmx.size, Symbol_Function);
            }
        }

        if (i >= 64)
        {
            if (config.restVmx64Address != 0)
            {
                auto& restvmx = functions.emplace_back();
                restvmx.base = config.restVmx64Address + (i - 64) * 8;
                restvmx.size = (128 - i) * 8 + 4;
                image.symbols.emplace(fmt::format("__restvmx_{}", i), restvmx.base, restvmx.size, Symbol_Function);
            }

            if (config.saveVmx64Address != 0)
            {
                auto& savevmx = functions.emplace_back();
                savevmx.base = config.saveVmx64Address + (i - 64) * 8;
                savevmx.size = (128 - i) * 8 + 4;
                image.symbols.emplace(fmt::format("__savevmx_{}", i), savevmx.base, savevmx.size, Symbol_Function);
            }
        }
    }

    for (auto& [address, size] : config.functions)
    {
        functions.emplace_back(address, size);
        image.symbols.emplace(fmt::format("sub_{:X}", address), address, size, Symbol_Function);
    }

    auto& pdata = *image.Find(".pdata");
    size_t count = pdata.size / sizeof(IMAGE_CE_RUNTIME_FUNCTION);
    auto* pf = (IMAGE_CE_RUNTIME_FUNCTION*)pdata.data;
    for (size_t i = 0; i < count; i++)
    {
        auto fn = pf[i];
        fn.BeginAddress = ByteSwap(fn.BeginAddress);
        fn.Data = ByteSwap(fn.Data);

        if (image.symbols.find(fn.BeginAddress) == image.symbols.end())
        {
            auto& f = functions.emplace_back();
            f.base = fn.BeginAddress;
            f.size = fn.FunctionLength * 4;

            image.symbols.emplace(fmt::format("sub_{:X}", f.base), f.base, f.size, Symbol_Function);
        }
    }

    for (const auto& section : image.sections)
    {
        if (!(section.flags & SectionFlags_Code))
        {
            continue;
        }
        size_t base = section.base;
        uint8_t* data = section.data;
        uint8_t* dataEnd = section.data + section.size;

        while (data < dataEnd)
        {
            uint32_t insn = ByteSwap(*(uint32_t*)data);
            if (PPC_OP(insn) == PPC_OP_B && PPC_BL(insn))
            {
                size_t address = base + (data - section.data) + PPC_BI(insn);

                if (address >= section.base && address < section.base + section.size && image.symbols.find(address) == image.symbols.end())
                {
                    auto data = section.data + address - section.base;
                    auto& fn = functions.emplace_back(Function::Analyze(data, section.base + section.size - address, address));
                    image.symbols.emplace(fmt::format("sub_{:X}", fn.base), fn.base, fn.size, Symbol_Function);
                }
            }
            data += 4;
        }

        data = section.data;

        while (data < dataEnd)
        {
            auto invalidInstr = config.invalidInstructions.find(ByteSwap(*(uint32_t*)data));
            if (invalidInstr != config.invalidInstructions.end())
            {
                base += invalidInstr->second;
                data += invalidInstr->second;
                continue;
            }

            auto fnSymbol = image.symbols.find(base);
            if (fnSymbol != image.symbols.end() && fnSymbol->address == base && fnSymbol->type == Symbol_Function)
            {
                assert(fnSymbol->address == base);

                base += fnSymbol->size;
                data += fnSymbol->size;
            }
            else
            {
                auto& fn = functions.emplace_back(Function::Analyze(data, dataEnd - data, base));
                image.symbols.emplace(fmt::format("sub_{:X}", fn.base), fn.base, fn.size, Symbol_Function);

                base += fn.size;
                data += fn.size;
            }
        }
    }

    std::sort(functions.begin(), functions.end(), [](auto& lhs, auto& rhs) { return lhs.base < rhs.base; });
}

bool Recompiler::Recompile(
    const Function& fn,
    uint32_t base,
    const ppc_insn& insn,
    const uint32_t* data,
    std::unordered_map<uint32_t, RecompilerSwitchTable>::iterator& switchTable,
    RecompilerLocalVariables& localVariables,
    CSRState& csrState)
{
    println("\t// {} {}", insn.opcode->name, insn.op_str);

    // TODO: we could cache these formats in an array
    auto r = [&](size_t index)
        {
            if ((config.nonArgumentRegistersAsLocalVariables && (index == 0 || index == 2 || index == 11 || index == 12)) || 
                (config.nonVolatileRegistersAsLocalVariables && index >= 14))
            {
                localVariables.r[index] = true;
                return fmt::format("r{}", index);
            }
            return fmt::format("ctx.r{}", index);
        };

    auto f = [&](size_t index)
        {
            if ((config.nonArgumentRegistersAsLocalVariables && index == 0) ||
                (config.nonVolatileRegistersAsLocalVariables && index >= 14))
            {
                localVariables.f[index] = true;
                return fmt::format("f{}", index);
            }
            return fmt::format("ctx.f{}", index);
        };

    auto v = [&](size_t index)
        {
            if ((config.nonArgumentRegistersAsLocalVariables && (index >= 32 && index <= 63)) ||
                (config.nonVolatileRegistersAsLocalVariables && ((index >= 14 && index <= 31) || (index >= 64 && index <= 127))))
            {
                localVariables.v[index] = true;
                return fmt::format("v{}", index);
            }
            return fmt::format("ctx.v{}", index);
        };

    auto cr = [&](size_t index)
        {
            if (config.crRegistersAsLocalVariables)
            {
                localVariables.cr[index] = true;
                return fmt::format("cr{}", index);
            }
            return fmt::format("ctx.cr{}", index);
        };

    auto ctr = [&]()
        {
            if (config.ctrAsLocalVariable)
            {
                localVariables.ctr = true;
                return "ctr";
            }
            return "ctx.ctr";
        };

    auto xer = [&]()
        {
            if (config.xerAsLocalVariable)
            {
                localVariables.xer = true;
                return "xer";
            }
            return "ctx.xer";
        };

    auto reserved = [&]()
        {
            if (config.reservedRegisterAsLocalVariable)
            {
                localVariables.reserved = true;
                return "reserved";
            }
            return "ctx.reserved";
        };

    auto temp = [&]()
        {
            localVariables.temp = true;
            return "temp";
        };

    auto vTemp = [&]()
        {
            localVariables.vTemp = true;
            return "vTemp";
        };

    auto env = [&]()
        {
            localVariables.env = true;
            return "env";
        };

    auto ea = [&]()
        {
            localVariables.ea = true;
            return "ea";
        };

    // TODO (Sajid): Check for out of bounds access
    auto mmioStore = [&]() -> bool
        {
            return *(data + 1) == c_eieio;
        };

    auto printFunctionCall = [&](uint32_t address)
        {
            if (address == config.longJmpAddress)
            {
                println("\tlongjmp(*reinterpret_cast<jmp_buf*>(base + {}.u32), {}.s32);", r(3), r(4));
            }
            else if (address == config.setJmpAddress)
            {
                println("\t{} = ctx;", env());
                println("\t{}.s64 = setjmp(*reinterpret_cast<jmp_buf*>(base + {}.u32));", temp(), r(3));
                println("\tif ({}.s64 != 0) ctx = {};", temp(), env());
                println("\t{} = {};", r(3), temp());
            }
            else
            {
                auto targetSymbol = image.symbols.find(address);

                if (targetSymbol != image.symbols.end() && targetSymbol->address == address && targetSymbol->type == Symbol_Function)
                {
                    if (config.nonVolatileRegistersAsLocalVariables && (targetSymbol->name.find("__rest") == 0 || targetSymbol->name.find("__save") == 0))
                    {
                        // print nothing
                    }
                    else
                    {
                        println("\t{}(ctx, base);", targetSymbol->name);
                    }
                }
                else
                {
                    println("\t// ERROR {:X}", address);
                }
            }
        };

    auto printConditionalBranch = [&](bool not_, const std::string_view& cond)
        {
            if (insn.operands[1] < fn.base || insn.operands[1] >= fn.base + fn.size)
            {
                println("\tif ({}{}.{}) {{", not_ ? "!" : "", cr(insn.operands[0]), cond);
                print("\t");
                printFunctionCall(insn.operands[1]);
                println("\t\treturn;");
                println("\t}}");
            }
            else
            {
                println("\tif ({}{}.{}) goto loc_{:X};", not_ ? "!" : "", cr(insn.operands[0]), cond, insn.operands[1]);
            }
        };

    auto printSetFlushMode = [&](bool enable)
        {
            auto newState = enable ? CSRState::VMX : CSRState::FPU;
            if (csrState != newState)
            {
                auto prefix = enable ? "enable" : "disable";
                auto suffix = csrState != CSRState::Unknown ? "Unconditional" : "";
                println("\tctx.fpscr.{}FlushMode{}();", prefix, suffix);

                csrState = newState;
            }
        };

    auto midAsmHook = config.midAsmHooks.find(base);

    auto printMidAsmHook = [&]()
        {
            bool returnsBool = midAsmHook->second.returnOnFalse || midAsmHook->second.returnOnTrue ||
                midAsmHook->second.jumpAddressOnFalse != NULL || midAsmHook->second.jumpAddressOnTrue != NULL;

            print("\t");
            if (returnsBool)
                print("if (");

            print("{}(", midAsmHook->second.name);
            for (auto& reg : midAsmHook->second.registers)
            {
                if (out.back() != '(')
                    out += ", ";

                switch (reg[0])
                {
                case 'c':
                    if (reg == "ctr")
                        out += ctr();
                    else
                        out += cr(std::atoi(reg.c_str() + 2));
                    break;

                case 'x':
                    out += xer();
                    break;

                case 'r':
                    if (reg == "reserved")
                        out += reserved();
                    else
                        out += r(std::atoi(reg.c_str() + 1));
                    break;

                case 'f':
                    if (reg == "fpscr")
                        out += "ctx.fpscr";
                    else
                        out += f(std::atoi(reg.c_str() + 1));
                    break;

                case 'v':
                    out += v(std::atoi(reg.c_str() + 1));
                    break;
                }
            }

            if (returnsBool)
            {
                println(")) {{");

                if (midAsmHook->second.returnOnTrue)
                    println("\t\treturn;");
                else if (midAsmHook->second.jumpAddressOnTrue != NULL)
                    println("\t\tgoto loc_{:X};", midAsmHook->second.jumpAddressOnTrue);

                println("\t}}");

                println("\telse {{");

                if (midAsmHook->second.returnOnFalse)
                    println("\t\treturn;");
                else if (midAsmHook->second.jumpAddressOnFalse != NULL)
                    println("\t\tgoto loc_{:X};", midAsmHook->second.jumpAddressOnFalse);

                println("\t}}");
            }
            else
            {
                println(");");

                if (midAsmHook->second.ret)
                    println("\treturn;");
                else if (midAsmHook->second.jumpAddress != NULL)
                    println("\tgoto loc_{:X};", midAsmHook->second.jumpAddress);
            }
        };

    if (midAsmHook != config.midAsmHooks.end() && !midAsmHook->second.afterInstruction)
        printMidAsmHook();

    int id = insn.opcode->id;

    // Handling instructions that don't disassemble correctly for some reason here
    if (id == PPC_INST_VUPKHSB128 && insn.operands[2] == 0x60) id = PPC_INST_VUPKHSH128;
    else if (id == PPC_INST_VUPKLSB128 && insn.operands[2] == 0x60) id = PPC_INST_VUPKLSH128;

    switch (id)
    {
    case PPC_INST_ADD:
        println("\t{}.u64 = {}.u64 + {}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ADDC:
        println("\t{}.ca = ({}.u32 + {}.u32 < {}.u32);", xer(), r(insn.operands[1]), r(insn.operands[2]), r(insn.operands[1]));
        println("\t{}.u64 = {}.u64 + {}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ADDE:
        println("\t{}.u8 = ({}.u32 + {}.u32 < {}.u32) | ({}.u32 + {}.u32 + {}.ca < {}.ca);", temp(), r(insn.operands[1]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[1]), r(insn.operands[2]), xer(), xer());
        println("\t{}.u64 = {}.u64 + {}.u64 + {}.ca;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]), xer());
        println("\t{}.ca = {}.u8;", xer(), temp());
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ADDI:
        print("\t{}.s64 = ", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.s64 + ", r(insn.operands[1]));
        println("{};", int32_t(insn.operands[2]));
        break;

    case PPC_INST_ADDIC:
        println("\t{}.ca = {}.u32 > {};", xer(), r(insn.operands[1]), ~insn.operands[2]);
        println("\t{}.s64 = {}.s64 + {};", r(insn.operands[0]), r(insn.operands[1]), int32_t(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ADDIS:
        print("\t{}.s64 = ", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.s64 + ", r(insn.operands[1]));
        println("{};", static_cast<int32_t>(insn.operands[2] << 16));
        break;

    case PPC_INST_ADDME:
        println("\t{}.u64 = {}.u64 + {}.ca - 1;", temp(), r(insn.operands[1]), xer());
        println("\t{}.ca = ({}.u64 > {}.u64) || ({}.u64 == {}.u64 && {}.ca);", xer(), 
            r(insn.operands[1]), temp(), r(insn.operands[1]), temp(), xer());
        println("\t{}.u64 = {}.u64;", r(insn.operands[0]), temp());
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", 
                cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ADDZE:
        println("\t{}.s64 = {}.s64 + {}.ca;", temp(), r(insn.operands[1]), xer());
        println("\t{}.ca = {}.u32 < {}.u32;", xer(), temp(), r(insn.operands[1]));
        println("\t{}.s64 = {}.s64;", r(insn.operands[0]), temp());
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_AND:
        println("\t{}.u64 = {}.u64 & {}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ANDC:
        println("\t{}.u64 = {}.u64 & ~{}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ANDI:
        println("\t{}.u64 = {}.u64 & {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2]);
        println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ANDIS:
        println("\t{}.u64 = {}.u64 & {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2] << 16);
        println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ATTN:
        // undefined instruction
        break;

    case PPC_INST_B:
        if (insn.operands[0] < fn.base || insn.operands[0] >= fn.base + fn.size)
        {
            printFunctionCall(insn.operands[0]);
            println("\treturn;");
        }
        else
        {
            println("\tgoto loc_{:X};", insn.operands[0]);
        }
        break;

    case PPC_INST_BCTR:
        if (switchTable != config.switchTables.end())
        {
            println("\tswitch ({}.u64) {{", r(switchTable->second.r));

            for (size_t i = 0; i < switchTable->second.labels.size(); i++)
            {
                println("\tcase {}:", i);
                auto label = switchTable->second.labels[i];
                if (label < fn.base || label >= fn.base + fn.size)
                {
                    println("\t\t// ERROR: 0x{:X}", label);
                    fmt::println("ERROR: Switch case at {:X} is trying to jump outside function: {:X}", base, label);
                    println("\t\treturn;");
                }
                else
                {
                    println("\t\tgoto loc_{:X};", label);
                }
            }

            println("\tdefault:");
            println("\t\t__builtin_unreachable();");
            println("\t}}");

            switchTable = config.switchTables.end();
        }
        else
        {
            println("\tPPC_CALL_INDIRECT_FUNC({}.u32);", ctr());
            println("\treturn;");
        }
        break;

    case PPC_INST_BCTRL:
        if (!config.skipLr)
            println("\tctx.lr = 0x{:X};", base + 4);
        println("\tPPC_CALL_INDIRECT_FUNC({}.u32);", ctr());
        csrState = CSRState::Unknown; // the call could change it
        break;

    case PPC_INST_BDZ:
        println("\t--{}.u64;", ctr());
        println("\tif ({}.u32 == 0) goto loc_{:X};", ctr(), insn.operands[0]);
        break;

    case PPC_INST_BDZLR:
        println("\t--{}.u64;", ctr());
        println("\tif ({}.u32 == 0) return;", ctr(), insn.operands[0]);
        break;

    case PPC_INST_BDNZ:
        println("\t--{}.u64;", ctr());
        println("\tif ({}.u32 != 0) goto loc_{:X};", ctr(), insn.operands[0]);
        break;

    case PPC_INST_BDNZF:
        // NOTE: assuming eq here as a shortcut because all the instructions in the game do that
        println("\t--{}.u64;", ctr());
        println("\tif ({}.u32 != 0 && !{}.eq) goto loc_{:X};", ctr(), cr(insn.operands[0] / 4), insn.operands[1]);
        break;

    case PPC_INST_BEQ:
        printConditionalBranch(false, "eq");
        break;

    case PPC_INST_BEQLR:
        println("\tif ({}.eq) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_BGE:
        printConditionalBranch(true, "lt");
        break;

    case PPC_INST_BGELR:
        println("\tif (!{}.lt) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_BGT:
        printConditionalBranch(false, "gt");
        break;

    case PPC_INST_BGTLR:
        println("\tif ({}.gt) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_BL:
        if (!config.skipLr)
            println("\tctx.lr = 0x{:X};", base + 4);
        printFunctionCall(insn.operands[0]);
        csrState = CSRState::Unknown; // the call could change it
        break;

    case PPC_INST_BLE:
        printConditionalBranch(true, "gt");
        break;

    case PPC_INST_BLELR:
        println("\tif (!{}.gt) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_BLR:
        println("\treturn;");
        break;

    case PPC_INST_BLRL:
        println("__builtin_debugtrap();");
        break;

    case PPC_INST_BLT:
        printConditionalBranch(false, "lt");
        break;

    case PPC_INST_BLTLR:
        println("\tif ({}.lt) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_BNE:
        printConditionalBranch(true, "eq");
        break;

    case PPC_INST_BNECTR:
        println("\tif (!{}.eq) {{", cr(insn.operands[0]));
        println("\t\tPPC_CALL_INDIRECT_FUNC({}.u32);", ctr());
        println("\t\treturn;");
        println("\t}}");
        break;

    case PPC_INST_BNELR:
        println("\tif (!{}.eq) return;", cr(insn.operands[0]));
        break;

    case PPC_INST_CCTPL:
        // no op
        break;

    case PPC_INST_CCTPM:
        // no op
        break;

    case PPC_INST_CLRLDI:
        println("\t{}.u64 = {}.u64 & 0x{:X};", r(insn.operands[0]), r(insn.operands[1]), (1ull << (64 - insn.operands[2])) - 1);
        break;

    case PPC_INST_CLRLWI:
        println("\t{}.u64 = {}.u32 & 0x{:X};", r(insn.operands[0]), r(insn.operands[1]), (1ull << (32 - insn.operands[2])) - 1);
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_CMPD:
        println("\t{}.compare<int64_t>({}.s64, {}.s64, {});", cr(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]), xer());
        break;

    case PPC_INST_CMPDI:
        println("\t{}.compare<int64_t>({}.s64, {}, {});", cr(insn.operands[0]), r(insn.operands[1]), int32_t(insn.operands[2]), xer());
        break;

    case PPC_INST_CMPLD:
        println("\t{}.compare<uint64_t>({}.u64, {}.u64, {});", cr(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]), xer());
        break;

    case PPC_INST_CMPLDI:
        println("\t{}.compare<uint64_t>({}.u64, {}, {});", cr(insn.operands[0]), r(insn.operands[1]), insn.operands[2], xer());
        break;

    case PPC_INST_CMPLW:
        println("\t{}.compare<uint32_t>({}.u32, {}.u32, {});", cr(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]), xer());
        break;

    case PPC_INST_CMPLWI:
        println("\t{}.compare<uint32_t>({}.u32, {}, {});", cr(insn.operands[0]), r(insn.operands[1]), insn.operands[2], xer());
        break;

    case PPC_INST_CMPW:
        println("\t{}.compare<int32_t>({}.s32, {}.s32, {});", cr(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]), xer());
        break;

    case PPC_INST_CMPWI:
        println("\t{}.compare<int32_t>({}.s32, {}, {});", cr(insn.operands[0]), r(insn.operands[1]), int32_t(insn.operands[2]), xer());
        break;

    case PPC_INST_CNTLZD:
        println("\t{0}.u64 = {1}.u64 == 0 ? 64 : __builtin_clzll({1}.u64);", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_CNTLZW:
        println("\t{0}.u64 = {1}.u32 == 0 ? 32 : __builtin_clz({1}.u32);", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_DB16CYC:
        // no op
        break;

    case PPC_INST_DCBF:
        // no op
        break;

    case PPC_INST_DCBT:
        // no op
        break;

    case PPC_INST_DCBST:
    case PPC_INST_DCBTST:
        // no op
        break;

    case PPC_INST_DCBZ:
        print("\tmemset(base + ((");
        if (insn.operands[0] != 0)
            print("{}.u32 + ", r(insn.operands[0]));
        println("{}.u32) & ~31), 0, 32);", r(insn.operands[1]));
        break;

    case PPC_INST_DCBZL:
        print("\tmemset(base + ((");
        if (insn.operands[0] != 0)
            print("{}.u32 + ", r(insn.operands[0]));
        println("{}.u32) & ~127), 0, 128);", r(insn.operands[1]));
        break;

    case PPC_INST_DIVD:
        println("\t{}.s64 = {}.s64 / {}.s64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_DIVDU:
        println("\t{}.u64 = {}.u64 / {}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_DIVW:
        println("\t{}.s32 = {}.s32 / {}.s32;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_DIVWU:
        println("\t{}.u32 = {}.u32 / {}.u32;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_EIEIO:
        // no op
        break;

    case PPC_INST_EQV:
        // rA = ~(rS XOR rB)
        println("\t{}.u64 = ~({}.u64 ^ {}.u64);", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_EXTSB:
        println("\t{}.s64 = {}.s8;", r(insn.operands[0]), r(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_EXTSH:
        println("\t{}.s64 = {}.s16;", r(insn.operands[0]), r(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_EXTSW:
        println("\t{}.s64 = {}.s32;", r(insn.operands[0]), r(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_FABS:
        printSetFlushMode(false);
        println("\t{}.u64 = {}.u64 & ~0x8000000000000000;", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FADD:
        printSetFlushMode(false);
        println("\t{}.f64 = {}.f64 + {}.f64;", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_FADDS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float({}.f64 + {}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_FCFID:
        printSetFlushMode(false);
        println("\t{}.f64 = double({}.s64);", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FCMPU:
        printSetFlushMode(false);
        println("\t{}.compare({}.f64, {}.f64);", cr(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_FCTID:
        printSetFlushMode(false);
        println("\t{}.s64 = ({}.f64 > double(LLONG_MAX)) ? LLONG_MAX : _mm_cvtsd_si64(_mm_load_sd(&{}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[1]));
        break;

    case PPC_INST_FCTIDZ:
        printSetFlushMode(false);
        println("\t{}.s64 = ({}.f64 > double(LLONG_MAX)) ? LLONG_MAX : _mm_cvttsd_si64(_mm_load_sd(&{}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[1]));
        break;

    case PPC_INST_FCTIWZ:
        printSetFlushMode(false);
        println("\t{}.s64 = ({}.f64 > double(INT_MAX)) ? INT_MAX : _mm_cvttsd_si32(_mm_load_sd(&{}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[1]));
        break;

    case PPC_INST_FDIV:
        printSetFlushMode(false);
        println("\t{}.f64 = {}.f64 / {}.f64;", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_FDIVS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float({}.f64 / {}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_FMADD:
        printSetFlushMode(false);
        println("\t{}.f64 = {}.f64 * {}.f64 + {}.f64;", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_FMADDS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float({}.f64 * {}.f64 + {}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_FMR:
        printSetFlushMode(false);
        println("\t{}.f64 = {}.f64;", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FMSUB:
        printSetFlushMode(false);
        println("\t{}.f64 = {}.f64 * {}.f64 - {}.f64;", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_FMSUBS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float({}.f64 * {}.f64 - {}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_FMUL:
        printSetFlushMode(false);
        println("\t{}.f64 = {}.f64 * {}.f64;", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_FMULS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float({}.f64 * {}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_FNABS:
        printSetFlushMode(false);
        println("\t{}.u64 = {}.u64 | 0x8000000000000000;", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FNEG:
        printSetFlushMode(false);
        println("\t{}.u64 = {}.u64 ^ 0x8000000000000000;", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FNMADDS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float(-({}.f64 * {}.f64 + {}.f64)));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_FNMSUB:
        printSetFlushMode(false);
        println("\t{}.f64 = -({}.f64 * {}.f64 - {}.f64);", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_FNMSUBS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float(-({}.f64 * {}.f64 - {}.f64)));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_FRES:
        printSetFlushMode(false);
        println("\t{}.f64 = float(1.0 / {}.f64);", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FRSP:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float({}.f64));", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FSEL:
        printSetFlushMode(false);
        println("\t{}.f64 = {}.f64 >= 0.0 ? {}.f64 : {}.f64;", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]), f(insn.operands[3]));
        break;

    case PPC_INST_FRSQRTE:
        // TODO(crack): I sure hope the c++ optimizer can optimize this. Fixme with some simd magic later
        printSetFlushMode(false);
        println("\t{}.f64 = double(1.0f / sqrtf(float({}.f64)));", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FSQRT:
        printSetFlushMode(false);
        println("\t{}.f64 = sqrt({}.f64);", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FSQRTS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float(sqrt({}.f64)));", f(insn.operands[0]), f(insn.operands[1]));
        break;

    case PPC_INST_FSUB:
        printSetFlushMode(false);
        println("\t{}.f64 = {}.f64 - {}.f64;", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_FSUBS:
        printSetFlushMode(false);
        println("\t{}.f64 = double(float({}.f64 - {}.f64));", f(insn.operands[0]), f(insn.operands[1]), f(insn.operands[2]));
        break;

    case PPC_INST_LBZ:
        print("\t{}.u64 = PPC_LOAD_U8(", r(insn.operands[0]));
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{});", int32_t(insn.operands[1]));
        break;

    case PPC_INST_LBZU:
        println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        println("\t{}.u64 = PPC_LOAD_U8({});", r(insn.operands[0]), ea());
        println("\t{}.u32 = {};", r(insn.operands[2]), ea());
        break;

    case PPC_INST_LBZX:
        print("\t{}.u64 = PPC_LOAD_U8(", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32);", r(insn.operands[2]));
        break;

    case PPC_INST_LD:
        print("\t{}.u64 = PPC_LOAD_U64(", r(insn.operands[0]));
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{});", int32_t(insn.operands[1]));
        break;

    case PPC_INST_LDARX:
        print("\t{}.u64 = *(uint64_t*)(base + ", reserved());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32);", r(insn.operands[2]));
        println("\t{}.u64 = __builtin_bswap64({}.u64);", r(insn.operands[0]), reserved());
        break;

    case PPC_INST_LDU:
        println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        println("\t{}.u64 = PPC_LOAD_U64({});", r(insn.operands[0]), ea());
        println("\t{}.u32 = {};", r(insn.operands[2]), ea());
        break;

    case PPC_INST_LDX:
        print("\t{}.u64 = PPC_LOAD_U64(", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32);", r(insn.operands[2]));
        break;

    case PPC_INST_LFD:
        printSetFlushMode(false);
        print("\t{}.u64 = PPC_LOAD_U64(", f(insn.operands[0]));
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{});", int32_t(insn.operands[1]));
        break;

    case PPC_INST_LFDX:
        printSetFlushMode(false);
        print("\t{}.u64 = PPC_LOAD_U64(", f(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32);", r(insn.operands[2]));
        break;

    case PPC_INST_LFS:
        printSetFlushMode(false);
        print("\t{}.u32 = PPC_LOAD_U32(", temp());
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{});", int32_t(insn.operands[1]));
        println("\t{}.f64 = double({}.f32);", f(insn.operands[0]), temp());
        break;

    case PPC_INST_LFSX:
        printSetFlushMode(false);
        print("\t{}.u32 = PPC_LOAD_U32(", temp());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32);", r(insn.operands[2]));
        println("\t{}.f64 = double({}.f32);", f(insn.operands[0]), temp());
        break;

    case PPC_INST_LHA:
        print("\t{}.s64 = int16_t(PPC_LOAD_U16(", r(insn.operands[0]));
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{}));", int32_t(insn.operands[1]));
        break;

    case PPC_INST_LHAX:
        print("\t{}.s64 = int16_t(PPC_LOAD_U16(", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32));", r(insn.operands[2]));
        break;

    case PPC_INST_LHZ:
        print("\t{}.u64 = PPC_LOAD_U16(", r(insn.operands[0]));
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{});", int32_t(insn.operands[1]));
        break;

    case PPC_INST_LHZX:
        print("\t{}.u64 = PPC_LOAD_U16(", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32);", r(insn.operands[2]));
        break;

    case PPC_INST_LI:
        println("\t{}.s64 = {};", r(insn.operands[0]), int32_t(insn.operands[1]));
        break;

    case PPC_INST_LIS:
        println("\t{}.s64 = {};", r(insn.operands[0]), int32_t(insn.operands[1] << 16));
        break;

    case PPC_INST_LVEBX:
    case PPC_INST_LVEHX:
    case PPC_INST_LVEWX:
    case PPC_INST_LVEWX128:
    case PPC_INST_LVX:
    case PPC_INST_LVX128:
        // NOTE: for endian swapping, we reverse the whole vector instead of individual elements.
        // this is accounted for in every instruction (eg. dp3 sums yzw instead of xyz)
        print("\t_mm_store_si128((__m128i*){}.u8, _mm_shuffle_epi8(_mm_load_si128((__m128i*)(base + ((", v(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32) & ~0xF))), _mm_load_si128((__m128i*)VectorMaskL)));", r(insn.operands[2]));
        break;

    case PPC_INST_LVLX:
    case PPC_INST_LVLX128:
        print("\t{}.u32 = ", temp());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32;", r(insn.operands[2]));
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_shuffle_epi8(_mm_load_si128((__m128i*)(base + ({}.u32 & ~0xF))), _mm_load_si128((__m128i*)&VectorMaskL[({}.u32 & 0xF) * 16])));", v(insn.operands[0]), temp(), temp());
        break;

    case PPC_INST_LVRX:
    case PPC_INST_LVRX128:
        print("\t{}.u32 = ", temp());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32;", r(insn.operands[2]));
        println("\t_mm_store_si128((__m128i*){}.u8, {}.u32 & 0xF ? _mm_shuffle_epi8(_mm_load_si128((__m128i*)(base + ({}.u32 & ~0xF))), _mm_load_si128((__m128i*)&VectorMaskR[({}.u32 & 0xF) * 16])) : _mm_setzero_si128());", v(insn.operands[0]), temp(), temp(), temp());
        break;

    case PPC_INST_LVSL:
        print("\t{}.u32 = ", temp());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32;", r(insn.operands[2]));
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_load_si128((__m128i*)&VectorShiftTableL[({}.u32 & 0xF) * 16]));", v(insn.operands[0]), temp());
        break;

    case PPC_INST_LVSR:
        print("\t{}.u32 = ", temp());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32;", r(insn.operands[2]));
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_load_si128((__m128i*)&VectorShiftTableR[({}.u32 & 0xF) * 16]));", v(insn.operands[0]), temp());
        break;

    case PPC_INST_LWA:
        print("\t{}.s64 = int32_t(PPC_LOAD_U32(", r(insn.operands[0]));
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{}));", int32_t(insn.operands[1]));
        break;

    case PPC_INST_LWARX:
        print("\t{}.u32 = *(uint32_t*)(base + ", reserved());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32);", r(insn.operands[2]));
        println("\t{}.u64 = __builtin_bswap32({}.u32);", r(insn.operands[0]), reserved());
        break;

    case PPC_INST_LWAX:
        print("\t{}.s64 = int32_t(PPC_LOAD_U32(", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32));", r(insn.operands[2]));
        break;

    case PPC_INST_LWBRX:
        print("\t{}.u64 = __builtin_bswap32(PPC_LOAD_U32(", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32));", r(insn.operands[2]));
        break;

    case PPC_INST_LWSYNC:
        // no op
        break;

    case PPC_INST_LWZ:
        print("\t{}.u64 = PPC_LOAD_U32(", r(insn.operands[0]));
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{});", int32_t(insn.operands[1]));
        break;

    case PPC_INST_LWZU:
        println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        println("\t{}.u64 = PPC_LOAD_U32({});", r(insn.operands[0]), ea());
        println("\t{}.u32 = {};", r(insn.operands[2]), ea());
        break;

    case PPC_INST_LWZX:
        print("\t{}.u64 = PPC_LOAD_U32(", r(insn.operands[0]));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32);", r(insn.operands[2]));
        break;

    case PPC_INST_MFCR:
        for (size_t i = 0; i < 32; i++)
        {
            constexpr std::string_view fields[] = { "lt", "gt", "eq", "so" };
            println("\t{}.u64 {}= {}.{} ? 0x{:X} : 0;", r(insn.operands[0]), i == 0 ? "" : "|", cr(i / 4), fields[i % 4], 1u << (31 - i));
        }
        break;

    case PPC_INST_MFFS:
        println("\t{}.u64 = ctx.fpscr.loadFromHost();", r(insn.operands[0]));
        break;

    case PPC_INST_MFLR:
        if (!config.skipLr)
            println("\t{}.u64 = ctx.lr;", r(insn.operands[0]));
        break;

    case PPC_INST_MFMSR:
        if (!config.skipMsr)
            println("\t{}.u64 = ctx.msr;", r(insn.operands[0]));
        break;

    case PPC_INST_MFOCRF:
        // TODO: don't hardcode to cr6
        println("\t{}.u64 = ({}.lt << 7) | ({}.gt << 6) | ({}.eq << 5) | ({}.so << 4);", r(insn.operands[0]), cr(6), cr(6), cr(6), cr(6));
        break;

    case PPC_INST_MFTB:
        println("\t{}.u64 = __rdtsc();", r(insn.operands[0]));
        break;

    case PPC_INST_MR:
        println("\t{}.u64 = {}.u64;", r(insn.operands[0]), r(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_MTCR:
        for (size_t i = 0; i < 32; i++)
        {
            constexpr std::string_view fields[] = { "lt", "gt", "eq", "so" };
            println("\t{}.{} = ({}.u32 & 0x{:X}) != 0;", cr(i / 4), fields[i % 4], r(insn.operands[0]), 1u << (31 - i));
        }
        break;

    case PPC_INST_MTCTR:
        println("\t{}.u64 = {}.u64;", ctr(), r(insn.operands[0]));
        break;

    case PPC_INST_MTFSF:
        println("\tctx.fpscr.storeFromGuest({}.u32);", f(insn.operands[1]));
        break;

    case PPC_INST_MTLR:
        if (!config.skipLr)
            println("\tctx.lr = {}.u64;", r(insn.operands[0]));
        break;

    case PPC_INST_MTMSRD:
        if (!config.skipMsr)
            println("\tctx.msr = ({}.u32 & 0x8020) | (ctx.msr & ~0x8020);", r(insn.operands[0]));
        break;

    case PPC_INST_MTXER:
        println("\t{}.so = ({}.u64 & 0x80000000) != 0;", xer(), r(insn.operands[0]));
        println("\t{}.ov = ({}.u64 & 0x40000000) != 0;", xer(), r(insn.operands[0]));
        println("\t{}.ca = ({}.u64 & 0x20000000) != 0;", xer(), r(insn.operands[0]));
        break;

    case PPC_INST_MULHW:
        println("\t{}.s64 = (int64_t({}.s32) * int64_t({}.s32)) >> 32;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_MULHWU:
        println("\t{}.u64 = (uint64_t({}.u32) * uint64_t({}.u32)) >> 32;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_MULLD:
        println("\t{}.s64 = {}.s64 * {}.s64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_MULLI:
        println("\t{}.s64 = {}.s64 * {};", r(insn.operands[0]), r(insn.operands[1]), int32_t(insn.operands[2]));
        break;

    case PPC_INST_MULLW:
        println("\t{}.s64 = int64_t({}.s32) * int64_t({}.s32);", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_MULHD:
        println("\t{}.s64 = __mulh({}.s64, {}.s64);",
            r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", 
                cr(0), r(insn.operands[0]), xer());
        break;
    
    case PPC_INST_MULHDU:
        println("\t{}.u64 = __mulhu({}.u64, {}.u64);", 
            r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", 
                cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_NAND:
        println("\t{}.u64 = ~({}.u64 & {}.u64);", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_NEG:
        println("\t{}.s64 = -{}.s64;", r(insn.operands[0]), r(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_NOP:
        // no op
        break;

    case PPC_INST_NOR:
        println("\t{}.u64 = ~({}.u64 | {}.u64);", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_NOT:
        println("\t{}.u64 = ~{}.u64;", r(insn.operands[0]), r(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_OR:
        println("\t{}.u64 = {}.u64 | {}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ORC:
        println("\t{}.u64 = {}.u64 | ~{}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_ORI:
        println("\t{}.u64 = {}.u64 | {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2]);
        break;

    case PPC_INST_ORIS:
        println("\t{}.u64 = {}.u64 | {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2] << 16);
        break;

    case PPC_INST_RLDICL:
        println("\t{}.u64 = __builtin_rotateleft64({}.u64, {}) & 0x{:X};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2], ComputeMask(insn.operands[3], 63));
        break;

    case PPC_INST_RLDICR:
        println("\t{}.u64 = __builtin_rotateleft64({}.u64, {}) & 0x{:X};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2], ComputeMask(0, insn.operands[3]));
        break;

    case PPC_INST_RLDIMI:
    {
        const uint64_t mask = ComputeMask(insn.operands[3], ~insn.operands[2]);
        println("\t{}.u64 = (__builtin_rotateleft64({}.u64, {}) & 0x{:X}) | ({}.u64 & 0x{:X});", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2], mask, r(insn.operands[0]), ~mask);
        break;
    }

    case PPC_INST_RLWIMI:
    {
        const uint64_t mask = ComputeMask(insn.operands[3] + 32, insn.operands[4] + 32);
        println("\t{}.u64 = (__builtin_rotateleft32({}.u32, {}) & 0x{:X}) | ({}.u64 & 0x{:X});", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2], mask, r(insn.operands[0]), ~mask);
        break;
    }

    case PPC_INST_RLWINM:
        println("\t{}.u64 = __builtin_rotateleft64({}.u32 | ({}.u64 << 32), {}) & 0x{:X};", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[1]), insn.operands[2], ComputeMask(insn.operands[3] + 32, insn.operands[4] + 32));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_RLWNM:
        println("\t{}.u64 = __builtin_rotateleft64({}.u32 | ({}.u64 << 32), {}.u8 & 0x1F) & 0x{:X};", 
            r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[1]), 
            r(insn.operands[2]), ComputeMask(insn.operands[3] + 32, insn.operands[4] + 32));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_ROTLDI:
        println("\t{}.u64 = __builtin_rotateleft64({}.u64, {});", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2]);
        break;

    case PPC_INST_ROTLW:
        println("\t{}.u64 = __builtin_rotateleft32({}.u32, {}.u8 & 0x1F);", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_ROTLWI:
        println("\t{}.u64 = __builtin_rotateleft32({}.u32, {});", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2]);
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_SLD:
        println("\t{}.u64 = {}.u8 & 0x40 ? 0 : ({}.u64 << ({}.u8 & 0x7F));", r(insn.operands[0]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_SLW:
        println("\t{}.u64 = {}.u8 & 0x20 ? 0 : ({}.u32 << ({}.u8 & 0x3F));", r(insn.operands[0]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_SRAD:
        println("\t{}.u64 = {}.u64 & 0x7F;", temp(), r(insn.operands[2]));
        println("\tif ({}.u64 > 0x3F) {}.u64 = 0x3F;", temp(), temp());
        println("\t{}.ca = ({}.s64 < 0) & ((({}.s64 >> {}.u64) << {}.u64) != {}.s64);", xer(), r(insn.operands[1]), r(insn.operands[1]), temp(), temp(), r(insn.operands[1]));
        println("\t{}.s64 = {}.s64 >> {}.u64;", r(insn.operands[0]), r(insn.operands[1]), temp());
        break;

    case PPC_INST_SRADI:
        if (insn.operands[2] != 0)
        {
            println("\t{}.ca = ({}.s64 < 0) & (({}.u64 & 0x{:X}) != 0);", xer(), r(insn.operands[1]), r(insn.operands[1]), ComputeMask(64 - insn.operands[2], 63));
            println("\t{}.s64 = {}.s64 >> {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2]);
        }
        else
        {
            println("\t{}.ca = 0;", xer());
            println("\t{}.s64 = {}.s64;", r(insn.operands[0]), r(insn.operands[1]));
        }
        break;

    case PPC_INST_SRAW:
        println("\t{}.u32 = {}.u32 & 0x3F;", temp(), r(insn.operands[2]));
        println("\tif ({}.u32 > 0x1F) {}.u32 = 0x1F;", temp(), temp());
        println("\t{}.ca = ({}.s32 < 0) & ((({}.s32 >> {}.u32) << {}.u32) != {}.s32);", xer(), r(insn.operands[1]), r(insn.operands[1]), temp(), temp(), r(insn.operands[1]));
        println("\t{}.s64 = {}.s32 >> {}.u32;", r(insn.operands[0]), r(insn.operands[1]), temp());
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_SRAWI:
        if (insn.operands[2] != 0)
        {
            println("\t{}.ca = ({}.s32 < 0) & (({}.u32 & 0x{:X}) != 0);", xer(), r(insn.operands[1]), r(insn.operands[1]), ComputeMask(64 - insn.operands[2], 63));
            println("\t{}.s64 = {}.s32 >> {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2]);
        }
        else
        {
            println("\t{}.ca = 0;", xer());
            println("\t{}.s64 = {}.s32;", r(insn.operands[0]), r(insn.operands[1]));
        }
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_SRD:
        println("\t{}.u64 = {}.u8 & 0x40 ? 0 : ({}.u64 >> ({}.u8 & 0x7F));", r(insn.operands[0]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[2]));
        break;

    case PPC_INST_SRW:
        println("\t{}.u64 = {}.u8 & 0x20 ? 0 : ({}.u32 >> ({}.u8 & 0x3F));", r(insn.operands[0]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_STB:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U8(" : "\tPPC_STORE_U8(");
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{}, {}.u8);", int32_t(insn.operands[1]), r(insn.operands[0]));
        break;

    case PPC_INST_STBU:
        println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        println("\tPPC_STORE_U8({}, {}.u8);", ea(), r(insn.operands[0]));
        println("\t{}.u32 = {};", r(insn.operands[2]), ea());
        break;

    case PPC_INST_STBX:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U8(" : "\tPPC_STORE_U8(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, {}.u8);", r(insn.operands[2]), r(insn.operands[0]));
        break;

    case PPC_INST_STD:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U64(" : "\tPPC_STORE_U64(");
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{}, {}.u64);", int32_t(insn.operands[1]), r(insn.operands[0]));
        break;

    case PPC_INST_STDCX:
        println("\t{}.lt = 0;", cr(0));
        println("\t{}.gt = 0;", cr(0));
        print("\t{}.eq = __sync_bool_compare_and_swap(reinterpret_cast<uint64_t*>(base + ", cr(0));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32), {}.s64, __builtin_bswap64({}.s64));", r(insn.operands[2]), reserved(), r(insn.operands[0]));
        println("\t{}.so = {}.so;", cr(0), xer());
        break;

    case PPC_INST_STDU:
        println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        println("\tPPC_STORE_U64({}, {}.u64);", ea(), r(insn.operands[0]));
        println("\t{}.u32 = {};", r(insn.operands[2]), ea());
        break;

    case PPC_INST_STDX:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U64(" : "\tPPC_STORE_U64(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, {}.u64);", r(insn.operands[2]), r(insn.operands[0]));
        break;

    case PPC_INST_STFD:
        printSetFlushMode(false);
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U64(" : "\tPPC_STORE_U64(");
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{}, {}.u64);", int32_t(insn.operands[1]), f(insn.operands[0]));
        break;

    case PPC_INST_STFDX:
        printSetFlushMode(false);
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U64(" : "\tPPC_STORE_U64(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, {}.u64);", r(insn.operands[2]), f(insn.operands[0]));
        break;

    case PPC_INST_STFIWX:
        printSetFlushMode(false);
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U32(" : "\tPPC_STORE_U32(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, {}.u32);", r(insn.operands[2]), f(insn.operands[0]));
        break;

    case PPC_INST_STFS:
        printSetFlushMode(false);
        println("\t{}.f32 = float({}.f64);", temp(), f(insn.operands[0]));
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U32(" : "\tPPC_STORE_U32(");
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{}, {}.u32);", int32_t(insn.operands[1]), temp());
        break;

    case PPC_INST_STFSX:
        printSetFlushMode(false);
        println("\t{}.f32 = float({}.f64);", temp(), f(insn.operands[0]));
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U32(" : "\tPPC_STORE_U32(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, {}.u32);", r(insn.operands[2]), temp());
        break;

    case PPC_INST_STH:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U16(" : "\tPPC_STORE_U16(");
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{}, {}.u16);", int32_t(insn.operands[1]), r(insn.operands[0]));
        break;

    case PPC_INST_STHBRX:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U16(" : "\tPPC_STORE_U16(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, __builtin_bswap16({}.u16));", r(insn.operands[2]), r(insn.operands[0]));
        break;

    case PPC_INST_STHX:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U16(" : "\tPPC_STORE_U16(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, {}.u16);", r(insn.operands[2]), r(insn.operands[0]));
        break;

    case PPC_INST_STVEHX:
        // TODO: vectorize
        // NOTE: accounting for the full vector reversal here
        print("\t{} = (", ea());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32) & ~0x1;", r(insn.operands[2]));
        println("\tPPC_STORE_U16(ea, {}.u16[7 - (({} & 0xF) >> 1)]);", v(insn.operands[0]), ea());
        break;

    case PPC_INST_STVEWX:
    case PPC_INST_STVEWX128:
        // TODO: vectorize
        // NOTE: accounting for the full vector reversal here
        print("\t{} = (", ea());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32) & ~0x3;", r(insn.operands[2]));
        println("\tPPC_STORE_U32(ea, {}.u32[3 - (({} & 0xF) >> 2)]);", v(insn.operands[0]), ea());
        break;

    case PPC_INST_STVLX:
    case PPC_INST_STVLX128:
        // TODO: vectorize
        // NOTE: accounting for the full vector reversal here
        print("\t{} = ", ea());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32;", r(insn.operands[2]));

        println("\tfor (size_t i = 0; i < (16 - ({} & 0xF)); i++)", ea());
        println("\t\tPPC_STORE_U8({} + i, {}.u8[15 - i]);", ea(), v(insn.operands[0]));
        break;

    case PPC_INST_STVRX:
    case PPC_INST_STVRX128:
        // TODO: vectorize
        // NOTE: accounting for the full vector reversal here
        print("\t{} = ", ea());
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32;", r(insn.operands[2]));

        println("\tfor (size_t i = 0; i < ({} & 0xF); i++)", ea());
        println("\t\tPPC_STORE_U8({} - i - 1, {}.u8[i]);", ea(), v(insn.operands[0]));
        break;

    case PPC_INST_STVX:
    case PPC_INST_STVX128:
        print("\t_mm_store_si128((__m128i*)(base + ((");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32) & ~0xF)), _mm_shuffle_epi8(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*)VectorMaskL)));", r(insn.operands[2]), v(insn.operands[0]));
        break;

    case PPC_INST_STW:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U32(" : "\tPPC_STORE_U32(");
        if (insn.operands[2] != 0)
            print("{}.u32 + ", r(insn.operands[2]));
        println("{}, {}.u32);", int32_t(insn.operands[1]), r(insn.operands[0]));
        break;

    case PPC_INST_STWBRX:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U32(" : "\tPPC_STORE_U32(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, __builtin_bswap32({}.u32));", r(insn.operands[2]), r(insn.operands[0]));
        break;

    case PPC_INST_STWCX:
        println("\t{}.lt = 0;", cr(0));
        println("\t{}.gt = 0;", cr(0));
        print("\t{}.eq = __sync_bool_compare_and_swap(reinterpret_cast<uint32_t*>(base + ", cr(0));
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32), {}.s32, __builtin_bswap32({}.s32));", r(insn.operands[2]), reserved(), r(insn.operands[0]));
        println("\t{}.so = {}.so;", cr(0), xer());
        break;

    case PPC_INST_STWU:
        println("\t{} = {} + {}.u32;", ea(), int32_t(insn.operands[1]), r(insn.operands[2]));
        println("\tPPC_STORE_U32({}, {}.u32);", ea(), r(insn.operands[0]));
        println("\t{}.u32 = {};", r(insn.operands[2]), ea());
        break;

    case PPC_INST_STWUX:
        println("\t{} = {}.u32 + {}.u32;", ea(), r(insn.operands[1]), r(insn.operands[2]));
        println("\tPPC_STORE_U32({}, {}.u32);", ea(), r(insn.operands[0]));
        println("\t{}.u32 = {};", r(insn.operands[1]), ea());
        break;

    case PPC_INST_STWX:
        print("{}", mmioStore() ? "\tPPC_MM_STORE_U32(" : "\tPPC_STORE_U32(");
        if (insn.operands[1] != 0)
            print("{}.u32 + ", r(insn.operands[1]));
        println("{}.u32, {}.u32);", r(insn.operands[2]), r(insn.operands[0]));
        break;

    case PPC_INST_SUBF:
        println("\t{}.s64 = {}.s64 - {}.s64;", r(insn.operands[0]), r(insn.operands[2]), r(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_SUBFC:
        println("\t{}.ca = {}.u32 >= {}.u32;", xer(), r(insn.operands[2]), r(insn.operands[1]));
        println("\t{}.s64 = {}.s64 - {}.s64;", r(insn.operands[0]), r(insn.operands[2]), r(insn.operands[1]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_SUBFE:
        println("\t{}.u8 = (~{}.u32 + {}.u32 < ~{}.u32) | (~{}.u32 + {}.u32 + {}.ca < {}.ca);", temp(), r(insn.operands[1]), r(insn.operands[2]), r(insn.operands[1]), r(insn.operands[1]), r(insn.operands[2]), xer(), xer());
        println("\t{}.u64 = ~{}.u64 + {}.u64 + {}.ca;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]), xer());
        println("\t{}.ca = {}.u8;", xer(), temp());
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_SUBFIC:
        println("\t{}.ca = {}.u32 <= {};", xer(), r(insn.operands[1]), insn.operands[2]);
        println("\t{}.s64 = {} - {}.s64;", r(insn.operands[0]), int32_t(insn.operands[2]), r(insn.operands[1]));
        break;

    case PPC_INST_SUBFME:
        println("\t{}.u64 = ~{}.u64 + {}.ca - 1;", temp(), r(insn.operands[1]), xer());
        println("\t{}.ca = ({}.u64 < ~{}.u64) || ({}.u64 == ~{}.u64 && {}.ca);", xer(), 
            temp(), r(insn.operands[1]), temp(), r(insn.operands[1]), xer());
        println("\t{}.u64 = {}.u64;", r(insn.operands[0]), temp());
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", 
                cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_SUBFZE:
        println("\t{}.u64 = ~{}.u64 + {}.ca;", temp(), r(insn.operands[1]), xer());
        println("\t{}.ca = {}.u64 < {}.ca;", xer(), temp(), xer());
        println("\t{}.u64 = {}.u64;", r(insn.operands[0]), temp());
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_SYNC:
        // no op
        break;

    case PPC_INST_TDEQ:
        println("\tif ({}.u64 == {}.u64) __builtin_debugtrap();", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_TDEQI:
        println("\tif ({}.u64 == {}) __builtin_debugtrap();", r(insn.operands[0]), insn.operands[1]);
        break;

    case PPC_INST_TDGE:
        println("\tif ({}.s64 >= {}.s64) __builtin_debugtrap();", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_TDGEI:
        println("\tif ({}.s64 >= {}) __builtin_debugtrap();", r(insn.operands[0]), int32_t(insn.operands[1]));
        break;

    case PPC_INST_TDGT:
        println("\tif ({}.s64 > {}.s64) __builtin_debugtrap();", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_TDGTI:
        println("\tif ({}.s64 > {}) __builtin_debugtrap();", r(insn.operands[0]), int32_t(insn.operands[1]));
        break;

    case PPC_INST_TDLE:
        println("\tif ({}.s64 <= {}.s64) __builtin_debugtrap();", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_TDLEI:
        println("\tif ({}.s64 <= {}) __builtin_debugtrap();", r(insn.operands[0]), int32_t(insn.operands[1]));
        break;

    case PPC_INST_TDLGE:
        println("\tif ({}.u64 >= {}.u64) __builtin_debugtrap();", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_TDLGEI:
        println("\tif ({}.u64 >= {}) __builtin_debugtrap();", r(insn.operands[0]), insn.operands[1]);
        break;

    case PPC_INST_TDLGT:
        println("\tif ({}.u64 > {}.u64) __builtin_debugtrap();", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_TDLGTI:
        println("\tif ({}.u64 > {}) __builtin_debugtrap();", r(insn.operands[0]), insn.operands[1]);
        break;

    case PPC_INST_TDLLE:
        println("\tif ({}.u64 <= {}.u64) __builtin_debugtrap();", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_TDLLEI:
        println("\tif ({}.u64 <= {}) __builtin_debugtrap();", r(insn.operands[0]), insn.operands[1]);
        break;

    case PPC_INST_TDLLT:
        println("\tif ({}.u64 < {}.u64) __builtin_debugtrap();", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_TDLLTI:
        println("\tif ({}.u64 < {}) __builtin_debugtrap();", r(insn.operands[0]), insn.operands[1]);
        break;

    case PPC_INST_TDLT:
        println("\tif ({}.s64 < {}.s64) __builtin_debugtrap();", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_TDLTI:
        println("\tif ({}.s64 < {}) __builtin_debugtrap();", r(insn.operands[0]), int32_t(insn.operands[1]));
        break;

    case PPC_INST_TDNE:
        println("\tif ({}.u64 != {}.u64) __builtin_debugtrap();", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_TDNEI:
        println("\tif ({}.u64 != {}) __builtin_debugtrap();", r(insn.operands[0]), insn.operands[1]);
        break;
    case PPC_INST_TWI:
    {
        // TO field specifies trap conditions:
        // Bit 0 (16): Less than (signed)
        // Bit 1 (8): Greater than (signed)  
        // Bit 2 (4): Equal
        // Bit 3 (2): Less than (unsigned)
        // Bit 4 (1): Greater than (unsigned)
        
        bool first = true;
        print("\tif (");
        
        if (insn.operands[0] & 16) {
            print("{}.s32 < {}", r(insn.operands[1]), int32_t(insn.operands[2]));
            first = false;
        }
        
        if (insn.operands[0] & 8) {
            if (!first) print(" || ");
            print("{}.s32 > {}", r(insn.operands[1]), int32_t(insn.operands[2]));
            first = false;
        }
        
        if (insn.operands[0] & 4) {
            if (!first) print(" || ");
            print("{}.u32 == {}", r(insn.operands[1]), insn.operands[2]);
            first = false;
        }
        
        if (insn.operands[0] & 2) {
            if (!first) print(" || ");
            print("{}.u32 < {}", r(insn.operands[1]), insn.operands[2]);
            first = false;
        }
        
        if (insn.operands[0] & 1) {
            if (!first) print(" || ");
            print("{}.u32 > {}", r(insn.operands[1]), insn.operands[2]);
            first = false;
        }
        
        if (first) {
            // TO = 0 means never trap
            println("false) __builtin_debugtrap();");
        } else {
            println(") __builtin_debugtrap();");
        }
    }
    break;

    case PPC_INST_TWEQ:
        println("\tif ({}.u32 == {}.u32) __builtin_debugtrap();", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_TWEQI:
        println("\tif ({}.u32 == {}) __builtin_debugtrap();", r(insn.operands[0]), insn.operands[1]);
        break;

    case PPC_INST_TWGE:
        println("\tif ({}.s32 >= {}.s32) __builtin_debugtrap();", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_TWGEI:
        println("\tif ({}.s32 >= {}) __builtin_debugtrap();", r(insn.operands[0]), int32_t(insn.operands[1]));
        break;

    case PPC_INST_TWGT:
        println("\tif ({}.s32 > {}.s32) __builtin_debugtrap();", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_TWGTI:
        println("\tif ({}.s32 > {}) __builtin_debugtrap();", r(insn.operands[0]), int32_t(insn.operands[1]));
        break;

    case PPC_INST_TWLE:
        println("\tif ({}.s32 <= {}.s32) __builtin_debugtrap();", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_TWLEI:
        println("\tif ({}.s32 <= {}) __builtin_debugtrap();", r(insn.operands[0]), int32_t(insn.operands[1]));
        break;

    case PPC_INST_TWLGE:
        println("\tif ({}.u32 >= {}.u32) __builtin_debugtrap();", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_TWLGEI:
        println("\tif ({}.u32 >= {}) __builtin_debugtrap();", r(insn.operands[0]), insn.operands[1]);
        break;

    case PPC_INST_TWLGT:
        println("\tif ({}.u32 > {}.u32) __builtin_debugtrap();", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_TWLGTI:
        println("\tif ({}.u32 > {}) __builtin_debugtrap();", r(insn.operands[0]), insn.operands[1]);
        break;

    case PPC_INST_TWLLE:
        println("\tif ({}.u32 <= {}.u32) __builtin_debugtrap();", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_TWLLEI:
        println("\tif ({}.u32 <= {}) __builtin_debugtrap();", r(insn.operands[0]), insn.operands[1]);
        break;

    case PPC_INST_TWLLT:
        println("\tif ({}.u32 < {}.u32) __builtin_debugtrap();", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_TWLLTI:
        println("\tif ({}.u32 < {}) __builtin_debugtrap();", r(insn.operands[0]), insn.operands[1]);
        break;

    case PPC_INST_TWLT:
        println("\tif ({}.s32 < {}.s32) __builtin_debugtrap();", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_TWLTI:
        println("\tif ({}.s32 < {}) __builtin_debugtrap();", r(insn.operands[0]), int32_t(insn.operands[1]));
        break;

    case PPC_INST_TWNE:
        println("\tif ({}.u32 != {}.u32) __builtin_debugtrap();", r(insn.operands[0]), r(insn.operands[1]));
        break;

    case PPC_INST_TWNEI:
        println("\tif ({}.u32 != {}) __builtin_debugtrap();", r(insn.operands[0]), insn.operands[1]);
        break;

    case PPC_INST_VADDFP:
    case PPC_INST_VADDFP128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_add_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VADDSHS:
        println("\t_mm_store_si128((__m128i*){}.s16, _mm_adds_epi16(_mm_load_si128((__m128i*){}.s16), _mm_load_si128((__m128i*){}.s16)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VADDUBM:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_add_epi8(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VADDUBS:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_adds_epu8(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VADDUHM:
        println("\t_mm_store_si128((__m128i*){}.u16, _mm_add_epi16(_mm_load_si128((__m128i*){}.u16), _mm_load_si128((__m128i*){}.u16)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VADDUWM:
        println("\t_mm_store_si128((__m128i*){}.u32, _mm_add_epi32(_mm_load_si128((__m128i*){}.u32), _mm_load_si128((__m128i*){}.u32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VADDUWS:
        println("\t_mm_store_si128((__m128i*){}.u32, _mm_adds_epu32(_mm_load_si128((__m128i*){}.u32), _mm_load_si128((__m128i*){}.u32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VAND:
    case PPC_INST_VAND128:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_and_si128(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VANDC:
    case PPC_INST_VANDC128:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_andnot_si128(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VAVGSB:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_avg_epi8(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VAVGSH:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_avg_epi16(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VAVGUB:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_avg_epu8(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VAVGUH:
        println("\t_mm_store_si128((__m128i*){}.u16, _mm_avg_epu16(_mm_load_si128((__m128i*){}.u16), _mm_load_si128((__m128i*){}.u16)));", 
            v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VCTSXS:
    case PPC_INST_VCFPSXWS128:
        printSetFlushMode(true);
        print("\t_mm_store_si128((__m128i*){}.s32, _mm_vctsxs(", v(insn.operands[0]));
        if (insn.operands[2] != 0)
            println("_mm_mul_ps(_mm_load_ps({}.f32), _mm_set1_ps({}))));", v(insn.operands[1]), 1u << insn.operands[2]);
        else
            println("_mm_load_ps({}.f32)));", v(insn.operands[1]));
        break;

    case PPC_INST_VCTUXS:
    case PPC_INST_VCFPUXWS128:
        printSetFlushMode(true);
        print("\t_mm_store_si128((__m128i*){}.u32, _mm_vctuxs(", v(insn.operands[0]));
        if (insn.operands[2] != 0)
            println("_mm_mul_ps(_mm_load_ps({}.f32), _mm_set1_ps({}))));", v(insn.operands[1]), 1u << insn.operands[2]);
        else
            println("_mm_load_ps({}.f32)));", v(insn.operands[1]));
        break;

    case PPC_INST_VCFSX:
    case PPC_INST_VCSXWFP128:
    {
        printSetFlushMode(true);
        print("\t_mm_store_ps({}.f32, ", v(insn.operands[0]));
        if (insn.operands[2] != 0)
        {
            const float value = ldexp(1.0f, -int32_t(insn.operands[2]));
            println("_mm_mul_ps(_mm_cvtepi32_ps(_mm_load_si128((__m128i*){}.u32)), _mm_castsi128_ps(_mm_set1_epi32(int(0x{:X})))));", v(insn.operands[1]), *reinterpret_cast<const uint32_t*>(&value));
        }
        else
        {
            println("_mm_cvtepi32_ps(_mm_load_si128((__m128i*){}.u32)));", v(insn.operands[1]));
        }
        break;
    }

    case PPC_INST_VCFUX:
    case PPC_INST_VCUXWFP128:
    {
        printSetFlushMode(true);
        print("\t_mm_store_ps({}.f32, ", v(insn.operands[0]));
        if (insn.operands[2] != 0)
        {
            const float value = ldexp(1.0f, -int32_t(insn.operands[2]));
            println("_mm_mul_ps(_mm_cvtepu32_ps_(_mm_load_si128((__m128i*){}.u32)), _mm_castsi128_ps(_mm_set1_epi32(int(0x{:X})))));", v(insn.operands[1]), *reinterpret_cast<const uint32_t*>(&value));
        }
        else
        {
            println("_mm_cvtepu32_ps_(_mm_load_si128((__m128i*){}.u32)));", v(insn.operands[1]));
        }
        break;
    }

    case PPC_INST_VCMPBFP:
    case PPC_INST_VCMPBFP128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_vcmpbfp(_mm_load_ps({}.f32), _mm_load_ps({}.f32)));", 
            v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.setFromMask(_mm_load_ps({}.f32), 0xF);", cr(6), v(insn.operands[0]));
        break;

    case PPC_INST_VCMPEQFP:
    case PPC_INST_VCMPEQFP128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_cmpeq_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.setFromMask(_mm_load_ps({}.f32), 0xF);", cr(6), v(insn.operands[0]));
        break;

    case PPC_INST_VCMPEQUB:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_cmpeq_epi8(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.setFromMask(_mm_load_si128((__m128i*){}.u8), 0xFFFF);", cr(6), v(insn.operands[0]));
        break;

    case PPC_INST_VCMPEQUW:
    case PPC_INST_VCMPEQUW128:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_cmpeq_epi32(_mm_load_si128((__m128i*){}.u32), _mm_load_si128((__m128i*){}.u32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.setFromMask(_mm_load_ps({}.f32), 0xF);", cr(6), v(insn.operands[0]));
        break;

    case PPC_INST_VCMPGEFP:
    case PPC_INST_VCMPGEFP128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_cmpge_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.setFromMask(_mm_load_ps({}.f32), 0xF);", cr(6), v(insn.operands[0]));
        break;

    case PPC_INST_VCMPGTFP:
    case PPC_INST_VCMPGTFP128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_cmpgt_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.setFromMask(_mm_load_ps({}.f32), 0xF);", cr(6), v(insn.operands[0]));
        break;

    case PPC_INST_VCMPGTUB:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_cmpgt_epu8(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VCMPGTUH:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_cmpgt_epu16(_mm_load_si128((__m128i*){}.u16), _mm_load_si128((__m128i*){}.u16)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VEXPTEFP:
    case PPC_INST_VEXPTEFP128:
        // TODO: vectorize
        printSetFlushMode(true);
        for (size_t i = 0; i < 4; i++)
            println("\t{}.f32[{}] = exp2f({}.f32[{}]);", v(insn.operands[0]), i, v(insn.operands[1]), i);
        break;

    case PPC_INST_VLOGEFP:
    case PPC_INST_VLOGEFP128:
        // TODO: vectorize
        printSetFlushMode(true);
        for (size_t i = 0; i < 4; i++)
            println("\t{}.f32[{}] = log2f({}.f32[{}]);", v(insn.operands[0]), i, v(insn.operands[1]), i);
        break;

    case PPC_INST_VMADDCFP128:
    case PPC_INST_VMADDFP:
    case PPC_INST_VMADDFP128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_add_ps(_mm_mul_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32)), _mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]), v(insn.operands[3]));
        break;

    case PPC_INST_VMAXFP:
    case PPC_INST_VMAXFP128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_max_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VMAXSH:
        println("\t_mm_store_si128((__m128i*){}.s16, _mm_max_epi16(_mm_load_si128((__m128i*){}.s16), _mm_load_si128((__m128i*){}.s16)));", 
            v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VMAXSW:
        println("\t_mm_store_si128((__m128i*){}.u32, _mm_max_epi32(_mm_load_si128((__m128i*){}.u32), _mm_load_si128((__m128i*){}.u32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VMAXUH:
        println("\t_mm_store_si128((__m128i*){}.u16, _mm_max_epu16(_mm_load_si128((__m128i*){}.u16), _mm_load_si128((__m128i*){}.u16)));", 
            v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VMINFP:
    case PPC_INST_VMINFP128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_min_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VMINSH:
        println("\t_mm_store_si128((__m128i*){}.s16, _mm_min_epi16(_mm_load_si128((__m128i*){}.s16), _mm_load_si128((__m128i*){}.s16)));", 
            v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VMINUH:
        println("\t_mm_store_si128((__m128i*){}.u16, _mm_min_epu16(_mm_load_si128((__m128i*){}.u16), _mm_load_si128((__m128i*){}.u16)));", 
            v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VMRGHB:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_unpackhi_epi8(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VMRGHH:
        println("\t_mm_store_si128((__m128i*){}.u16, _mm_unpackhi_epi16(_mm_load_si128((__m128i*){}.u16), _mm_load_si128((__m128i*){}.u16)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VMRGHW:
    case PPC_INST_VMRGHW128:
        println("\t_mm_store_si128((__m128i*){}.u32, _mm_unpackhi_epi32(_mm_load_si128((__m128i*){}.u32), _mm_load_si128((__m128i*){}.u32)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VMRGLB:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_unpacklo_epi8(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VMRGLH:
        println("\t_mm_store_si128((__m128i*){}.u16, _mm_unpacklo_epi16(_mm_load_si128((__m128i*){}.u16), _mm_load_si128((__m128i*){}.u16)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VMRGLW:
    case PPC_INST_VMRGLW128:
        println("\t_mm_store_si128((__m128i*){}.u32, _mm_unpacklo_epi32(_mm_load_si128((__m128i*){}.u32), _mm_load_si128((__m128i*){}.u32)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VMSUM3FP128:
        // NOTE: accounting for full vector reversal here. should dot product yzw instead of xyz
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_dp_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32), 0xEF));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VMSUM4FP128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_dp_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32), 0xFF));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VMULFP128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_mul_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VNMSUBFP:
    case PPC_INST_VNMSUBFP128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_xor_ps(_mm_sub_ps(_mm_mul_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32)), _mm_load_ps({}.f32)), _mm_castsi128_ps(_mm_set1_epi32(int(0x80000000)))));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]), v(insn.operands[3]));
        break;

    case PPC_INST_VNOR:
    case PPC_INST_VNOR128:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_xor_si128(_mm_or_si128(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)), _mm_set1_epi32(-1)));",
            v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VOR:
    case PPC_INST_VOR128:
        print("\t_mm_store_si128((__m128i*){}.u8, ", v(insn.operands[0]));

        if (insn.operands[1] != insn.operands[2])
            println("_mm_or_si128(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[1]), v(insn.operands[2]));
        else
            println("_mm_load_si128((__m128i*){}.u8));", v(insn.operands[1]));

        break;

    case PPC_INST_VPERM:
    case PPC_INST_VPERM128:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_perm_epi8_(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]), v(insn.operands[3]));
        break;

    case PPC_INST_VPERMWI128:
    {
        // NOTE: accounting for full vector reversal here
        uint32_t x = 3 - (insn.operands[2] & 0x3);
        uint32_t y = 3 - ((insn.operands[2] >> 2) & 0x3);
        uint32_t z = 3 - ((insn.operands[2] >> 4) & 0x3);
        uint32_t w = 3 - ((insn.operands[2] >> 6) & 0x3);
        uint32_t perm = x | (y << 2) | (z << 4) | (w << 6);
        println("\t_mm_store_si128((__m128i*){}.u32, _mm_shuffle_epi32(_mm_load_si128((__m128i*){}.u32), 0x{:X}));", v(insn.operands[0]), v(insn.operands[1]), perm);
        break;
    }

    case PPC_INST_VPKD3D128:
        // TODO: vectorize somehow?
        // NOTE: handling vector reversal here too
        printSetFlushMode(true);
        switch (insn.operands[2])
        {
        case 0: // D3D color
            if (insn.operands[3] != 1)
                fmt::println("Unexpected D3D color pack instruction at {:X}", base);

            for (size_t i = 0; i < 4; i++)
            {
                constexpr size_t indices[] = { 3, 0, 1, 2 };
                println("\t{}.u32[{}] = 0x404000FF;", vTemp(), i);
                println("\t{}.f32[{}] = {}.f32[{}] < 3.0f ? 3.0f : ({}.f32[{}] > {}.f32[{}] ? {}.f32[{}] : {}.f32[{}]);", vTemp(), i, v(insn.operands[1]), i, v(insn.operands[1]), i, vTemp(), i, vTemp(), i, v(insn.operands[1]), i);
                println("\t{}.u32 {}= uint32_t({}.u8[{}]) << {};", temp(), i == 0 ? "" : "|", vTemp(), i * 4, indices[i] * 8);
            }
            println("\t{}.u32[{}] = {}.u32;", v(insn.operands[0]), insn.operands[4], temp());
            break;

        case 5: // float16_4
            if (insn.operands[3] != 2 || insn.operands[4] > 2)
                fmt::println("Unexpected float16_4 pack instruction at {:X}", base);

            for (size_t i = 0; i < 4; i++)
            {
        		// Strip sign from source
        		println("\t{}.u32 = ({}.u32[{}]&0x7FFFFFFF);", temp(), v(insn.operands[1]), i);
        		// If |source| is > 65504, clamp output to 0x7FFF, else save 8 exponent bits 
        		println("\t{0}.u8[0] = ({1}.f32 != {1}.f32) || ({1}.f32 > 65504.0f) ? 0xFF : (({2}.u32[{3}]&0x7f800000)>>23);", vTemp(), temp(), v(insn.operands[1]), i);
        		// If 8 exponent bits were saved, it can only be 0x8E at most
        		// If saved, save first 10 bits of mantissa
        		println("\t{}.u16 = {}.u8[0] != 0xFF ? (({}.u32[{}]&0x7FE000)>>13) : 0x0;", temp(), vTemp(), v(insn.operands[1]), i);
        		// If saved and > 127-15, exponent is converted from 8 to 5-bit by subtracting 0x70
        		// If saved but not > 127-15, clamp exponent at 0, add 0x400 to mantissa and shift right by (0x71-exponent)
        		// If right shift is greater than 31 bits, manually clamp mantissa to 0 or else the output of the shift will be wrong
        		println("\t{0}.u16[{1}] = {2}.u8[0] != 0xFF ? ({2}.u8[0] > 0x70 ? ((({2}.u8[0]-0x70)<<10)+{3}.u16) : (0x71-{2}.u8[0] > 31 ? 0x0 : ((0x400+{3}.u16)>>(0x71-{2}.u8[0])))) : 0x7FFF;", v(insn.operands[0]), i+(2*insn.operands[4]), vTemp(), temp());
        		// Add back original sign
        		println("\t{}.u16[{}] |= (({}.u32[{}]&0x80000000)>>16);", v(insn.operands[0]), i+(2*insn.operands[4]), v(insn.operands[1]), i);
            }
            break;

        default:
            println("\t__builtin_debugtrap();");
            break;
        }
        break;

    case PPC_INST_VPKSHSS:
    case PPC_INST_VPKSHSS128:
        println("\t_mm_store_si128((__m128i*){}.s8, _mm_packs_epi16(_mm_load_si128((__m128i*){}.s16), _mm_load_si128((__m128i*){}.s16)));", 
            v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VPKSHUS:
    case PPC_INST_VPKSHUS128:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_packus_epi16(_mm_load_si128((__m128i*){}.s16), _mm_load_si128((__m128i*){}.s16)));", v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VPKSWSS:
    case PPC_INST_VPKSWSS128:
        println("\t_mm_store_si128((__m128i*){}.s16, _mm_packs_epi32(_mm_load_si128((__m128i*){}.s32), _mm_load_si128((__m128i*){}.s32)));", 
            v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VPKSWUS:
    case PPC_INST_VPKSWUS128:
        println("\t_mm_store_si128((__m128i*){}.s32, _mm_load_si128((__m128i*){}.s32));", vTemp(), v(insn.operands[2]));
        for (int i = 0; i < 4; i++) {
            println("\t{}.u16[{}] = {}.s32[{}] < 0 ? 0 : ({}.s32[{}] > 0xFFFF ? 0xFFFF : {}.s32[{}]);",
                v(insn.operands[0]), i, vTemp(), i, vTemp(), i, vTemp(), i);
        }
        println("\t_mm_store_si128((__m128i*){}.s32, _mm_load_si128((__m128i*){}.s32));", vTemp(), v(insn.operands[1]));
        for (int i = 0; i < 4; i++) {
            println("\t{}.u16[{}] = {}.s32[{}] < 0 ? 0 : ({}.s32[{}] > 0xFFFF ? 0xFFFF : {}.s32[{}]);",
                v(insn.operands[0]), i + 4, vTemp(), i, vTemp(), i, vTemp(), i);
        }
        break;

    case PPC_INST_VPKUHUM:
        // Pack without saturation - use shuffle to select lower bytes
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_packus_epi16("
            "_mm_and_si128(_mm_load_si128((__m128i*){}.u16), _mm_set1_epi16(0xFF)), "
            "_mm_and_si128(_mm_load_si128((__m128i*){}.u16), _mm_set1_epi16(0xFF))));",
            v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VPKUHUS:
    case PPC_INST_VPKUHUS128:
        // Pack unsigned halfwords to unsigned bytes with saturation
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_packus_epi16(_mm_load_si128((__m128i*){}.u16), _mm_load_si128((__m128i*){}.u16)));", 
            v(insn.operands[0]), v(insn.operands[2]), v(insn.operands[1]));
        break;

    case PPC_INST_VPKUWUM:
    case PPC_INST_VPKUWUM128:
        println("\t_mm_store_si128((__m128i*){}.u32, _mm_load_si128((__m128i*){}.u32));", vTemp(), v(insn.operands[2]));
        for (int i = 0; i < 4; i++) {
            println("\t{}.u16[{}] = {}.u16[{}];", 
                v(insn.operands[0]), i, vTemp(), i*2);
        }
        println("\t_mm_store_si128((__m128i*){}.u32, _mm_load_si128((__m128i*){}.u32));", vTemp(), v(insn.operands[1]));
        for (int i = 0; i < 4; i++) {
            println("\t{}.u16[{}] = {}.u16[{}];", 
                v(insn.operands[0]), i + 4, vTemp(), i*2);
        }
        break;

    case PPC_INST_VPKUWUS:
    case PPC_INST_VPKUWUS128:
        println("\t_mm_store_si128((__m128i*){}.u32, _mm_load_si128((__m128i*){}.u32));", vTemp(), v(insn.operands[2]));
        for (int i = 0; i < 4; i++) {
            println("\t{}.u16[{}] = {}.u32[{}] > 0xFFFF ? 0xFFFF : {}.u32[{}];",
                v(insn.operands[0]), i, vTemp(), i, vTemp(), i);
        }
        println("\t_mm_store_si128((__m128i*){}.u32, _mm_load_si128((__m128i*){}.u32));", vTemp(), v(insn.operands[1]));
        for (int i = 0; i < 4; i++) {
            println("\t{}.u16[{}] = {}.u32[{}] > 0xFFFF ? 0xFFFF : {}.u32[{}];",
                v(insn.operands[0]), i + 4, vTemp(), i, vTemp(), i);
        }
        break;

    case PPC_INST_VREFP:
    case PPC_INST_VREFP128:
        // TODO: see if we can use rcp safely
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_div_ps(_mm_set1_ps(1), _mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]));
        break;

    case PPC_INST_VRFIM:
    case PPC_INST_VRFIM128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_round_ps(_mm_load_ps({}.f32), _MM_FROUND_TO_NEG_INF | _MM_FROUND_NO_EXC));", v(insn.operands[0]), v(insn.operands[1]));
        break;

    case PPC_INST_VRFIN:
    case PPC_INST_VRFIN128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_round_ps(_mm_load_ps({}.f32), _MM_FROUND_TO_NEAREST_INT | _MM_FROUND_NO_EXC));", v(insn.operands[0]), v(insn.operands[1]));
        break;

    case PPC_INST_VRFIZ:
    case PPC_INST_VRFIZ128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_round_ps(_mm_load_ps({}.f32), _MM_FROUND_TO_ZERO | _MM_FROUND_NO_EXC));", v(insn.operands[0]), v(insn.operands[1]));
        break;

    case PPC_INST_VRLIMI128:
    {
        constexpr size_t shuffles[] = { _MM_SHUFFLE(3, 2, 1, 0), _MM_SHUFFLE(2, 1, 0, 3), _MM_SHUFFLE(1, 0, 3, 2), _MM_SHUFFLE(0, 3, 2, 1) };
        println("\t_mm_store_ps({}.f32, _mm_blend_ps(_mm_load_ps({}.f32), _mm_permute_ps(_mm_load_ps({}.f32), {}), {}));", v(insn.operands[0]), v(insn.operands[0]), v(insn.operands[1]), shuffles[insn.operands[3]], insn.operands[2]);
        break;
    }

    case PPC_INST_VRSQRTEFP:
    case PPC_INST_VRSQRTEFP128:
        // TODO: see if we can use rsqrt safely
        // TODO: we can detect if the input is from a dot product and apply logic only on one value
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_div_ps(_mm_set1_ps(1), _mm_sqrt_ps(_mm_load_ps({}.f32))));", v(insn.operands[0]), v(insn.operands[1]));
        break;

    case PPC_INST_VSEL:
    case PPC_INST_VSEL128:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_or_si128(_mm_andnot_si128(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)), _mm_and_si128(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8))));", v(insn.operands[0]), v(insn.operands[3]), v(insn.operands[1]), v(insn.operands[3]), v(insn.operands[2]));
        break;

    case PPC_INST_VSL:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_vsl(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", 
            v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VSLB:
        // TODO: vectorize
        for (size_t i = 0; i < 16; i++)
            println("\t{}.u8[{}] = {}.u8[{}] << ({}.u8[{}] & 0x7);", v(insn.operands[0]), i, v(insn.operands[1]), i, v(insn.operands[2]), i);
        break;

    case PPC_INST_VSLH:
        // Vector shift left halfword
        for (size_t i = 0; i < 8; i++)
            println("\t{}.u16[{}] = {}.u16[{}] << ({}.u16[{}] & 0xF);", 
                v(insn.operands[0]), i, v(insn.operands[1]), i, v(insn.operands[2]), i);
        break;

    case PPC_INST_VSRAH:
        // Vector shift right algebraic halfword
        for (size_t i = 0; i < 8; i++)
            println("\t{}.s16[{}] = {}.s16[{}] >> ({}.u16[{}] & 0xF);", 
                v(insn.operands[0]), i, v(insn.operands[1]), i, v(insn.operands[2]), i);
        break;

    case PPC_INST_VSRH:
        // Vector shift right halfword
        for (size_t i = 0; i < 8; i++)
            println("\t{}.u16[{}] = {}.u16[{}] >> ({}.u16[{}] & 0xF);", 
                v(insn.operands[0]), i, v(insn.operands[1]), i, v(insn.operands[2]), i);
        break;

    case PPC_INST_VRLH:
        // Vector rotate left halfword
        for (size_t i = 0; i < 8; i++)
            println("\t{}.u16[{}] = ({}.u16[{}] << ({}.u16[{}] & 0xF)) | "
                "({}.u16[{}] >> (16 - ({}.u16[{}] & 0xF)));", 
                v(insn.operands[0]), i, v(insn.operands[1]), i, v(insn.operands[2]), i,
                v(insn.operands[1]), i, v(insn.operands[2]), i);
        break;

    case PPC_INST_VSLDOI:
    case PPC_INST_VSLDOI128:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_alignr_epi8(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8), {}));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]), 16 - insn.operands[3]);
        break;

    case PPC_INST_VSLW:
    case PPC_INST_VSLW128:
        // TODO: vectorize, ensure endianness is correct
        for (size_t i = 0; i < 4; i++)
            println("\t{}.u32[{}] = {}.u32[{}] << ({}.u8[{}] & 0x1F);", v(insn.operands[0]), i, v(insn.operands[1]), i, v(insn.operands[2]), i * 4);
        break;

    case PPC_INST_VSPLTB:
    {
        // NOTE: accounting for full vector reversal here
        uint32_t perm = 15 - insn.operands[2];
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_shuffle_epi8(_mm_load_si128((__m128i*){}.u8), _mm_set1_epi8(char(0x{:X}))));", v(insn.operands[0]), v(insn.operands[1]), perm);
        break;
    }

    case PPC_INST_VSPLTH:
    {
        // NOTE: accounting for full vector reversal here
        uint32_t perm = 7 - insn.operands[2];
        perm = (perm * 2) | ((perm * 2 + 1) << 8);
        println("\t_mm_store_si128((__m128i*){}.u16, _mm_shuffle_epi8(_mm_load_si128((__m128i*){}.u16), _mm_set1_epi16(short(0x{:X}))));", v(insn.operands[0]), v(insn.operands[1]), perm);
        break;
    }

    case PPC_INST_VSPLTISB:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_set1_epi8(char(0x{:X})));", v(insn.operands[0]), insn.operands[1]);
        break;

    case PPC_INST_VSPLTISH:
        println("\t_mm_store_si128((__m128i*){}.s16, _mm_set1_epi16(short({})));", 
            v(insn.operands[0]), int16_t(insn.operands[1]));
        break;

    case PPC_INST_VSPLTISW:
    case PPC_INST_VSPLTISW128:
        println("\t_mm_store_si128((__m128i*){}.u32, _mm_set1_epi32(int(0x{:X})));", v(insn.operands[0]), insn.operands[1]);
        break;

    case PPC_INST_VSPLTW:
    case PPC_INST_VSPLTW128:
    {
        // NOTE: accounting for full vector reversal here
        uint32_t perm = 3 - insn.operands[2];
        perm |= (perm << 2) | (perm << 4) | (perm << 6);
        println("\t_mm_store_si128((__m128i*){}.u32, _mm_shuffle_epi32(_mm_load_si128((__m128i*){}.u32), 0x{:X}));", v(insn.operands[0]), v(insn.operands[1]), perm);
        break;
    }

    case PPC_INST_VSR:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_vsr(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VSRAW:
    case PPC_INST_VSRAW128:
        // TODO: vectorize, ensure endianness is correct
        for (size_t i = 0; i < 4; i++)
            println("\t{}.s32[{}] = {}.s32[{}] >> ({}.u8[{}] & 0x1F);", v(insn.operands[0]), i, v(insn.operands[1]), i, v(insn.operands[2]), i * 4);
        break;

    case PPC_INST_VSRW:
    case PPC_INST_VSRW128:
        // TODO: vectorize, ensure endianness is correct
        for (size_t i = 0; i < 4; i++)
            println("\t{}.u32[{}] = {}.u32[{}] >> ({}.u8[{}] & 0x1F);", v(insn.operands[0]), i, v(insn.operands[1]), i, v(insn.operands[2]), i * 4);
        break;

    case PPC_INST_VSUBFP:
    case PPC_INST_VSUBFP128:
        printSetFlushMode(true);
        println("\t_mm_store_ps({}.f32, _mm_sub_ps(_mm_load_ps({}.f32), _mm_load_ps({}.f32)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VSUBSHS:
        println("\t_mm_store_si128((__m128i*){}.s16, _mm_subs_epi16(_mm_load_si128((__m128i*){}.s16), _mm_load_si128((__m128i*){}.s16)));", 
            v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VSUBSWS:
        // TODO: vectorize
        for (size_t i = 0; i < 4; i++)
        {
            println("\t{}.s64 = int64_t({}.s32[{}]) - int64_t({}.s32[{}]);", temp(), v(insn.operands[1]), i, v(insn.operands[2]), i);
            println("\t{}.s32[{}] = {}.s64 > INT_MAX ? INT_MAX : {}.s64 < INT_MIN ? INT_MIN : {}.s64;", v(insn.operands[0]), i, temp(), temp(), temp());
        }
        break;

    case PPC_INST_VSUBUBS:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_subs_epu8(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VSUBUHM:
        println("\t_mm_store_si128((__m128i*){}.u8, _mm_sub_epi16(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[2]));
        break;

    case PPC_INST_VUPKD3D128:
        // TODO: vectorize somehow?
        // NOTE: handling vector reversal here too
        switch (insn.operands[2] >> 2)
        {
        case 0: // D3D color
            for (size_t i = 0; i < 4; i++)
            {
                constexpr size_t indices[] = { 3, 0, 1, 2 };
                println("\t{}.u32[{}] = {}.u8[{}] | 0x3F800000;", vTemp(), i, v(insn.operands[1]), indices[i]);
            }
            println("\t{} = {};", v(insn.operands[0]), vTemp());
            break;

        case 1: // 2 shorts
            for (size_t i = 0; i < 2; i++)
            {
                println("\t{}.f32 = 3.0f;", temp());
                println("\t{}.s32 += {}.s16[{}];", temp(), v(insn.operands[1]), 1 - i);
                println("\t{}.f32[{}] = {}.f32;", vTemp(), 3 - i, temp());
            }
            println("\t{}.f32[1] = 0.0f;", vTemp());
            println("\t{}.f32[0] = 1.0f;", vTemp());
            println("\t{} = {};", v(insn.operands[0]), vTemp());
            break;

        default:
            println("\t__builtin_debugtrap();");
            break;
        }
        break;

    case PPC_INST_VUPKHSB:
    case PPC_INST_VUPKHSB128:
        println("\t_mm_store_si128((__m128i*){}.s16, _mm_cvtepi8_epi16(_mm_unpackhi_epi64(_mm_load_si128((__m128i*){}.s8), _mm_load_si128((__m128i*){}.s8))));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[1]));
        break;

    case PPC_INST_VUPKHSH:
    case PPC_INST_VUPKHSH128:
        println("\t_mm_store_si128((__m128i*){}.s32, _mm_cvtepi16_epi32(_mm_unpackhi_epi64(_mm_load_si128((__m128i*){}.s16), _mm_load_si128((__m128i*){}.s16))));", v(insn.operands[0]), v(insn.operands[1]), v(insn.operands[1]));
        break;

    case PPC_INST_VUPKLSB:
    case PPC_INST_VUPKLSB128:
        println("\t_mm_store_si128((__m128i*){}.s32, _mm_cvtepi8_epi16(_mm_load_si128((__m128i*){}.s16)));", v(insn.operands[0]), v(insn.operands[1]));
        break;

    case PPC_INST_VUPKLSH:
    case PPC_INST_VUPKLSH128:
        println("\t_mm_store_si128((__m128i*){}.s32, _mm_cvtepi16_epi32(_mm_load_si128((__m128i*){}.s16)));", v(insn.operands[0]), v(insn.operands[1]));
        break;

    case PPC_INST_VXOR:
    case PPC_INST_VXOR128:
        print("\t_mm_store_si128((__m128i*){}.u8, ", v(insn.operands[0]));

        if (insn.operands[1] != insn.operands[2])
            println("_mm_xor_si128(_mm_load_si128((__m128i*){}.u8), _mm_load_si128((__m128i*){}.u8)));", v(insn.operands[1]), v(insn.operands[2]));
        else
            println("_mm_setzero_si128());");

        break;

    case PPC_INST_XOR:
        println("\t{}.u64 = {}.u64 ^ {}.u64;", r(insn.operands[0]), r(insn.operands[1]), r(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\t{}.compare<int32_t>({}.s32, 0, {});", cr(0), r(insn.operands[0]), xer());
        break;

    case PPC_INST_XORI:
        println("\t{}.u64 = {}.u64 ^ {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2]);
        break;

    case PPC_INST_XORIS:
        println("\t{}.u64 = {}.u64 ^ {};", r(insn.operands[0]), r(insn.operands[1]), insn.operands[2] << 16);
        break;

    default:
        return false;
    }

#if 1
    if (strchr(insn.opcode->name, '.'))
    {
        int lastLine = out.find_last_of('\n', out.size() - 2);
        if (out.find("cr0", lastLine + 1) == std::string::npos && out.find("cr6", lastLine + 1) == std::string::npos)
            fmt::println("{} at {:X} has RC bit enabled but no comparison was generated", insn.opcode->name, base);
    }
#endif

    if (midAsmHook != config.midAsmHooks.end() && midAsmHook->second.afterInstruction)
        printMidAsmHook();
    
    return true;
}

bool Recompiler::Recompile(const Function& fn)
{
    auto base = fn.base;
    auto end = base + fn.size;
    auto* data = (uint32_t*)image.Find(base);

    static std::unordered_set<size_t> labels;
    labels.clear();

    for (size_t addr = base; addr < end; addr += 4)
    {
        const uint32_t instruction = ByteSwap(*(uint32_t*)((char*)data + addr - base));
        if (!PPC_BL(instruction))
        {
            const size_t op = PPC_OP(instruction);
            if (op == PPC_OP_B)
                labels.emplace(addr + PPC_BI(instruction));
            else if (op == PPC_OP_BC)
                labels.emplace(addr + PPC_BD(instruction));
        }

        auto switchTable = config.switchTables.find(addr);
        if (switchTable != config.switchTables.end())
        {
            for (auto label : switchTable->second.labels)
                labels.emplace(label);
        }

        auto midAsmHook = config.midAsmHooks.find(addr);
        if (midAsmHook != config.midAsmHooks.end())
        {
            if (midAsmHook->second.returnOnFalse || midAsmHook->second.returnOnTrue ||
                midAsmHook->second.jumpAddressOnFalse != NULL || midAsmHook->second.jumpAddressOnTrue != NULL)
            {
                print("extern bool ");
            }
            else
            {
                print("extern void ");
            }

            print("{}(", midAsmHook->second.name);
            for (auto& reg : midAsmHook->second.registers)
            {
                if (out.back() != '(')
                    out += ", ";

                switch (reg[0])
                {
                case 'c':
                    if (reg == "ctr")
                        print("PPCRegister& ctr");
                    else
                        print("PPCCRRegister& {}", reg);
                    break;

                case 'x':
                    print("PPCXERRegister& xer");
                    break;

                case 'r':
                    print("PPCRegister& {}", reg);
                    break;

                case 'f':
                    if (reg == "fpscr")
                        print("PPCFPSCRRegister& fpscr");
                    else
                        print("PPCRegister& {}", reg);
                    break;

                case 'v':
                    print("PPCVRegister& {}", reg);
                    break;
                }
            }

            println(");\n");

            if (midAsmHook->second.jumpAddress != NULL)
                labels.emplace(midAsmHook->second.jumpAddress);       
            if (midAsmHook->second.jumpAddressOnTrue != NULL)
                labels.emplace(midAsmHook->second.jumpAddressOnTrue);    
            if (midAsmHook->second.jumpAddressOnFalse != NULL)
                labels.emplace(midAsmHook->second.jumpAddressOnFalse);
        }
    }

    auto symbol = image.symbols.find(fn.base);
    std::string name;
    if (symbol != image.symbols.end())
    {
        name = symbol->name;
    }
    else
    {
        name = fmt::format("sub_{}", fn.base);
    }

#ifdef XENON_RECOMP_USE_ALIAS
    println("__attribute__((alias(\"__imp__{}\"))) PPC_WEAK_FUNC({});", name, name);
#endif

    println("PPC_FUNC_IMPL(__imp__{}) {{", name);
    println("\tPPC_FUNC_PROLOGUE();");

    auto switchTable = config.switchTables.end();
    bool allRecompiled = true;
    CSRState csrState = CSRState::Unknown;

    // TODO: the printing scheme here is scuffed
    RecompilerLocalVariables localVariables;
    static std::string tempString;
    tempString.clear();
    std::swap(out, tempString);

    ppc_insn insn;
    while (base < end)
    {
        if (labels.find(base) != labels.end())
        {
            println("loc_{:X}:", base);

            // Anyone could jump to this label so we wouldn't know what the CSR state would be.
            csrState = CSRState::Unknown;
        }

        if (switchTable == config.switchTables.end())
            switchTable = config.switchTables.find(base);

        ppc::Disassemble(data, 4, base, insn);

        if (insn.opcode == nullptr)
        {
            println("\t// {}", insn.op_str);
#if 1
            if (*data != 0)
                fmt::println("Unable to decode instruction {:X} at {:X}", *data, base);
#endif
        }
        else
        {
            if (insn.opcode->id == PPC_INST_BCTR && (*(data - 1) == 0x07008038 || *(data - 1) == 0x00000060) && switchTable == config.switchTables.end())
                fmt::println("Found a switch jump table at {:X} with no switch table entry present", base);

            if (!Recompile(fn, base, insn, data, switchTable, localVariables, csrState))
            {
                fmt::println("Unrecognized instruction at 0x{:X}: {}", base, insn.opcode->name);
                allRecompiled = false;
            }
        }

        base += 4;
        ++data;
    }

#if 0
    if (insn.opcode == nullptr || (insn.opcode->id != PPC_INST_B && insn.opcode->id != PPC_INST_BCTR && insn.opcode->id != PPC_INST_BLR))
        fmt::println("Function at {:X} ends prematurely with instruction {} at {:X}", fn.base, insn.opcode != nullptr ? insn.opcode->name : "INVALID", base - 4);
#endif

    println("}}\n");

#ifndef XENON_RECOMP_USE_ALIAS
    println("PPC_WEAK_FUNC({}) {{", name);
    println("\t__imp__{}(ctx, base);", name);
    println("}}\n");
#endif

    std::swap(out, tempString);
    if (localVariables.ctr)
        println("\tPPCRegister ctr{{}};");   
    if (localVariables.xer)
        println("\tPPCXERRegister xer{{}};");
    if (localVariables.reserved)
        println("\tPPCRegister reserved{{}};");

    for (size_t i = 0; i < 8; i++)
    {
        if (localVariables.cr[i])
            println("\tPPCCRRegister cr{}{{}};", i);
    }

    for (size_t i = 0; i < 32; i++)
    {
        if (localVariables.r[i])
            println("\tPPCRegister r{}{{}};", i);
    }

    for (size_t i = 0; i < 32; i++)
    {
        if (localVariables.f[i])
            println("\tPPCRegister f{}{{}};", i);
    }

    for (size_t i = 0; i < 128; i++)
    {
        if (localVariables.v[i])
            println("\tPPCVRegister v{}{{}};", i);
    }

    if (localVariables.env)
        println("\tPPCContext env{{}};"); 
    
    if (localVariables.temp)
        println("\tPPCRegister temp{{}};"); 
    
    if (localVariables.vTemp)
        println("\tPPCVRegister vTemp{{}};");

    if (localVariables.ea)
        println("\tuint32_t ea{{}};");

    out += tempString;

    return allRecompiled;
}

void Recompiler::Recompile(const std::filesystem::path& headerFilePath)
{
    out.reserve(10 * 1024 * 1024);

    {
        println("#pragma once");

        println("#ifndef PPC_CONFIG_H_INCLUDED");
        println("#define PPC_CONFIG_H_INCLUDED\n");

        if (config.skipLr)
            println("#define PPC_CONFIG_SKIP_LR");      
        if (config.ctrAsLocalVariable)
            println("#define PPC_CONFIG_CTR_AS_LOCAL");      
        if (config.xerAsLocalVariable)
            println("#define PPC_CONFIG_XER_AS_LOCAL");      
        if (config.reservedRegisterAsLocalVariable)
            println("#define PPC_CONFIG_RESERVED_AS_LOCAL");      
        if (config.skipMsr)
            println("#define PPC_CONFIG_SKIP_MSR");      
        if (config.crRegistersAsLocalVariables)
            println("#define PPC_CONFIG_CR_AS_LOCAL");      
        if (config.nonArgumentRegistersAsLocalVariables)
            println("#define PPC_CONFIG_NON_ARGUMENT_AS_LOCAL");   
        if (config.nonVolatileRegistersAsLocalVariables)
            println("#define PPC_CONFIG_NON_VOLATILE_AS_LOCAL");

        println("");

        println("#define PPC_IMAGE_BASE 0x{:X}ull", image.base);
        println("#define PPC_IMAGE_SIZE 0x{:X}ull", image.size);
        
        // Extract the address of the minimum code segment to store the function table at.
        size_t codeMin = ~0;
        size_t codeMax = 0;

        for (auto& section : image.sections)
        {
            if ((section.flags & SectionFlags_Code) != 0)
            {
                if (section.base < codeMin)
                    codeMin = section.base;

                if ((section.base + section.size) > codeMax)
                    codeMax = (section.base + section.size);
            }
        }

        println("#define PPC_CODE_BASE 0x{:X}ull", codeMin);
        println("#define PPC_CODE_SIZE 0x{:X}ull", codeMax - codeMin);

        println("");

        println("#ifdef PPC_INCLUDE_DETAIL");
        println("#include \"ppc_detail.h\"");
        println("#endif");

        println("\n#endif");

        SaveCurrentOutData("ppc_config.h");
    }

    {
        println("#pragma once");

        println("#include \"ppc_config.h\"\n");
        
        std::ifstream stream(headerFilePath);
        if (stream.good())
        {
            std::stringstream ss;
            ss << stream.rdbuf();
            out += ss.str();
        }

        SaveCurrentOutData("ppc_context.h");
    }

    {
        println("#pragma once\n");
        println("#include \"ppc_config.h\"");
        println("#include \"ppc_context.h\"\n");

        for (auto& symbol : image.symbols)
            println("PPC_EXTERN_FUNC({});", symbol.name);

        SaveCurrentOutData("ppc_recomp_shared.h");
    }

    {
        println("#include \"ppc_recomp_shared.h\"\n");

        println("PPCFuncMapping PPCFuncMappings[] = {{");
        for (auto& symbol : image.symbols)
            println("\t{{ 0x{:X}, {} }},", symbol.address, symbol.name);

        println("\t{{ 0, nullptr }}");
        println("}};");

        SaveCurrentOutData("ppc_func_mapping.cpp");
    }

    for (size_t i = 0; i < functions.size(); i++)
    {
        if ((i % 256) == 0)
        {
            SaveCurrentOutData();
            println("#include \"ppc_recomp_shared.h\"\n");
        }

        if ((i % 2048) == 0 || (i == (functions.size() - 1)))
            fmt::println("Recompiling functions... {}%", static_cast<float>(i + 1) / functions.size() * 100.0f);

        Recompile(functions[i]);
    }

    SaveCurrentOutData();
}

void Recompiler::SaveCurrentOutData(const std::string_view& name)
{
    if (!out.empty())
    {
        std::string cppName;

        if (name.empty())
        {
            cppName = fmt::format("ppc_recomp.{}.cpp", cppFileIndex);
            ++cppFileIndex;
        }

        bool shouldWrite = true;

        // Check if an identical file already exists first to not trigger recompilation
        std::string directoryPath = config.directoryPath;
        if (!directoryPath.empty())
            directoryPath += "/";

        std::string filePath = fmt::format("{}{}/{}", directoryPath, config.outDirectoryPath, name.empty() ? cppName : name);
        FILE* f = fopen(filePath.c_str(), "rb");
        if (f)
        {
            static std::vector<uint8_t> temp;

            fseek(f, 0, SEEK_END);
            long fileSize = ftell(f);
            if (fileSize == out.size())
            {
                fseek(f, 0, SEEK_SET);
                temp.resize(fileSize);
                fread(temp.data(), 1, fileSize, f);

                shouldWrite = !XXH128_isEqual(XXH3_128bits(temp.data(), temp.size()), XXH3_128bits(out.data(), out.size()));
            }
            fclose(f);
        }

        if (shouldWrite)
        {
            f = fopen(filePath.c_str(), "wb");
            fwrite(out.data(), 1, out.size(), f);
            fclose(f);
        }

        out.clear();
    }
}
