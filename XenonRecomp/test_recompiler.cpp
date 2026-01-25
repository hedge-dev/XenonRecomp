#include "test_recompiler.h"

void TestRecompiler::Analyse(const std::string_view& testName)
{
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
            if (*(uint32_t*)data == 0)
            {
                data += 4;
                base += 4;
                continue;
            }

            auto& fn = functions.emplace_back(Function::Analyze(data, dataEnd - data, base));
            image.symbols.emplace(fmt::format("{}_{:X}", testName, fn.base), fn.base, fn.size, Symbol_Function);
            
            base += fn.size;
            data += fn.size;
        }
    }

    std::sort(functions.begin(), functions.end(), [](auto& lhs, auto& rhs) { return lhs.base < rhs.base; });
}

void TestRecompiler::RecompileTests(const char* srcDirectoryPath, const char* dstDirectoryPath)
{
    std::map<std::string, std::unordered_set<size_t>> functions;

    for (auto& file : std::filesystem::directory_iterator(srcDirectoryPath))
    {
        if (file.path().extension() == ".o")
        {
            const auto exeFile = LoadFile(file.path().string().c_str());

            TestRecompiler recompiler;
            recompiler.config.outDirectoryPath = dstDirectoryPath;
            recompiler.image = Image::ParseImage(exeFile.data(), exeFile.size());

            auto stem = file.path().stem().string();
            recompiler.Analyse(stem);

            recompiler.println("#define PPC_CONFIG_H_INCLUDED");
            recompiler.println("#include <ppc_context.h>\n");
            recompiler.println("#define __builtin_debugtrap()\n");

            for (auto& fn : recompiler.functions)
            {
                if (recompiler.Recompile(fn))
                {
                    functions[stem].emplace(fn.base);
                }
                else
                {
                    fmt::println("Function {:X} in {} has unimplemented instructions", fn.base, stem);
                }
            }
            stem += ".cpp";
            recompiler.SaveCurrentOutData(stem);
        }
    }

    std::unordered_map<std::string, std::string> symbols;

    for (auto& [fn, addr] : functions)
    {
        std::ifstream in(fmt::format("{}/{}.dis", srcDirectoryPath, fn));
        if (in.is_open())
        {
            std::string line;
            while (std::getline(in, line))
            {
                int spaceIndex = line.find(' ');
                int bracketIndex = line.find('>');
                if (spaceIndex != std::string::npos && bracketIndex != std::string::npos)
                {
                    size_t address = ~0;
                    std::from_chars(&line[0], &line[spaceIndex], address, 16);
                    address &= 0xFFFFF;
                    if (addr.find(address) != addr.end())
                        symbols.emplace(line.substr(spaceIndex + 2, bracketIndex - spaceIndex - 2), fmt::format("{}_{:X}", fn, address));
                }
            }
        }
        else
        {
            fmt::println("Unable to locate disassembly file for {}", fn);
        }
    }

    FILE* file = fopen(fmt::format("{}/main.cpp", dstDirectoryPath).c_str(), "w");
    std::string main;

    fmt::println(file, "#define PPC_CONFIG_H_INCLUDED");
    fmt::println(file, "#include <ppc_context.h>");
    fmt::println(file, "#ifdef _WIN32");
    fmt::println(file, "#include <Windows.h>");
    fmt::println(file, "#else");
    fmt::println(file, "#include <sys/mman.h>");
    fmt::println(file, "#endif");
    fmt::println(file, "#include <fmt/core.h>\n");
    fmt::println(file, "#define PPC_CHECK_VALUE_U(f, lhs, rhs) if (lhs != rhs) fmt::println(#f \" \" #lhs \" EXPECTED \" #rhs \" ACTUAL {{:X}}\", lhs)\n");
    fmt::println(file, "#define PPC_CHECK_VALUE_F(f, lhs, rhs) if (lhs != rhs) fmt::println(#f \" \" #lhs \" EXPECTED \" #rhs \" ACTUAL {{}}\", lhs)\n");

    for (auto& [fn, addr] : functions)
    {
        std::ifstream in(fmt::format("{}/../{}.s", srcDirectoryPath, fn));
        if (in.is_open())
        {
            std::string str;
            auto getline = [&]()
                {
                    if (std::getline(in, str))
                    {
                        str.erase(str.find_last_not_of(' ') + 1);
                        str.erase(0, str.find_first_not_of(' '));
                        return true;
                    }
                    return false;
                };

            while (getline())
            {
                if (!str.empty() && str[0] != '#')
                {
                    int colonIndex = str.find(':');
                    if (colonIndex != std::string::npos)
                    {
                        auto name = str.substr(0, colonIndex);
                        auto symbol = symbols.find(name);
                        if (symbol != symbols.end())
                        {
                            fmt::println(file, "PPC_FUNC({});\n", symbol->second);
                            fmt::println(file, "void {}(uint8_t* base) {{", name);
                            fmt::println(file, "\tPPCContext ctx{{}};");
                            fmt::println(file, "\tctx.fpscr.loadFromHost();");

                            while (getline() && !str.empty() && str[0] == '#')
                            {
                                if (str.size() > 1 && str[1] == '_')
                                {
                                    int registerInIndex = str.find("REGISTER_IN");
                                    if (registerInIndex != std::string::npos)
                                    {
                                        int spaceIndex = str.find(' ', registerInIndex);
                                        int secondSpaceIndex = str.find(' ', spaceIndex + 1);
                                        auto reg = str.substr(spaceIndex + 1, secondSpaceIndex - spaceIndex - 1);
                                        if (reg[0] == 'v')
                                        {
                                            int openingBracketIndex = str.find('[', secondSpaceIndex + 1);
                                            int commaIndex0 = str.find(',', openingBracketIndex + 1);
                                            int commaIndex1 = str.find(',', commaIndex0 + 1);
                                            int commaIndex2 = str.find(',', commaIndex1 + 1);
                                            int closingBracketIndex = str.find(']', commaIndex2 + 1);

                                            fmt::println(file, "\tctx.{}.u32[3] = 0x{};", reg, str.substr(openingBracketIndex + 1, commaIndex0 - openingBracketIndex - 1));
                                            fmt::println(file, "\tctx.{}.u32[2] = 0x{};", reg, str.substr(commaIndex0 + 2, commaIndex1 - commaIndex0 - 2));
                                            fmt::println(file, "\tctx.{}.u32[1] = 0x{};", reg, str.substr(commaIndex1 + 2, commaIndex2 - commaIndex1 - 2));
                                            fmt::println(file, "\tctx.{}.u32[0] = 0x{};", reg, str.substr(commaIndex2 + 2, closingBracketIndex - commaIndex2 - 2));
                                        }
                                        else
                                        {
                                            fmt::println(file, "\tctx.{}.{}64 = {};",
                                                reg,
                                                str.find('.', secondSpaceIndex) != std::string::npos ? 'f' : 'u',
                                                str.substr(secondSpaceIndex + 1));
                                        }
                                    }
                                    else
                                    {
                                        int memoryInIndex = str.find("MEMORY_IN");
                                        if (memoryInIndex != std::string::npos)
                                        {
                                            int spaceIndex = str.find(' ', memoryInIndex);
                                            int secondSpaceIndex = str.find(' ', spaceIndex + 1);
                                            auto address = str.substr(spaceIndex + 1, secondSpaceIndex - spaceIndex - 1);
                                            for (size_t i = secondSpaceIndex + 1, j = 0; i < str.size(); i++)
                                            {
                                                if (str[i] != ' ')
                                                {
                                                    fmt::println(file, "\tbase[0x{} + 0x{:X}] = 0x{}{};", address, j, str[i], str[i + 1]);
                                                    ++i; // the loop adds another
                                                    ++j;
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            while (getline() && (str.empty() || str[0] != '#'))
                                ;

                            fmt::println(file, "\t{}(ctx, base);", symbol->second);

                            do
                            {
                                if (str.size() > 1 && str[1] == '_')
                                {
                                    int registerOutIndex = str.find("REGISTER_OUT");
                                    if (registerOutIndex != std::string::npos)
                                    {
                                        int spaceIndex = str.find(' ', registerOutIndex);
                                        int secondSpaceIndex = str.find(' ', spaceIndex + 1);
                                        auto reg = str.substr(spaceIndex + 1, secondSpaceIndex - spaceIndex - 1);
                                        if (reg[0] == 'c')
                                        {
                                            // CR register: parse 4-bit value (lt, gt, eq, so)
                                            auto value = str.substr(secondSpaceIndex + 1);
                                            fmt::println(file, "\tPPC_CHECK_VALUE_U({}, ctx.{}.lt, ({}) >> 3 & 1);", name, reg, value);
                                            fmt::println(file, "\tPPC_CHECK_VALUE_U({}, ctx.{}.gt, ({}) >> 2 & 1);", name, reg, value);
                                            fmt::println(file, "\tPPC_CHECK_VALUE_U({}, ctx.{}.eq, ({}) >> 1 & 1);", name, reg, value);
                                            fmt::println(file, "\tPPC_CHECK_VALUE_U({}, ctx.{}.so, ({}) & 1);", name, reg, value);
                                            continue;
                                        }
                                        if (reg[0] == 'v')
                                        {
                                            int openingBracketIndex = str.find('[', secondSpaceIndex + 1);
                                            int commaIndex0 = str.find(',', openingBracketIndex + 1);
                                            int commaIndex1 = str.find(',', commaIndex0 + 1);
                                            int commaIndex2 = str.find(',', commaIndex1 + 1);
                                            int closingBracketIndex = str.find(']', commaIndex2 + 1);

                                            fmt::println(file, "\tPPC_CHECK_VALUE_U({}, ctx.{}.u32[3], 0x{});", name, reg, str.substr(openingBracketIndex + 1, commaIndex0 - openingBracketIndex - 1));
                                            fmt::println(file, "\tPPC_CHECK_VALUE_U({}, ctx.{}.u32[2], 0x{});", name, reg, str.substr(commaIndex0 + 2, commaIndex1 - commaIndex0 - 2));
                                            fmt::println(file, "\tPPC_CHECK_VALUE_U({}, ctx.{}.u32[1], 0x{});", name, reg, str.substr(commaIndex1 + 2, commaIndex2 - commaIndex1 - 2));
                                            fmt::println(file, "\tPPC_CHECK_VALUE_U({}, ctx.{}.u32[0], 0x{});", name, reg, str.substr(commaIndex2 + 2, closingBracketIndex - commaIndex2 - 2));
                                        }
                                        else
                                        {
                                            fmt::println(file, "\tPPC_CHECK_VALUE_{}({}, ctx.{}.{}64, {});",
                                                str.find('.', secondSpaceIndex) != std::string::npos ? 'F' : 'U',
                                                name,
                                                reg,
                                                str.find('.', secondSpaceIndex) != std::string::npos ? 'f' : 'u',
                                                str.substr(secondSpaceIndex + 1));
                                        }
                                    }
                                    else
                                    {
                                        int memoryOutIndex = str.find("MEMORY_OUT");
                                        if (memoryOutIndex != std::string::npos)
                                        {
                                            int spaceIndex = str.find(' ', memoryOutIndex);
                                            int secondSpaceIndex = str.find(' ', spaceIndex + 1);
                                            auto address = str.substr(spaceIndex + 1, secondSpaceIndex - spaceIndex - 1);
                                            for (size_t i = secondSpaceIndex + 1, j = 0; i < str.size(); i++)
                                            {
                                                if (str[i] != ' ')
                                                {
                                                    fmt::println(file, "\tPPC_CHECK_VALUE_U({}, base[0x{} + 0x{:X}], 0x{}{});", name, address, j, str[i], str[i + 1]);
                                                    ++i; // the loop adds another
                                                    ++j;
                                                }
                                            }
                                        }
                                    }
                                }
                            } while (getline() && !str.empty() && str[0] == '#');

                            fmt::println(file, "}}\n");

                            fmt::format_to(std::back_inserter(main), "\t{}(base);\n", name);
                        }
                        else
                        {
                            fmt::println("Found no symbol for {}", name);
                        }
                    }
                }
            }
        }
        else
        {
            fmt::println("Unable to locate source file for {}", fn);
        }
    }

    fmt::println(file, "int main() {{");
    fmt::println(file, "#ifdef _WIN32");
    fmt::println(file, "\tuint8_t* base = reinterpret_cast<uint8_t*>(VirtualAlloc(nullptr, 0x100000000ull, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));");
    fmt::println(file, "#else");
    fmt::println(file, "\tuint8_t* base = reinterpret_cast<uint8_t*>(mmap(NULL, 0x100000000ull, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0));");
    fmt::println(file, "#endif");
    fwrite(main.data(), 1, main.size(), file);
    fmt::println(file, "\treturn 0;");
    fmt::println(file, "}}");

    fclose(file);
}
