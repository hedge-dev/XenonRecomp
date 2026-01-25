#pragma once

#include "pch.h"
#include "recompiler_config.h"

struct RecompilerLocalVariables
{
    bool ctr{};
    bool xer{};
    bool reserved{};
    bool cr[8]{};
    bool r[32]{};
    bool f[32]{};
    bool v[128]{};
    bool env{};
    bool temp{};
    bool vTemp{};
    bool ea{};
};

enum class CSRState
{
    Unknown,
    FPU,
    VMX
};

struct RecompileArgs
{
    const Function& fn;
    uint32_t base;
    const ppc_insn& insn;
    const uint32_t* data;
    std::unordered_map<uint32_t, RecompilerSwitchTable>::iterator& switchTable;
    RecompilerLocalVariables& localVariables;
    CSRState& csrState;
};

struct Recompiler
{
    // Enforce In-order Execution of I/O constant for quick comparison
    static constexpr uint32_t c_eieio = 0xAC06007C;
    Image image;
    std::vector<Function> functions;
    std::string out;
    size_t cppFileIndex = 0;
    RecompilerConfig config;

    bool LoadConfig(const std::string_view& configFilePath);

    template<class... Args>
    void print(fmt::format_string<Args...> fmt, Args&&... args)
    {
        fmt::vformat_to(std::back_inserter(out), fmt.get(), fmt::make_format_args(args...));
    }

    template<class... Args>
    void println(fmt::format_string<Args...> fmt, Args&&... args)
    {
        fmt::vformat_to(std::back_inserter(out), fmt.get(), fmt::make_format_args(args...));
        out += '\n';
    }

    void Analyse();

    bool Recompile(const RecompileArgs& args);

    bool Recompile(const Function& fn);

    void Recompile(const std::filesystem::path& headerFilePath);

    void SaveCurrentOutData(const std::string_view& name = std::string_view());
};
