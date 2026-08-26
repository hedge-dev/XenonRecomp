#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#include "pch.h"
#include "test_recompiler.h"
#include <csignal>
#include <exception>

static void OnAbort(int)
{
    fmt::println(stderr, "[FATAL] SIGABRT received");
    fflush(stderr);
}

int main(int argc, char* argv[])
{
    #ifdef _DEBUG
        _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_DEBUG | _CRTDBG_MODE_FILE);
        _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    #endif
    std::signal(SIGABRT, OnAbort);

    try
    {
#ifndef XENON_RECOMP_CONFIG_FILE_PATH
        if (argc < 3)
        {
            fmt::println(stderr,
                "Usage: XenonRecomp [input TOML file path] [PPC context header file path]");
            return EXIT_SUCCESS;
        }
#endif

        const char* path =
#ifdef XENON_RECOMP_CONFIG_FILE_PATH
            XENON_RECOMP_CONFIG_FILE_PATH
#else
            argv[1]
#endif
            ;

        fmt::println(stderr, "[1/3] Starting XenonRecomp");
        fmt::println(stderr, "      Config: {}", path);

        if (std::filesystem::is_regular_file(path))
        {
            Recompiler recompiler;

            fmt::println(stderr, "[1/3] Loading configuration and XEX...");
            if (!recompiler.LoadConfig(path))
                return -1;

            fmt::println(stderr, "[1/3] LoadConfig complete");

            fmt::println(stderr, "[2/3] Analysing executable...");
            recompiler.Analyse();
            fmt::println(stderr, "[2/3] Analyse complete: {} functions", recompiler.functions.size());

            auto entry = recompiler.image.symbols.find(recompiler.image.entry_point);
            if (entry != recompiler.image.symbols.end())
            {
                entry->name = "_xstart";
            }

            const char* headerFilePath =
#ifdef XENON_RECOMP_HEADER_FILE_PATH
                XENON_RECOMP_HEADER_FILE_PATH
#else
                argv[2]
#endif
                ;

            fmt::println(stderr, "[3/3] Recompiling functions...");
            recompiler.Recompile(headerFilePath);
            fmt::println(stderr, "[3/3] Recompilation complete");
        }
        else
        {
            TestRecompiler::RecompileTests(path, argv[2]);
        }

        return EXIT_SUCCESS;
    }
    catch (const std::exception& e)
    {
        fmt::println(stderr, "[FATAL] Unhandled exception: {}", e.what());
        return EXIT_FAILURE;
    }
    catch (...)
    {
        fmt::println(stderr, "[FATAL] Unhandled non-standard exception");
        return EXIT_FAILURE;
    }
}