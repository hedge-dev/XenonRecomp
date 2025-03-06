#pragma once
#include "recompiler.h"

struct TestRecompiler : Recompiler
{
    void Analyse(const std::string_view& testName);
    void Reset();

    static void RecompileTests(const char* srcDirectoryPath, const char* dstDirectoryPath);
};
