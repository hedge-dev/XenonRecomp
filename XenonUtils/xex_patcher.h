// Referenced from: https://github.com/xenia-canary/xenia-canary/blob/canary_experimental/src/xenia/cpu/xex_module.cc

/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2023 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#pragma once

#include <cstdint>
#include <filesystem>
#include <span>
#include <vector>

extern int lzxDecompress(const void* lzxData, size_t lzxLength, void* dst, size_t dstLength, uint32_t windowSize, void* windowData, size_t windowDataLength);

struct XexPatcher
{
    enum class Result {
        Success,
        FileOpenFailed,
        FileWriteFailed,
        XexFileUnsupported,
        XexFileInvalid,
        PatchFileInvalid,
        PatchIncompatible,
        PatchFailed,
        PatchUnsupported
    };

    static Result apply(const uint8_t* xexBytes, size_t xexBytesSize, const uint8_t* patchBytes, size_t patchBytesSize, std::vector<uint8_t> &outBytes, bool skipData);
    static Result apply(const std::filesystem::path &baseXexPath, const std::filesystem::path &patchXexPath, const std::filesystem::path &newXexPath);
};
