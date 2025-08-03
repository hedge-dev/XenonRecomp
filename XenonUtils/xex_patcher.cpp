// Referenced from: https://github.com/xenia-canary/xenia-canary/blob/canary_experimental/src/xenia/cpu/xex_module.cc

/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2023 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include "xex_patcher.h"
#include "xex.h"

#include <bit>
#include <cassert>
#include <climits>
#include <fstream>

#include <aes.hpp>
#include <lzx.h>
#include <mspack.h>
#include <TinySHA1.hpp>

#include "memory_mapped_file.h"

struct mspack_memory_file
{
    mspack_system sys;
    void *buffer;
    size_t bufferSize;
    size_t offset;
};

static mspack_memory_file *mspack_memory_open(mspack_system *sys, void *buffer, size_t bufferSize)
{
    assert(bufferSize < INT_MAX);

    if (bufferSize >= INT_MAX)
    {
        return nullptr;
    }

    mspack_memory_file *memoryFile = (mspack_memory_file *)(std::calloc(1, sizeof(mspack_memory_file)));
    if (memoryFile == nullptr)
    {
        return memoryFile;
    }

    memoryFile->buffer = buffer;
    memoryFile->bufferSize = bufferSize;
    memoryFile->offset = 0;
    return memoryFile;
}

static void mspack_memory_close(mspack_memory_file *file)
{
    std::free(file);
}

static int mspack_memory_read(mspack_file *file, void *buffer, int chars)
{
    mspack_memory_file *memoryFile = (mspack_memory_file *)(file);
    const size_t remaining = memoryFile->bufferSize - memoryFile->offset;
    const size_t total = std::min(size_t(chars), remaining);
    std::memcpy(buffer, (uint8_t *)(memoryFile->buffer) + memoryFile->offset, total);
    memoryFile->offset += total;
    return int(total);
}

static int mspack_memory_write(mspack_file *file, void *buffer, int chars)
{
    mspack_memory_file *memoryFile = (mspack_memory_file *)(file);
    const size_t remaining = memoryFile->bufferSize - memoryFile->offset;
    const size_t total = std::min(size_t(chars), remaining);
    std::memcpy((uint8_t *)(memoryFile->buffer) + memoryFile->offset, buffer, total);
    memoryFile->offset += total;
    return int(total);
}

static void *mspack_memory_alloc(mspack_system *sys, size_t chars)
{
    return std::calloc(chars, 1);
}

static void mspack_memory_free(void *ptr)
{
    std::free(ptr);
}

static void mspack_memory_copy(void *src, void *dest, size_t chars)
{
    std::memcpy(dest, src, chars);
}

static mspack_system *mspack_memory_sys_create()
{
    auto sys = (mspack_system *)(std::calloc(1, sizeof(mspack_system)));
    if (!sys)
    {
        return nullptr;
    }

    sys->read = mspack_memory_read;
    sys->write = mspack_memory_write;
    sys->alloc = mspack_memory_alloc;
    sys->free = mspack_memory_free;
    sys->copy = mspack_memory_copy;
    return sys;
}

static void mspack_memory_sys_destroy(struct mspack_system *sys)
{
    free(sys);
}

#if defined(_WIN32)
inline bool bitScanForward(uint32_t v, uint32_t *outFirstSetIndex)
{
    return _BitScanForward((unsigned long *)(outFirstSetIndex), v) != 0;
}

inline bool bitScanForward(uint64_t v, uint32_t *outFirstSetIndex)
{
    return _BitScanForward64((unsigned long *)(outFirstSetIndex), v) != 0;
}

#else
inline bool bitScanForward(uint32_t v, uint32_t *outFirstSetIndex)
{
    int i = ffs(v);
    *outFirstSetIndex = i - 1;
    return i != 0;
}

inline bool bitScanForward(uint64_t v, uint32_t *outFirstSetIndex)
{
    int i = __builtin_ffsll(v);
    *outFirstSetIndex = i - 1;
    return i != 0;
}
#endif

int lzxDecompress(const void *lzxData, size_t lzxLength, void *dst, size_t dstLength, uint32_t windowSize, void *windowData, size_t windowDataLength)
{
    int resultCode = 1;
    uint32_t windowBits;
    if (!bitScanForward(windowSize, &windowBits)) {
        return resultCode;
    }

    mspack_system *sys = mspack_memory_sys_create();
    mspack_memory_file *lzxSrc = mspack_memory_open(sys, (void *)(lzxData), lzxLength);
    mspack_memory_file *lzxDst = mspack_memory_open(sys, dst, dstLength);
    lzxd_stream *lzxd = lzxd_init(sys, (mspack_file *)(lzxSrc), (mspack_file *)(lzxDst), windowBits, 0, 0x8000, dstLength, 0);
    if (lzxd != nullptr) {
        if (windowData != nullptr) {
            size_t paddingLength = windowSize - windowDataLength;
            std::memset(&lzxd->window[0], 0, paddingLength);
            std::memcpy(&lzxd->window[paddingLength], windowData, windowDataLength);
            lzxd->ref_data_size = windowSize;
        }

        resultCode = lzxd_decompress(lzxd, dstLength);
        lzxd_free(lzxd);
    }

    if (lzxSrc) {
        mspack_memory_close(lzxSrc);
    }

    if (lzxDst) {
        mspack_memory_close(lzxDst);
    }

    if (sys) {
        mspack_memory_sys_destroy(sys);
    }

    return resultCode;
}

static int lzxDeltaApplyPatch(const Xex2DeltaPatch *deltaPatch, uint32_t patchLength, uint32_t windowSize, uint8_t *dstData)
{
    const void *patchEnd = (const uint8_t *)(deltaPatch) + patchLength;
    const Xex2DeltaPatch *curPatch = deltaPatch;
    while (patchEnd > curPatch)
    {
        int patchSize = -4; 
        if (curPatch->compressedLength == 0 && curPatch->uncompressedLength == 0 && curPatch->newAddress == 0 && curPatch->oldAddress == 0)
        {
            // End of patch.
            break;
        }

        switch (curPatch->compressedLength)
        {
        case 0:
            // Set the data to zeroes.
            std::memset(&dstData[curPatch->newAddress], 0, curPatch->uncompressedLength);
            break;
        case 1:
            // Move the data.
            std::memcpy(&dstData[curPatch->newAddress], &dstData[curPatch->oldAddress], curPatch->uncompressedLength);
            break;
        default:
            // Decompress the data into the destination.
            patchSize = curPatch->compressedLength - 4;
            int result = lzxDecompress(curPatch->patchData, curPatch->compressedLength, &dstData[curPatch->newAddress], curPatch->uncompressedLength, windowSize, &dstData[curPatch->oldAddress], curPatch->uncompressedLength);
            if (result != 0)
            {
                return result;
            }

            break;
        }

        curPatch++;
        curPatch = (const Xex2DeltaPatch *)((const uint8_t *)(curPatch) + patchSize);
    }

    return 0;
}

XexPatcher::Result XexPatcher::apply(const uint8_t* xexBytes, size_t xexBytesSize, const uint8_t* patchBytes, size_t patchBytesSize, std::vector<uint8_t> &outBytes, bool skipData)
{
    // Validate headers.
    static const char Xex2Magic[] = "XEX2";
    const Xex2Header *xexHeader = (const Xex2Header *)(xexBytes);
    if (memcmp(xexBytes, Xex2Magic, 4) != 0)
    {
        return Result::XexFileInvalid;
    }

    const Xex2Header *patchHeader = (const Xex2Header *)(patchBytes);
    if (memcmp(patchBytes, Xex2Magic, 4) != 0)
    {
        return Result::PatchFileInvalid;
    }

    if ((patchHeader->moduleFlags & (XEX_MODULE_MODULE_PATCH | XEX_MODULE_PATCH_DELTA | XEX_MODULE_PATCH_FULL)) == 0)
    {
        return Result::PatchFileInvalid;
    }

    // Validate patch.
    const Xex2OptDeltaPatchDescriptor *patchDescriptor = (const Xex2OptDeltaPatchDescriptor *)(getOptHeaderPtr(patchBytes, XEX_HEADER_DELTA_PATCH_DESCRIPTOR));
    if (patchDescriptor == nullptr)
    {
        return Result::PatchFileInvalid;
    }
    
    const Xex2OptFileFormatInfo *patchFileFormatInfo = (const Xex2OptFileFormatInfo *)(getOptHeaderPtr(patchBytes, XEX_HEADER_FILE_FORMAT_INFO));
    if (patchFileFormatInfo == nullptr)
    {
        return Result::PatchFileInvalid;
    }

    if (patchFileFormatInfo->compressionType != XEX_COMPRESSION_DELTA)
    {
        return Result::PatchFileInvalid;
    }

    if (patchDescriptor->deltaHeadersSourceOffset > xexHeader->headerSize)
    {
        return Result::PatchIncompatible;
    }

    if (patchDescriptor->deltaHeadersSourceSize > (xexHeader->headerSize - patchDescriptor->deltaHeadersSourceOffset))
    {
        return Result::PatchIncompatible;
    }

    if (patchDescriptor->deltaHeadersTargetOffset > patchDescriptor->sizeOfTargetHeaders)
    {
        return Result::PatchIncompatible;
    }

    uint32_t deltaTargetSize = patchDescriptor->sizeOfTargetHeaders - patchDescriptor->deltaHeadersTargetOffset;
    if (patchDescriptor->deltaHeadersSourceSize > deltaTargetSize)
    {
        return Result::PatchIncompatible;
    }

    // Apply patch.
    uint32_t headerTargetSize = patchDescriptor->sizeOfTargetHeaders;
    if (headerTargetSize == 0)
    {
        headerTargetSize = patchDescriptor->deltaHeadersTargetOffset + patchDescriptor->deltaHeadersSourceSize;
    }

    // Create the bytes for the new XEX header. Copy over the existing data.
    uint32_t newXexHeaderSize = std::max(headerTargetSize, xexHeader->headerSize.get());
    outBytes.resize(newXexHeaderSize);
    memset(outBytes.data(), 0, newXexHeaderSize);
    memcpy(outBytes.data(), xexBytes, headerTargetSize);

    Xex2Header *newXexHeader = (Xex2Header *)(outBytes.data());
    if (patchDescriptor->deltaHeadersSourceOffset > 0)
    {
        memcpy(&outBytes[patchDescriptor->deltaHeadersTargetOffset], &outBytes[patchDescriptor->deltaHeadersSourceOffset], patchDescriptor->deltaHeadersSourceSize);
    }

    int resultCode = lzxDeltaApplyPatch(&patchDescriptor->info, patchDescriptor->size, ((const Xex2FileNormalCompressionInfo*)(patchFileFormatInfo + 1))->windowSize, outBytes.data());
    if (resultCode != 0)
    {
        return Result::PatchFailed;
    }

    // Make the header the specified size by the patch.
    outBytes.resize(headerTargetSize);
    newXexHeader = (Xex2Header *)(outBytes.data());

    // Copy the rest of the data.
    const Xex2SecurityInfo *newSecurityInfo = (const Xex2SecurityInfo *)(&outBytes[newXexHeader->securityOffset]);
    outBytes.resize(outBytes.size() + newSecurityInfo->imageSize);
    memset(&outBytes[headerTargetSize], 0, outBytes.size() - headerTargetSize);
    memcpy(&outBytes[headerTargetSize], &xexBytes[xexHeader->headerSize], xexBytesSize - xexHeader->headerSize);
    newXexHeader = (Xex2Header *)(outBytes.data());
    newSecurityInfo = (const Xex2SecurityInfo *)(&outBytes[newXexHeader->securityOffset]);
    
    // Decrypt the keys and validate that the patch is compatible with the base file.
    constexpr uint32_t KeySize = 16;
    const Xex2SecurityInfo *originalSecurityInfo = (const Xex2SecurityInfo *)(&xexBytes[xexHeader->securityOffset]);
    const Xex2SecurityInfo *patchSecurityInfo = (const Xex2SecurityInfo *)(&patchBytes[patchHeader->securityOffset]);
    uint8_t decryptedOriginalKey[KeySize];
    uint8_t decryptedNewKey[KeySize];
    uint8_t decryptedPatchKey[KeySize];
    uint8_t decrpytedImageKeySource[KeySize];
    memcpy(decryptedOriginalKey, originalSecurityInfo->aesKey, KeySize);
    memcpy(decryptedNewKey, newSecurityInfo->aesKey, KeySize);
    memcpy(decryptedPatchKey, patchSecurityInfo->aesKey, KeySize);
    memcpy(decrpytedImageKeySource, patchDescriptor->imageKeySource, KeySize);

    AES_ctx aesContext;
    AES_init_ctx_iv(&aesContext, Xex2RetailKey, AESBlankIV);
    AES_CBC_decrypt_buffer(&aesContext, decryptedOriginalKey, KeySize);

    AES_ctx_set_iv(&aesContext, AESBlankIV);
    AES_CBC_decrypt_buffer(&aesContext, decryptedNewKey, KeySize);

    AES_init_ctx_iv(&aesContext, decryptedNewKey, AESBlankIV);
    AES_CBC_decrypt_buffer(&aesContext, decryptedPatchKey, KeySize);

    AES_ctx_set_iv(&aesContext, AESBlankIV);
    AES_CBC_decrypt_buffer(&aesContext, decrpytedImageKeySource, KeySize);

    // Validate the patch's key matches the one from the original XEX.
    if (memcmp(decrpytedImageKeySource, decryptedOriginalKey, KeySize) != 0)
    {
        return Result::PatchIncompatible;
    }

    // Don't process the rest of the patch.
    if (skipData)
    {
        return Result::Success;
    }
    
    // Decrypt base XEX if necessary.
    const Xex2OptFileFormatInfo *fileFormatInfo = (const Xex2OptFileFormatInfo *)(getOptHeaderPtr(xexBytes, XEX_HEADER_FILE_FORMAT_INFO));
    if (fileFormatInfo == nullptr)
    {
        return Result::XexFileInvalid;
    }

    if (fileFormatInfo->encryptionType == XEX_ENCRYPTION_NORMAL)
    {
        AES_init_ctx_iv(&aesContext, decryptedOriginalKey, AESBlankIV);
        AES_CBC_decrypt_buffer(&aesContext, &outBytes[headerTargetSize], xexBytesSize - xexHeader->headerSize);
    }
    else if (fileFormatInfo->encryptionType != XEX_ENCRYPTION_NONE)
    {
        return Result::XexFileInvalid;
    }

    // Decompress base XEX if necessary.
    if (fileFormatInfo->compressionType == XEX_COMPRESSION_BASIC)
    {
        const Xex2FileBasicCompressionBlock *blocks = &((const Xex2FileBasicCompressionInfo*)(fileFormatInfo + 1))->firstBlock;
        int32_t numBlocks = (fileFormatInfo->infoSize / sizeof(Xex2FileBasicCompressionBlock)) - 1;
        int32_t baseCompressedSize = 0;
        int32_t baseImageSize = 0;
        for (int32_t i = 0; i < numBlocks; i++) {
            baseCompressedSize += blocks[i].dataSize;
            baseImageSize += blocks[i].dataSize + blocks[i].zeroSize;
        }

        if (outBytes.size() < (headerTargetSize + baseImageSize))
        {
            return Result::XexFileInvalid;
        }
        
        // Reverse iteration allows to perform this decompression in place.
        uint8_t *srcDataCursor = outBytes.data() + headerTargetSize + baseCompressedSize;
        uint8_t *outDataCursor = outBytes.data() + headerTargetSize + baseImageSize;
        for (int32_t i = numBlocks - 1; i >= 0; i--)
        {
            outDataCursor -= blocks[i].zeroSize;
            memset(outDataCursor, 0, blocks[i].zeroSize);
            outDataCursor -= blocks[i].dataSize;
            srcDataCursor -= blocks[i].dataSize;
            memmove(outDataCursor, srcDataCursor, blocks[i].dataSize);
        }
    }
    else if (fileFormatInfo->compressionType == XEX_COMPRESSION_NORMAL)
    {
        const Xex2CompressedBlockInfo* blocks = &((const Xex2FileNormalCompressionInfo*)(fileFormatInfo + 1))->firstBlock;
        const uint32_t exeLength = xexBytesSize - xexHeader->headerSize.get();
        const uint8_t* exeBuffer = &outBytes[headerTargetSize];

        auto compressBuffer = std::make_unique<uint8_t[]>(exeLength);
        const uint8_t* p = NULL;
        uint8_t* d = NULL;
        sha1::SHA1 s;

        p = exeBuffer;
        d = compressBuffer.get();

        uint8_t blockCalcedDigest[0x14];
        while (blocks->blockSize) 
        {
            const uint8_t* pNext = p + blocks->blockSize;
            const auto* nextBlock = (const Xex2CompressedBlockInfo*)p;

            s.reset();
            s.processBytes(p, blocks->blockSize);
            s.finalize(blockCalcedDigest);

            if (memcmp(blockCalcedDigest, blocks->blockHash, 0x14) != 0)
                return Result::PatchFailed;

            p += 4;
            p += 20;

            while (true) 
            {
                const size_t chunkSize = (p[0] << 8) | p[1];
                p += 2;

                if (!chunkSize)
                    break;

                memcpy(d, p, chunkSize);
                p += chunkSize;
                d += chunkSize;
            }

            p = pNext;
            blocks = nextBlock;
        }

        int resultCode = 0;
        uint32_t uncompressedSize = originalSecurityInfo->imageSize;
        uint8_t* buffer = outBytes.data() + newXexHeaderSize;

        resultCode = lzxDecompress(compressBuffer.get(), d - compressBuffer.get(), buffer, uncompressedSize, ((const Xex2FileNormalCompressionInfo*)(fileFormatInfo + 1))->windowSize, nullptr, 0);

        if (resultCode)
            return Result::PatchFailed;
    }
    else if (fileFormatInfo->compressionType == XEX_COMPRESSION_DELTA)
    {
        return Result::XexFileUnsupported;
    }
    else if (fileFormatInfo->compressionType != XEX_COMPRESSION_NONE)
    {
        return Result::XexFileInvalid;
    }

    Xex2OptFileFormatInfo *newFileFormatInfo = (Xex2OptFileFormatInfo *)(getOptHeaderPtr(outBytes.data(), XEX_HEADER_FILE_FORMAT_INFO));
    if (newFileFormatInfo == nullptr)
    {
        return Result::PatchFailed;
    }
    
    // Update the header to indicate no encryption or compression is used.
    newFileFormatInfo->encryptionType = XEX_ENCRYPTION_NONE;
    newFileFormatInfo->compressionType = XEX_COMPRESSION_NONE;

    // Copy and decrypt patch data if necessary.
    std::vector<uint8_t> patchData;
    patchData.resize(patchBytesSize - patchHeader->headerSize);
    memcpy(patchData.data(), &patchBytes[patchHeader->headerSize], patchData.size());

    if (patchFileFormatInfo->encryptionType == XEX_ENCRYPTION_NORMAL)
    {
        AES_init_ctx_iv(&aesContext, decryptedPatchKey, AESBlankIV);
        AES_CBC_decrypt_buffer(&aesContext, patchData.data(), patchData.size());
    }
    else if (patchFileFormatInfo->encryptionType != XEX_ENCRYPTION_NONE)
    {
        return Result::PatchFileInvalid;
    }

    const Xex2CompressedBlockInfo *currentBlock = &((const Xex2FileNormalCompressionInfo*)(patchFileFormatInfo + 1))->firstBlock;
    uint8_t *outExe = &outBytes[newXexHeader->headerSize];
    if (patchDescriptor->deltaImageSourceOffset > 0)
    {
        memcpy(&outExe[patchDescriptor->deltaImageTargetOffset], &outExe[patchDescriptor->deltaImageSourceOffset], patchDescriptor->deltaImageSourceSize);
    }

    static const uint32_t DigestSize = 20;
    uint8_t sha1Digest[DigestSize];
    sha1::SHA1 sha1Context;
    uint8_t *patchDataCursor = patchData.data();
    while (currentBlock->blockSize > 0)
    {
        const Xex2CompressedBlockInfo *nextBlock = (const Xex2CompressedBlockInfo *)(patchDataCursor);

        // Hash and validate the block.
        sha1Context.reset();
        sha1Context.processBytes(patchDataCursor, currentBlock->blockSize);
        sha1Context.finalize(sha1Digest);
        if (memcmp(sha1Digest, currentBlock->blockHash, DigestSize) != 0)
        {
            return Result::PatchFailed;
        }

        patchDataCursor += 24;

        // Apply the block's patch data.
        uint32_t blockDataSize = currentBlock->blockSize - 24;
        if (lzxDeltaApplyPatch((const Xex2DeltaPatch *)(patchDataCursor), blockDataSize, ((const Xex2FileNormalCompressionInfo*)(patchFileFormatInfo + 1))->windowSize, outExe) != 0)
        {
            return Result::PatchFailed;
        }

        patchDataCursor += blockDataSize;
        currentBlock = nextBlock;
    }

    return Result::Success;
}

XexPatcher::Result XexPatcher::apply(const std::filesystem::path &baseXexPath, const std::filesystem::path &patchXexPath, const std::filesystem::path &newXexPath)
{
    MemoryMappedFile baseXexFile(baseXexPath);
    MemoryMappedFile patchFile(patchXexPath);
    if (!baseXexFile.isOpen() || !patchFile.isOpen())
    {
        return Result::FileOpenFailed;
    }

    std::vector<uint8_t> newXexBytes;
    Result result = apply(baseXexFile.data(), baseXexFile.size(), patchFile.data(), patchFile.size(), newXexBytes, false);
    if (result != Result::Success)
    {
        return result;
    }

    std::ofstream newXexFile(newXexPath, std::ios::binary);
    if (!newXexFile.is_open())
    {
        return Result::FileOpenFailed;
    }

    newXexFile.write((const char *)(newXexBytes.data()), newXexBytes.size());
    newXexFile.close();

    if (newXexFile.bad())
    {
        std::filesystem::remove(newXexPath);
        return Result::FileWriteFailed;
    }

    return Result::Success;
}
