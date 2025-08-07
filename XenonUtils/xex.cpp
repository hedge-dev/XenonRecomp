#include "xex.h"
#include "image.h"
#include <cassert>
#include <cstring>
#include <vector>
#include <unordered_map>
#include <aes.hpp>
#include <TinySHA1.hpp>
#include <xex_patcher.h>

#define STRINGIFY(X) #X
#define XE_EXPORT(MODULE, ORDINAL, NAME, TYPE) { (ORDINAL), "__imp__" STRINGIFY(NAME) }

#ifndef _WIN32

typedef struct _IMAGE_DOS_HEADER { 
    uint16_t   e_magic;                
    uint16_t   e_cblp;                 
    uint16_t   e_cp;                   
    uint16_t   e_crlc;                 
    uint16_t   e_cparhdr;              
    uint16_t   e_minalloc;             
    uint16_t   e_maxalloc;             
    uint16_t   e_ss;                   
    uint16_t   e_sp;                   
    uint16_t   e_csum;                 
    uint16_t   e_ip;                   
    uint16_t   e_cs;                   
    uint16_t   e_lfarlc;               
    uint16_t   e_ovno;                 
    uint16_t   e_res[4];               
    uint16_t   e_oemid;                
    uint16_t   e_oeminfo;              
    uint16_t   e_res2[10];             
    uint32_t   e_lfanew;               
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    uint16_t   Machine;
    uint16_t   NumberOfSections;
    uint32_t   TimeDateStamp;
    uint32_t   PointerToSymbolTable;
    uint32_t   NumberOfSymbols;
    uint16_t   SizeOfOptionalHeader;
    uint16_t   Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    uint32_t   VirtualAddress;
    uint32_t   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_OPTIONAL_HEADER {
    uint16_t   Magic;
    uint8_t    MajorLinkerVersion;
    uint8_t    MinorLinkerVersion;
    uint32_t   SizeOfCode;
    uint32_t   SizeOfInitializedData;
    uint32_t   SizeOfUninitializedData;
    uint32_t   AddressOfEntryPoint;
    uint32_t   BaseOfCode;
    uint32_t   BaseOfData;
    uint32_t   ImageBase;
    uint32_t   SectionAlignment;
    uint32_t   FileAlignment;
    uint16_t   MajorOperatingSystemVersion;
    uint16_t   MinorOperatingSystemVersion;
    uint16_t   MajorImageVersion;
    uint16_t   MinorImageVersion;
    uint16_t   MajorSubsystemVersion;
    uint16_t   MinorSubsystemVersion;
    uint32_t   Win32VersionValue;
    uint32_t   SizeOfImage;
    uint32_t   SizeOfHeaders;
    uint32_t   CheckSum;
    uint16_t   Subsystem;
    uint16_t   DllCharacteristics;
    uint32_t   SizeOfStackReserve;
    uint32_t   SizeOfStackCommit;
    uint32_t   SizeOfHeapReserve;
    uint32_t   SizeOfHeapCommit;
    uint32_t   LoaderFlags;
    uint32_t   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_NT_HEADERS {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, * PIMAGE_NT_HEADERS32;

#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_SECTION_HEADER {
    uint8_t    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        uint32_t   PhysicalAddress;
        uint32_t   VirtualSize;
    } Misc;
    uint32_t   VirtualAddress;
    uint32_t   SizeOfRawData;
    uint32_t   PointerToRawData;
    uint32_t   PointerToRelocations;
    uint32_t   PointerToLinenumbers;
    uint16_t   NumberOfRelocations;
    uint16_t   NumberOfLinenumbers;
    uint32_t   Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

#define IMAGE_SCN_CNT_CODE                   0x00000020

#endif

std::unordered_map<size_t, const char*> XamExports = 
{
    #include "xbox/xam_table.inc"
};

std::unordered_map<size_t, const char*> XboxKernelExports =
{
    #include "xbox/xboxkrnl_table.inc"
};

Image Xex2LoadImage(const uint8_t* data, size_t dataSize)
{
    auto* header = reinterpret_cast<const Xex2Header*>(data);
    auto* security = reinterpret_cast<const Xex2SecurityInfo*>(data + header->securityOffset);
    const auto* fileFormatInfo = reinterpret_cast<const Xex2OptFileFormatInfo*>(getOptHeaderPtr(data, XEX_HEADER_FILE_FORMAT_INFO));

    Image image{};
    std::unique_ptr<uint8_t[]> result{};
    size_t imageSize = security->imageSize;

    // Decompress image
    if (fileFormatInfo != nullptr)
    {
        assert(fileFormatInfo->compressionType <= XEX_COMPRESSION_NORMAL);

        std::unique_ptr<uint8_t[]> decryptedData;
        const uint8_t* srcData = nullptr;

        if (fileFormatInfo->encryptionType == XEX_ENCRYPTION_NORMAL)
        {
            constexpr uint32_t KeySize = 16;
            AES_ctx aesContext;

            uint8_t decryptedKey[KeySize];
            memcpy(decryptedKey, security->aesKey, KeySize);
            AES_init_ctx_iv(&aesContext, Xex2RetailKey, AESBlankIV);
            AES_CBC_decrypt_buffer(&aesContext, decryptedKey, KeySize);

            decryptedData = std::make_unique<uint8_t[]>(dataSize - header->headerSize);
            memcpy(decryptedData.get(), data + header->headerSize, dataSize - header->headerSize);
            AES_init_ctx_iv(&aesContext, decryptedKey, AESBlankIV);
            AES_CBC_decrypt_buffer(&aesContext, decryptedData.get(), dataSize - header->headerSize);

            srcData = decryptedData.get();
        }
        else
        {
            srcData = data + header->headerSize;
        }

        if (fileFormatInfo->compressionType == XEX_COMPRESSION_NONE)
        {
            result = std::make_unique<uint8_t[]>(imageSize);
            memcpy(result.get(), srcData, imageSize);
        }
        else if (fileFormatInfo->compressionType == XEX_COMPRESSION_BASIC)
        {
            auto* blocks = reinterpret_cast<const Xex2FileBasicCompressionBlock*>(fileFormatInfo + 1);
            const size_t numBlocks = (fileFormatInfo->infoSize / sizeof(Xex2FileBasicCompressionInfo)) - 1;

            imageSize = 0;
            for (size_t i = 0; i < numBlocks; i++)
            {
                imageSize += blocks[i].dataSize + blocks[i].zeroSize;
            }

            result = std::make_unique<uint8_t[]>(imageSize);
            auto* destData = result.get();

            for (size_t i = 0; i < numBlocks; i++)
            {
                memcpy(destData, srcData, blocks[i].dataSize);

                srcData += blocks[i].dataSize;
                destData += blocks[i].dataSize;

                memset(destData, 0, blocks[i].zeroSize);
                destData += blocks[i].zeroSize;
            }
        }
        else if (fileFormatInfo->compressionType == XEX_COMPRESSION_NORMAL)
        {
            result = std::make_unique<uint8_t[]>(imageSize);
            auto* destData = result.get();

            const Xex2CompressedBlockInfo* blocks = &((const Xex2FileNormalCompressionInfo*)(fileFormatInfo + 1))->firstBlock;
            const uint32_t headerSize = header->headerSize.get();

            const uint32_t exeLength = dataSize - headerSize;
            const uint8_t* exeBuffer = srcData;

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
                    return {};

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
            uint32_t uncompressedSize = security->imageSize;
            uint8_t* buffer = destData;

            resultCode = lzxDecompress(compressBuffer.get(), d - compressBuffer.get(), buffer, uncompressedSize, ((const Xex2FileNormalCompressionInfo*)(fileFormatInfo + 1))->windowSize, nullptr, 0);

            if (resultCode)
                return {};
        }
    }

    image.data = std::move(result);
    image.size = imageSize;

    // Map image
    const auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data.get());
    const auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS32*>(image.data.get() + dosHeader->e_lfanew);

    image.base = security->loadAddress;
    const void* xex2BaseAddressPtr = getOptHeaderPtr(data, XEX_HEADER_IMAGE_BASE_ADDRESS);
    if (xex2BaseAddressPtr != nullptr)
    {
        image.base = *reinterpret_cast<const be<uint32_t>*>(xex2BaseAddressPtr);
    }
    const void* xex2ResourceInfoPtr = getOptHeaderPtr(data, XEX_HEADER_RESOURCE_INFO);
    if (xex2ResourceInfoPtr != nullptr)
    {
        const Xex2ResourceInfo* resourceInfo = reinterpret_cast<const Xex2ResourceInfo*>(xex2ResourceInfoPtr);
        image.resource_offset = resourceInfo->offset;
        image.resource_size = resourceInfo->sizeOfData;
    }
    const void* xex2EntryPointPtr = getOptHeaderPtr(data, XEX_HEADER_ENTRY_POINT);
    if (xex2EntryPointPtr != nullptr)
    {
        image.entry_point = *reinterpret_cast<const be<uint32_t>*>(xex2EntryPointPtr);
    }

    const auto numSections = ntHeaders->FileHeader.NumberOfSections;
    const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(ntHeaders + 1);

    for (size_t i = 0; i < numSections; i++)
    {
        const auto& section = sections[i];
        uint8_t flags{};

        if (section.Characteristics & IMAGE_SCN_CNT_CODE)
        {
            flags |= SectionFlags_Code;
        }

        image.Map(reinterpret_cast<const char*>(section.Name), section.VirtualAddress, 
            section.Misc.VirtualSize, flags, image.data.get() + section.VirtualAddress);
    }

    auto* imports = reinterpret_cast<const Xex2ImportHeader*>(getOptHeaderPtr(data, XEX_HEADER_IMPORT_LIBRARIES));
    if (imports != nullptr)
    {
        std::vector<std::string_view> stringTable;
        auto* pStrTable = reinterpret_cast<const char*>(imports + 1);

        size_t paddedStringOffset = 0;
        for (size_t i = 0; i < imports->numImports; i++)
        {
            stringTable.emplace_back(pStrTable + paddedStringOffset);
            
            // pad the offset to the next multiple of 4
            paddedStringOffset += ((stringTable.back().length() + 1) + 3) & ~3;
        }

        auto* library = (Xex2ImportLibrary*)(((char*)imports) + sizeof(Xex2ImportHeader) + imports->sizeOfStringTable);
        for (size_t i = 0; i < stringTable.size(); i++)
        {
            auto* descriptors = (Xex2ImportDescriptor*)(library + 1);
            static std::unordered_map<size_t, const char*> DummyExports;
            const std::unordered_map<size_t, const char*>* names = &DummyExports;

            if (stringTable[i] == "xam.xex")
            {
                names = &XamExports;
            }
            else if (stringTable[i] == "xboxkrnl.exe")
            {
                names = &XboxKernelExports;
            }

            for (size_t im = 0; im < library->numberOfImports; im++)
            {
                auto originalThunk = (Xex2ThunkData*)image.Find(descriptors[im].firstThunk);
                auto originalData = originalThunk;
                originalData->data = ByteSwap(originalData->data);

                if (originalData->originalData.type != 0)
                {
                    uint32_t thunk[4] = { 0x00000060, 0x00000060, 0x00000060, 0x2000804E };
                    auto name = names->find(originalData->originalData.ordinal);
                    if (name != names->end())
                    {
                        image.symbols.insert({ name->second, descriptors[im].firstThunk, sizeof(thunk), Symbol_Function });
                    }

                    memcpy(originalThunk, thunk, sizeof(thunk));
                }
            }
            library = (Xex2ImportLibrary*)((char*)(library + 1) + library->numberOfImports * sizeof(Xex2ImportDescriptor));
        }
    }

    return image;
}
