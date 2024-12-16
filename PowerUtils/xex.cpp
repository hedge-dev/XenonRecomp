#include "xex.h"
#include "image.h"
#include <cassert>
#include <cstring>
#include <vector>
#include <unordered_map>

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

Image Xex2LoadImage(const uint8_t* data)
{
    auto* header = reinterpret_cast<const XEX_HEADER*>(data);
    auto* security = reinterpret_cast<const XEX2_SECURITY_INFO*>(data + header->AddressOfSecurityInfo);

    const auto* compressionInfo = Xex2FindOptionalHeader<XEX_FILE_FORMAT_INFO>(header, XEX_HEADER_FILE_FORMAT_INFO);

    Image image{};
    std::unique_ptr<uint8_t[]> result{};
    size_t imageSize = security->SizeOfImage;

    // Decompress image
    if (compressionInfo != nullptr)
    {
        assert(compressionInfo->CompressionType >= XEX_COMPRESSION_BASIC);
        assert(compressionInfo->EncryptionType == XEX_ENCRYPTION_NONE);

        if (compressionInfo->CompressionType == XEX_COMPRESSION_NONE)
        {
            result = std::make_unique<uint8_t[]>(imageSize);
            memcpy(result.get(), data + header->SizeOfHeader, imageSize);
        }
        else if (compressionInfo->CompressionType == XEX_COMPRESSION_BASIC)
        {
            auto* blocks = reinterpret_cast<const XEX_BASIC_FILE_COMPRESSION_INFO*>(compressionInfo + 1);
            const size_t numBlocks = (compressionInfo->SizeOfHeader / sizeof(XEX_BASIC_FILE_COMPRESSION_INFO)) - 1;

            imageSize = 0;
            for (size_t i = 0; i < numBlocks; i++)
            {
                imageSize += blocks[i].SizeOfData + blocks[i].SizeOfPadding;
            }

            result = std::make_unique<uint8_t[]>(imageSize);
            auto* srcData = data + header->SizeOfHeader;
            auto* destData = result.get();

            for (size_t i = 0; i < numBlocks; i++)
            {
                memcpy(destData, srcData, blocks[i].SizeOfData);

                srcData += blocks[i].SizeOfData;
                destData += blocks[i].SizeOfData;

                memset(destData, 0, blocks[i].SizeOfPadding);
                destData += blocks[i].SizeOfPadding;
            }
        }
    }

    image.data = std::move(result);
    image.size = imageSize;

    // Map image
    const auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data.get());
    const auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS32*>(image.data.get() + dosHeader->e_lfanew);

    image.base = ntHeaders->OptionalHeader.ImageBase;
    image.entry_point = image.base + ntHeaders->OptionalHeader.AddressOfEntryPoint;

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

    auto* imports = Xex2FindOptionalHeader<XEX_IMPORT_HEADER>(header, XEX_HEADER_IMPORT_LIBRARIES);
    if (imports != nullptr)
    {
        std::vector<std::string_view> stringTable;
        auto* pStrTable = reinterpret_cast<const char*>(imports + 1);

        for (size_t i = 0; i < imports->NumImports; i++)
        {
            stringTable.emplace_back(pStrTable);
            pStrTable += strlen(pStrTable) + 1;
        }

        auto* library = (XEX_IMPORT_LIBRARY*)(((char*)imports) + sizeof(XEX_IMPORT_HEADER) + imports->SizeOfStringTable);
        for (size_t i = 0; i < stringTable.size(); i++)
        {
            auto* descriptors = (XEX_IMPORT_DESCRIPTOR*)(library + 1);
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

            for (size_t im = 0; im < library->NumberOfImports; im++)
            {
                auto originalThunk = (XEX_THUNK_DATA*)image.Find(descriptors[im].FirstThunk);
                auto originalData = originalThunk;
                originalData->Data = ByteSwap(originalData->Data);

                if (originalData->OriginalData.Type != 0)
                {
                    uint32_t thunk[4] = { 0x00000060, 0x00000060, 0x00000060, 0x2000804E };
                    auto name = names->find(originalData->OriginalData.Ordinal);
                    if (name != names->end())
                    {
                        image.symbols.insert({ name->second, descriptors[im].FirstThunk, sizeof(thunk), Symbol_Function });
                    }

                    memcpy(originalThunk, thunk, sizeof(thunk));
                }
            }
            library = (XEX_IMPORT_LIBRARY*)((char*)(library + 1) + library->NumberOfImports * sizeof(XEX_IMPORT_DESCRIPTOR));
        }
    }

    return image;
}
