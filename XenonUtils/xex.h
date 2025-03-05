#pragma once
#include <memory>
#include "xbox.h"

inline constexpr uint8_t Xex2RetailKey[16] = { 0x20, 0xB1, 0x85, 0xA5, 0x9D, 0x28, 0xFD, 0xC3, 0x40, 0x58, 0x3F, 0xBB, 0x08, 0x96, 0xBF, 0x91 };
inline constexpr uint8_t AESBlankIV[16] = {};

enum Xex2ModuleFlags
{
    XEX_MODULE_MODULE_PATCH = 0x10,
    XEX_MODULE_PATCH_FULL = 0x20,
    XEX_MODULE_PATCH_DELTA = 0x40,
};

enum Xex2HeaderKeys
{
    XEX_HEADER_RESOURCE_INFO = 0x000002FF,
    XEX_HEADER_FILE_FORMAT_INFO = 0x000003FF,
    XEX_HEADER_DELTA_PATCH_DESCRIPTOR = 0x000005FF,
    XEX_HEADER_BASE_REFERENCE = 0x00000405,
    XEX_HEADER_BOUNDING_PATH = 0x000080FF,
    XEX_HEADER_DEVICE_ID = 0x00008105,
    XEX_HEADER_ORIGINAL_BASE_ADDRESS = 0x00010001,
    XEX_HEADER_ENTRY_POINT = 0x00010100,
    XEX_HEADER_IMAGE_BASE_ADDRESS = 0x00010201,
    XEX_HEADER_IMPORT_LIBRARIES = 0x000103FF,
    XEX_HEADER_CHECKSUM_TIMESTAMP = 0x00018002,
    XEX_HEADER_ENABLED_FOR_CALLCAP = 0x00018102,
    XEX_HEADER_ENABLED_FOR_FASTCAP = 0x00018200,
    XEX_HEADER_ORIGINAL_PE_NAME = 0x000183FF,
    XEX_HEADER_STATIC_LIBRARIES = 0x000200FF,
    XEX_HEADER_TLS_INFO = 0x00020104,
    XEX_HEADER_DEFAULT_STACK_SIZE = 0x00020200,
    XEX_HEADER_DEFAULT_FILESYSTEM_CACHE_SIZE = 0x00020301,
    XEX_HEADER_DEFAULT_HEAP_SIZE = 0x00020401,
    XEX_HEADER_PAGE_HEAP_SIZE_AND_FLAGS = 0x00028002,
    XEX_HEADER_SYSTEM_FLAGS = 0x00030000,
    XEX_HEADER_EXECUTION_INFO = 0x00040006,
    XEX_HEADER_TITLE_WORKSPACE_SIZE = 0x00040201,
    XEX_HEADER_GAME_RATINGS = 0x00040310,
    XEX_HEADER_LAN_KEY = 0x00040404,
    XEX_HEADER_XBOX360_LOGO = 0x000405FF,
    XEX_HEADER_MULTIDISC_MEDIA_IDS = 0x000406FF,
    XEX_HEADER_ALTERNATE_TITLE_IDS = 0x000407FF,
    XEX_HEADER_ADDITIONAL_TITLE_MEMORY = 0x00040801,
    XEX_HEADER_EXPORTS_BY_NAME = 0x00E10402,
};

enum Xex2EncryptionType
{
    XEX_ENCRYPTION_NONE = 0,
    XEX_ENCRYPTION_NORMAL = 1,
};

enum Xex2CompressionType
{
    XEX_COMPRESSION_NONE = 0,
    XEX_COMPRESSION_BASIC = 1,
    XEX_COMPRESSION_NORMAL = 2,
    XEX_COMPRESSION_DELTA = 3,
};

enum Xex2SectionType
{
    XEX_SECTION_CODE = 1,
    XEX_SECTION_DATA = 2,
    XEX_SECTION_READONLY_DATA = 3,
};

enum Xex2ThunkTypes
{
    XEX_THUNK_VARIABLE = 0,
    XEX_THUNK_FUNCTION = 1,
};

struct Xex2OptHeader
{
    be<uint32_t> key;

    union
    {
        be<uint32_t> value;
        be<uint32_t> offset;
    };
};

struct Xex2Header
{
    be<uint32_t> magic;
    be<uint32_t> moduleFlags;
    be<uint32_t> headerSize;
    be<uint32_t> reserved;
    be<uint32_t> securityOffset;
    be<uint32_t> headerCount;
};

struct Xex2PageDescriptor
{
    union
    {
        // Must be endian-swapped before reading the bitfield.
        uint32_t beValue;
        struct
        {
            uint32_t info : 4;
            uint32_t pageCount : 28;
        };
    };

    char dataDigest[0x14];
};

struct Xex2SecurityInfo
{
    be<uint32_t> headerSize;
    be<uint32_t> imageSize;
    char rsaSignature[0x100];
    be<uint32_t> unknown;
    be<uint32_t> imageFlags;
    be<uint32_t> loadAddress;
    char sectionDigest[0x14];
    be<uint32_t> importTableCount;
    char importTableDigest[0x14];
    char xgd2MediaId[0x10];
    char aesKey[0x10];
    be<uint32_t> exportTable;
    char headerDigest[0x14];
    be<uint32_t> region;
    be<uint32_t> allowedMediaTypes;
    be<uint32_t> pageDescriptorCount;
};

struct Xex2DeltaPatch
{
    be<uint32_t> oldAddress;
    be<uint32_t> newAddress;
    be<uint16_t> uncompressedLength;
    be<uint16_t> compressedLength;
    char patchData[1];
};

struct Xex2OptDeltaPatchDescriptor
{
    be<uint32_t> size;
    be<uint32_t> targetVersionValue;
    be<uint32_t> sourceVersionValue;
    uint8_t digestSource[0x14];
    uint8_t imageKeySource[0x10];
    be<uint32_t> sizeOfTargetHeaders;
    be<uint32_t> deltaHeadersSourceOffset;
    be<uint32_t> deltaHeadersSourceSize;
    be<uint32_t> deltaHeadersTargetOffset;
    be<uint32_t> deltaImageSourceOffset;
    be<uint32_t> deltaImageSourceSize;
    be<uint32_t> deltaImageTargetOffset;
    Xex2DeltaPatch info;
};

struct Xex2FileBasicCompressionBlock
{
    be<uint32_t> dataSize;
    be<uint32_t> zeroSize;
};

struct Xex2FileBasicCompressionInfo
{
    Xex2FileBasicCompressionBlock firstBlock;
};

struct Xex2CompressedBlockInfo
{
    be<uint32_t> blockSize;
    uint8_t blockHash[20];
};

struct Xex2FileNormalCompressionInfo
{
    be<uint32_t> windowSize;
    Xex2CompressedBlockInfo firstBlock;
};

struct Xex2OptFileFormatInfo
{
    be<uint32_t> infoSize;
    be<uint16_t> encryptionType;
    be<uint16_t> compressionType;
};

struct Xex2ImportHeader
{
    be<uint32_t> sizeOfHeader;
    be<uint32_t> sizeOfStringTable;
    be<uint32_t> numImports;
};

struct Xex2ImportLibrary 
{
    be<uint32_t> size;
    char nextImportDigest[0x14];
    be<uint32_t> id;
    be<uint32_t> version;
    be<uint32_t> minVersion;
    be<uint16_t> name;
    be<uint16_t> numberOfImports;
};

struct Xex2ImportDescriptor 
{
    be<uint32_t> firstThunk; // VA XEX_THUNK_DATA
};

struct Xex2ThunkData 
{
    union
    {
        struct
        {
            uint16_t ordinal : 16;
            uint16_t hint : 8;
            uint16_t type : 8;
        } originalData;

        be<uint32_t> ordinal;
        be<uint32_t> function;
        be<uint32_t> addressOfData;

        // For easier swapping
        uint32_t data;
    };
};

struct Xex2ResourceInfo
{
    be<uint32_t> sizeOfHeader;
    uint8_t resourceID[8];
    be<uint32_t> offset;
    be<uint32_t> sizeOfData;
};

inline const void* getOptHeaderPtr(const uint8_t* moduleBytes, uint32_t headerKey)
{
    const Xex2Header* xex2Header = (const Xex2Header*)(moduleBytes);
    for (uint32_t i = 0; i < xex2Header->headerCount; i++)
    {
        const Xex2OptHeader& optHeader = ((const Xex2OptHeader*)(xex2Header + 1))[i];
        if (optHeader.key == headerKey)
        {
            if((headerKey & 0xFF) == 0)
            {
                return reinterpret_cast<const uint32_t *>(&optHeader.value);
            }
            else if ((headerKey & 0xFF) == 1)
            {
                return reinterpret_cast<const void *>(&optHeader.value);
            }
            else
            {
                return reinterpret_cast<const void *>(reinterpret_cast<uintptr_t>(moduleBytes) + optHeader.offset);
            }
        }
    }

    return nullptr;
}

struct Image;
Image Xex2LoadImage(const uint8_t* data, size_t dataSize);
