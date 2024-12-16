#pragma once
#include <memory>
#include "xbox.h"

#define XEX_COMPRESSION_NONE 0
#define XEX_COMPRESSION_BASIC 1

#define XEX_ENCRYPTION_NONE 0

enum _XEX_THUNK_TYPES
{
    XEX_THUNK_VARIABLE = 0,
    XEX_THUNK_FUNCTION = 1,
};

enum _XEX_OPTIONAL_HEADER_TYPES
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

typedef struct _XEX_FILE_FORMAT_INFO
{
    be<uint32_t> SizeOfHeader;
    be<uint16_t> EncryptionType;
    be<uint16_t> CompressionType;
} XEX_FILE_FORMAT_INFO;

typedef struct _XEX_RESOURCE_INFO
{
    be<uint32_t> SizeOfHeader;
    uint8_t ResourceID[8];
    be<uint32_t> Offset;
    be<uint32_t> SizeOfData;
} XEX_RESOURCE_INFO;

typedef struct _XEX_BASIC_FILE_COMPRESSION_INFO
{
    be<uint32_t> SizeOfData;
    be<uint32_t> SizeOfPadding;
} XEX_BASIC_FILE_COMPRESSION_INFO;

typedef struct _XEX_THUNK_DATA {
    union
    {
        struct
        {
            uint16_t Ordinal : 16;
            uint16_t Hint : 8;
            uint16_t Type : 8;
        } OriginalData;

        be<uint32_t> Ordinal;
        be<uint32_t> Function;
        be<uint32_t> AddressOfData;

        // For easier swapping
        uint32_t Data;
    };
} XEX_THUNK_DATA;

typedef struct _XEX_IMPORT_HEADER {
    be<uint32_t> SizeOfHeader;
    be<uint32_t> SizeOfStringTable;
    be<uint32_t> NumImports;
} XEX_IMPORT_HEADER;

typedef struct _XEX_IMPORT_LIBRARY {
    be<uint32_t> Size;
    char NextImportDigest[0x14];
    be<uint32_t> ID;
    be<uint32_t> Version;
    be<uint32_t> MinVersion;
    be<uint16_t> Name;
    be<uint16_t> NumberOfImports;
} XEX_IMPORT_LIBRARY;

static_assert(sizeof(XEX_IMPORT_LIBRARY) == 0x28);

typedef struct _XEX_IMPORT_DESCRIPTOR {
    be<uint32_t> FirstThunk; // VA XEX_THUNK_DATA
} XEX_IMPORT_DESCRIPTOR;

typedef struct _XEX_OPTIONAL_HEADER
{
    be<uint32_t> Type;
    be<uint32_t> Address;
} XEX_OPTIONAL_HEADER;

typedef struct _XEX2_SECURITY_INFO
{
    be<uint32_t> SizeOfHeader;
    be<uint32_t> SizeOfImage;
    char RsaSignature[0x100];
    be<uint32_t> Unknown108;
    be<uint32_t> ImageFlags;
    be<uint32_t> ImageBase;
    char SectionDigest[0x14];
    be<uint32_t> NumberOfImports;
    char ImportsDigest[0x14];
    char Xgd2MediaID[0x10];
    char AesKey[0x10];
    be<uint32_t> AddressOfExports;
    char HeaderDigest[0x14];
    be<uint32_t> Region;
    be<uint32_t> AllowedMediaTypes;
    be<uint32_t> NumberOfPageDescriptors;
} XEX2_SECURITY_INFO;

typedef struct _XEX_HEADER
{
    char Signature[4];
    be<uint32_t> Flags;
    be<uint32_t> SizeOfHeader;
    char Reserved[4];
    be<uint32_t> AddressOfSecurityInfo;
    be<uint32_t> NumberOfOptionalHeaders;
} XEX_HEADER;

template<typename T>
inline static const T* Xex2FindOptionalHeader(const void* base, const XEX_OPTIONAL_HEADER* headers, size_t n, _XEX_OPTIONAL_HEADER_TYPES type)
{
    for (size_t i = 0; i < n; i++)
    {
        if (headers[i].Type == (uint32_t)type)
        {
            if ((type & 0xFF) == 0)
            {
                return reinterpret_cast<const T*>(&headers[i].Address);
            }
            else
            {
                return reinterpret_cast<const T*>(static_cast<const char*>(base) + headers[i].Address);
            }
        }
    }

    return nullptr;
}

template<typename T>
inline static const T* Xex2FindOptionalHeader(const XEX_HEADER* header, _XEX_OPTIONAL_HEADER_TYPES type)
{
    return Xex2FindOptionalHeader<T>(header, (XEX_OPTIONAL_HEADER*)(header + 1), header->NumberOfOptionalHeaders, type);
}

struct Image;
Image Xex2LoadImage(const uint8_t* data);
