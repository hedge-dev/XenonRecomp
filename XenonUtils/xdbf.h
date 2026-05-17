#pragma once

#include <xbox.h>

#define XDBF_SIGNATURE 0x58444246
#define XACH_SIGNATURE 0x58414348

struct XDBFHeader
{
    be<uint32_t> Signature;
    be<uint32_t> Version;
    be<uint32_t> EntryTableLength;
    be<uint32_t> EntryCount;
    be<uint32_t> FreeSpaceTableLength;
    be<uint32_t> FreeSpaceTableEntryCount;
};

enum EXDBFNamespace : uint16_t
{
    XDBF_SPA_NAMESPACE_METADATA = 1,
    XDBF_SPA_NAMESPACE_IMAGE = 2,
    XDBF_SPA_NAMESPACE_STRING_TABLE = 3,
    XDBF_GPD_NAMESPACE_ACHIEVEMENT = 1,
    XDBF_GPD_NAMESPACE_IMAGE = 2,
    XDBF_GPD_NAMESPACE_SETTING = 3,
    XDBF_GPD_NAMESPACE_TITLE = 4,
    XDBF_GPD_NAMESPACE_STRING = 5,
    XDBF_GPD_NAMESPACE_ACHIEVEMENT_SECURITY_GFWL = 6,
    XDBF_GPD_NAMESPACE_AVATAR_AWARD_360 = 6
};

#pragma pack(push, 1)
struct XDBFEntry
{
    be<EXDBFNamespace> NamespaceID;
    be<uint64_t> ResourceID;
    be<uint32_t> Offset;
    be<uint32_t> Length;
};
#pragma pack(pop)

struct XDBFFreeSpaceEntry
{
    be<uint32_t> Offset;
    be<uint32_t> Length;
};

enum EXDBFLanguage : uint32_t
{
    XDBF_LANGUAGE_UNKNOWN = 0,
    XDBF_LANGUAGE_ENGLISH = 1,
    XDBF_LANGUAGE_JAPANESE = 2,
    XDBF_LANGUAGE_GERMAN = 3,
    XDBF_LANGUAGE_FRENCH = 4,
    XDBF_LANGUAGE_SPANISH = 5,
    XDBF_LANGUAGE_ITALIAN = 6,
    XDBF_LANGUAGE_KOREAN = 7,
    XDBF_LANGUAGE_CHINESE_TRAD = 8,
    XDBF_LANGUAGE_PORTUGUESE = 9,
    XDBF_LANGUAGE_CHINESE_SIMP = 10,
    XDBF_LANGUAGE_POLISH = 11,
    XDBF_LANGUAGE_RUSSIAN = 12,
    XDBF_LANGUAGE_MAX
};

struct XSTCHeader
{
    be<uint32_t> Signature;
    be<uint32_t> Version;
    be<uint32_t> Size;
    be<EXDBFLanguage> Language;
};

#pragma pack(push, 1)
struct XSTRHeader
{
    be<uint32_t> Signature;
    be<uint32_t> Version;
    be<uint32_t> Size;
    be<uint16_t> StringCount;
};
#pragma pack(pop)

struct XSTREntry
{
    be<uint16_t> ID;
    be<uint16_t> Length;
};

#pragma pack(push, 1)
struct XACHHeader
{
    be<uint32_t> Signature;
    be<uint32_t> Version;
    be<uint32_t> Size;
    be<uint16_t> AchievementCount;
};
#pragma pack(pop)

enum EXACHFlags : uint32_t
{
    XACH_TYPE_COMPLETION = 1U,
    XACH_TYPE_LEVELING = 2U,
    XACH_TYPE_UNLOCK = 3U,
    XACH_TYPE_EVENT = 4U,
    XACH_TYPE_TOURNAMENT = 5U,
    XACH_TYPE_CHECKPOINT = 6U,
    XACH_TYPE_OTHER = 7U,
    XACH_TYPE_MASK = 7U,
    XACH_STATUS_UNACHIEVED = (1U << 4),
    XACH_STATUS_EARNED_ONLINE = (1U << 16),
    XACH_STATUS_EARNED = (1U << 17),
    XACH_STATUS_EDITED = (1U << 20)
};

struct XACHEntry
{
    be<uint16_t> AchievementID;
    be<uint16_t> NameID;
    be<uint16_t> UnlockedDescID;
    be<uint16_t> LockedDescID;
    be<uint32_t> ImageID;
    be<uint16_t> Gamerscore;
    char pad0[0x02];
    be<EXACHFlags> Flags;
    char pad1[0x10];
};

union XDBFTitleID
{
    struct
    {
        be<uint16_t> u16;
        char u8[0x02];
    } parts;

    be<uint32_t> u32;
};

struct XDBFTitleVersion
{
    be<uint16_t> Major;
    be<uint16_t> Minor;
    be<uint16_t> Build;
    be<uint16_t> Revision;
};

enum EXDBFTitleType : uint32_t
{
    XDBF_TITLE_TYPE_SYSTEM = 0,
    XDBF_TITLE_TYPE_FULL = 1,
    XDBF_TITLE_TYPE_DEMO = 2,
    XDBF_TITLE_TYPE_DOWNLOAD = 3
};

struct XTHDHeader
{
    be<uint32_t> Signature;
    be<uint32_t> Version;
    be<uint32_t> Size;
    XDBFTitleID TitleID;
    be<EXDBFTitleType> Type;
    XDBFTitleVersion TitleVersion;
    char pad0[0x10];
};

#pragma pack(push, 1)
struct XGAAHeader
{
    be<uint32_t> Signature;
    be<uint32_t> Version;
    be<uint32_t> Size;
    be<uint16_t> Count;
};
#pragma pack(pop)

struct XGAAEntry
{
    char pad0[0x04];
    be<uint16_t> AvatarAwardID;
    char pad1[0x06];
    XDBFTitleID TitleID;
    be<uint16_t> NameID;
    be<uint16_t> UnlockedDescID;
    be<uint16_t> LockedDescID;
    char pad2[0x02];
    be<uint32_t> ImageID;
    char pad3[0x08];
};

struct XSRCHeader
{
    be<uint32_t> Signature;
    be<uint32_t> Version;
    be<uint32_t> Size;
    be<uint32_t> FileNameLength;
};

struct XSRCHeader2
{
    be<uint32_t> UncompressedSize;
    be<uint32_t> CompressedSize;
};
