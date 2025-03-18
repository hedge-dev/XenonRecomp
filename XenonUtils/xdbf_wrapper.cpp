#include "xdbf_wrapper.h"

XDBFWrapper::XDBFWrapper(const uint8_t* buffer, size_t bufferSize) : pBuffer(buffer), BufferSize(bufferSize)
{
    if (!buffer || bufferSize <= sizeof(XDBFHeader))
    {
        pBuffer = nullptr;
        return;
    }

    auto seek = pBuffer;

    pHeader = (XDBFHeader*)seek;
    seek += sizeof(XDBFHeader);

    if (pHeader->Signature != XDBF_SIGNATURE)
    {
        pBuffer = nullptr;
        return;
    }

    pEntries = (XDBFEntry*)seek;
    seek += sizeof(XDBFEntry) * pHeader->EntryCount;

    pFiles = (XDBFFreeSpaceEntry*)seek;
    seek += sizeof(XDBFFreeSpaceEntry) * pHeader->FreeSpaceTableLength;

    pContent = seek;
}

XDBFBlock XDBFWrapper::GetResource(EXDBFNamespace ns, uint64_t id) const
{
    for (int i = 0; i < pHeader->EntryCount; i++)
    {
        auto& entry = pEntries[i];

        if (entry.NamespaceID == ns && entry.ResourceID == id)
        {
            XDBFBlock block {};
            block.pBuffer = pContent + entry.Offset;
            block.BufferSize = entry.Length;
            return block;
        }
    }

    return { nullptr };
}

std::string XDBFWrapper::GetString(EXDBFLanguage language, uint16_t id) const
{
    auto languageBlock = GetResource(XDBF_SPA_NAMESPACE_STRING_TABLE, (uint64_t)language);

    if (!languageBlock)
        return "";

    auto pHeader = (XSTRHeader*)languageBlock.pBuffer;
    auto seek = languageBlock.pBuffer + sizeof(XSTRHeader);

    for (int i = 0; i < pHeader->StringCount; i++)
    {
        auto entry = (XSTREntry*)seek;

        seek += sizeof(XSTREntry);

        if (entry->ID == id)
            return std::string((const char*)seek, entry->Length);

        seek += entry->Length;
    }

    return "";
}

std::vector<Achievement> XDBFWrapper::GetAchievements(EXDBFLanguage language) const
{
    std::vector<Achievement> result;

    auto achievementsBlock = GetResource(XDBF_SPA_NAMESPACE_METADATA, XACH_SIGNATURE);

    if (!achievementsBlock)
        return result;

    auto pHeader = (XACHHeader*)achievementsBlock.pBuffer;
    auto seek = achievementsBlock.pBuffer + sizeof(XACHHeader);

    for (int i = 0; i < pHeader->AchievementCount; i++)
    {
        auto entry = (XACHEntry*)seek;

        seek += sizeof(XACHEntry);

        Achievement achievement {};
        achievement.ID = entry->AchievementID;
        achievement.Name = GetString(language, entry->NameID);
        achievement.UnlockedDesc = GetString(language, entry->UnlockedDescID);
        achievement.LockedDesc = GetString(language, entry->LockedDescID);
        achievement.Score = entry->Gamerscore;

        auto imageBlock = GetResource(XDBF_SPA_NAMESPACE_IMAGE, entry->ImageID);

        if (imageBlock)
        {
            achievement.pImageBuffer = imageBlock.pBuffer;
            achievement.ImageBufferSize = imageBlock.BufferSize;
        }

        result.push_back(achievement);
    }

    return result;
}

Achievement XDBFWrapper::GetAchievement(EXDBFLanguage language, uint16_t id) const
{
    Achievement result {};

    auto achievementsBlock = GetResource(XDBF_SPA_NAMESPACE_METADATA, 0x58414348);

    if (!achievementsBlock)
        return result;

    auto pHeader = (XACHHeader*)achievementsBlock.pBuffer;
    auto seek = achievementsBlock.pBuffer + sizeof(XACHHeader);

    for (int i = 0; i < pHeader->AchievementCount; i++)
    {
        auto entry = (XACHEntry*)seek;

        seek += sizeof(XACHEntry);

        if (entry->AchievementID == id)
        {
            result.ID = entry->AchievementID;
            result.Name = GetString(language, entry->NameID);
            result.UnlockedDesc = GetString(language, entry->UnlockedDescID);
            result.LockedDesc = GetString(language, entry->LockedDescID);
            result.Score = entry->Gamerscore;

            auto imageBlock = GetResource(XDBF_SPA_NAMESPACE_IMAGE, entry->ImageID);

            if (imageBlock)
            {
                result.pImageBuffer = imageBlock.pBuffer;
                result.ImageBufferSize = imageBlock.BufferSize;
            }

            return result;
        }
    }

    return result;
}
