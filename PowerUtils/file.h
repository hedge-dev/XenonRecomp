#pragma once

#include <filesystem>
#include <fstream>
#include <vector>

inline std::vector<uint8_t> LoadFile(const std::filesystem::path& path)
{
    std::ifstream stream(path, std::ios::binary);
    if (!stream.is_open())
    {
        return {};
    }

    stream.seekg(0, std::ios::end);
    std::streampos size = stream.tellg();
    stream.seekg(0, std::ios::beg);

    std::vector<uint8_t> data;
    data.resize(size);
    stream.read((char *)(data.data()), size);
    if (stream.bad())
    {
        return {};
    }

    return data;
}
