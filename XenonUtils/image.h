#pragma once
#include <memory>
#include <string>
#include <set>
#include <section.h>
#include "symbol_table.h"

struct Image
{
    std::unique_ptr<uint8_t[]> data{};
    size_t base{};
    uint32_t size{};

    uint32_t resource_offset{};
    uint32_t resource_size{};

    size_t entry_point{};
    std::set<Section, SectionComparer> sections{};
    SymbolTable symbols{};

    /**
     * \brief Map data to image by RVA
     * \param name Name of section
     * \param base Section RVA
     * \param size Section Size
     * \param flags Section Flags, enum SectionFlags
     * \param data Section data
     */
    void Map(const std::string_view& name, size_t base, uint32_t size, uint8_t flags, uint8_t* data);

    /**
     * \param address Virtual Address
     * \return Pointer to image owned data
     */
    const void* Find(size_t address) const;

    /**
     * \param name Name of section
     * \return Section
     */
    const Section* Find(const std::string_view& name) const;

    /**
     * \brief Parse given data to an image, reallocates with ownership
     * \param data Pointer to data
     * \param size Size of data
     * \return Parsed image
     */
    static Image ParseImage(const uint8_t* data, size_t size);
};

Image ElfLoadImage(const uint8_t* data, size_t size);
