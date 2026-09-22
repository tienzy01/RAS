#pragma once

#include <cstdint>
#include <cstddef>

namespace ras
{
    std::uint32_t crc32(const std::uint8_t* data, std::size_t size);

    void decryptWithSeed(
        std::uint8_t* data,
        std::size_t size,
        std::int32_t seed
    );
}