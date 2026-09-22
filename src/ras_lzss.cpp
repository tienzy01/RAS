#include "ras_lzss.hpp"
#include "ras_common.hpp"

#include <array>
#include <algorithm>

namespace ras
{
    std::vector<std::uint8_t> lzssDecompress(
        const std::uint8_t* input,
        std::size_t inputSize,
        std::size_t expectedSize
    )
    {
        if (inputSize < 12)
            throw std::runtime_error("Compressed block too small.");

        const std::uint32_t uncompressedSize = le32(input + 4);
        const std::uint32_t compressedSize   = le32(input + 8);

        if (expectedSize == 0)
            expectedSize = uncompressedSize;

        std::vector<std::uint8_t> out;
        out.reserve(expectedSize);

        if (expectedSize == 0)
            return out;

        /*
            Pseudocode:
                memset(&R_File::text_buf, 32, 4078);
                write position = 4078;
        */
        std::array<std::uint8_t, 4096> ring{};
        ring.fill(0x20);

        std::size_t writePos = 4078;

        const std::size_t payloadEnd =
            12 + std::min<std::size_t>(
                compressedSize,
                inputSize - 12
            );

        std::size_t i = 12;
        std::uint32_t flags = 0;

        auto putByte = [&](std::uint8_t b)
        {
            out.push_back(b);
            ring[writePos] = b;
            writePos = (writePos + 1) & 0xFFF;
        };

        while (out.size() < expectedSize)
        {
            while (true)
            {
                flags >>= 1;

                if ((flags & 0x100u) == 0)
                {
                    if (i >= payloadEnd)
                        return out;

                    flags = static_cast<std::uint32_t>(input[i++]) | 0xFF00u;
                }

                if ((flags & 1u) == 0)
                    break;

                if (i >= payloadEnd)
                    return out;

                putByte(input[i++]);

                if (out.size() >= expectedSize)
                    return out;
            }

            if (i >= payloadEnd)
                break;

            const std::uint8_t low = input[i];

            if (i + 1 >= payloadEnd)
                break;

            const std::uint8_t high = input[i + 1];
            i += 2;

            const std::uint32_t position =
                (static_cast<std::uint32_t>(high & 0xF0) << 4) |
                static_cast<std::uint32_t>(low);

            const std::uint32_t length =
                static_cast<std::uint32_t>(high & 0x0F) + 3u;

            for (std::uint32_t k = 0;
                 k < length && out.size() < expectedSize;
                 ++k)
            {
                putByte(ring[(position + k) & 0xFFF]);
            }
        }

        return out;
    }
}