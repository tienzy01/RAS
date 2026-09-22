#include "ras_crypto.hpp"

#include <array>

namespace
{
    std::array<std::uint32_t, 256> makeCrc32Table()
    {
        std::array<std::uint32_t, 256> table{};

        for (std::uint32_t i = 0; i < 256; ++i)
        {
            std::uint32_t c = i;

            for (int k = 0; k < 8; ++k)
            {
                if (c & 1u)
                    c = 0xEDB88320u ^ (c >> 1);
                else
                    c >>= 1;
            }

            table[i] = c;
        }

        return table;
    }

    const std::array<std::uint32_t, 256> g_crc32Table = makeCrc32Table();

    inline std::uint8_t rol8(std::uint8_t v, unsigned r) noexcept
    {
        r &= 7u;

        if (r == 0)
            return v;

        return static_cast<std::uint8_t>(
            (v << r) | (v >> (8u - r))
        );
    }
}

namespace ras
{
    std::uint32_t crc32(const std::uint8_t* data, std::size_t size)
    {
        std::uint32_t crc = 0xFFFFFFFFu;

        for (std::size_t i = 0; i < size; ++i)
        {
            crc = g_crc32Table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
        }

        return ~crc;
    }

    /*
        R_File::decryptWithSeed karşılığı.

        Pseudocode:
            if (!a4) a4 = 1;

            for (i = 0; i < a3; ++i)
            {
                a2[i] = __ROL1__(a2[i], i % 5);
                a2[i] = -85 * a4 - 61 * (a4 / 177) + (a2[i] ^ (6 * (i + 3)));
                a4 = 171 * a4 - 30269 * (a4 / 177);
            }

        Önemli:
            - seed 32-bit signed int gibi davranmalı.
            - C++ signed overflow UB olduğu için int64_t ara işlem kullanıyoruz.
            - Sonuç 32-bit'e wrap ediliyor.
    */
    void decryptWithSeed(
        std::uint8_t* data,
        std::size_t size,
        std::int32_t seed
    )
    {
        if (size == 0)
            return;

        if (seed == 0)
            seed = 1;

        for (std::size_t i = 0; i < size; ++i)
        {
            const unsigned rot = static_cast<unsigned>(i % 5u);
            const std::uint8_t rotated = rol8(data[i], rot);

            const std::int32_t q = seed / 177;

            const std::uint8_t xorKey = static_cast<std::uint8_t>(
                (6u * (static_cast<std::uint32_t>(i) + 3u)) & 0xFFu
            );

            const std::int64_t value =
                -85LL * seed
                - 61LL * q
                + static_cast<std::int64_t>(rotated ^ xorKey);

            data[i] = static_cast<std::uint8_t>(value & 0xFF);

            const std::int64_t nextSeed64 =
                171LL * seed
                - 30269LL * q;

            seed = static_cast<std::int32_t>(
                static_cast<std::uint32_t>(nextSeed64)
            );
        }
    }
}