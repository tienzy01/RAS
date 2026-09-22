#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>

namespace ras
{
    /*
        R_File::decompress

        Compressed block format:
            +0x00 4 byte  CMPHEADER, currently "RA->"
            +0x04 uint32  uncompressed size
            +0x08 uint32  compressed payload size
            +0x0C payload

        expectedSize == 0 means "use the uncompressed size from the header".
    */
    std::vector<std::uint8_t> lzssDecompress(
        const std::uint8_t* input,
        std::size_t inputSize,
        std::size_t expectedSize = 0
    );
}