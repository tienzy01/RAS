// standard crc-32 polynomial
0xEDB88320

// init

0xFFFFFFFF

// final xor

~crc

// header crc check

std::vector<std::uint8_t> tmp = hdr;
storeLe32(tmp.data() + 0x1C, 0);
const std::uint32_t calc = crc32(tmp.data(), tmp.size());