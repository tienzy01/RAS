#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>
#include <array>
#include <filesystem>
#include <stdexcept>
#include <algorithm>

#ifdef _WIN32
#include <cstring>
#else
#include <strings.h>
#endif

namespace ras
{
    namespace fs = std::filesystem;

    static constexpr std::size_t RAS_HEADER_SIZE = 44;

    static constexpr std::array<std::uint8_t, 4> RAS_MAGIC
    {
        {
            static_cast<std::uint8_t>('R'),
            static_cast<std::uint8_t>('A'),
            static_cast<std::uint8_t>('S'),
            static_cast<std::uint8_t>(0)
        }
    };

    static constexpr float RAS_EXPECTED_VERSION = 1.2f;

    static constexpr std::uint32_t RAS_ARCHIVER_ID_MAX_PAYNE = 3;

    // IDA: R_File::CMPHEADER -> "RA->"
    static constexpr std::array<std::uint8_t, 4> RAS_CMPHEADER
    {
        {
            static_cast<std::uint8_t>('R'),
            static_cast<std::uint8_t>('A'),
            static_cast<std::uint8_t>('-'),
            static_cast<std::uint8_t>('>')
        }
    };

    // IDA: R_File::CRYPTHEADER -> "RC->"
    // Not: Bu .ras için değil, ayrı encrypted container gibi görünüyor.
    static constexpr std::array<std::uint8_t, 4> RAS_CRYPTHEADER
    {
        {
            static_cast<std::uint8_t>('R'),
            static_cast<std::uint8_t>('C'),
            static_cast<std::uint8_t>('-'),
            static_cast<std::uint8_t>('>')
        }
    };

    enum class RasMethod : std::uint32_t
    {
        Invalid             = 0,
        Compressed          = 1,
        EncryptedCompressed = 2,
        Stored              = 3
    };

    struct RasTimestamp
    {
        std::uint16_t year;
        std::uint16_t month;
        std::uint16_t dayOfWeek;
        std::uint16_t day;
        std::uint16_t hour;
        std::uint16_t minute;
        std::uint16_t second;
        std::uint16_t milliseconds;
    };

    static_assert(sizeof(RasTimestamp) == 16, "RasTimestamp must be 16 bytes.");

    struct RasArchiveHeader
    {
        std::int32_t  seed = 0;
        std::uint32_t fileCount = 0;
        std::uint32_t dirCount = 0;
        std::uint32_t fileBlobSize = 0;
        std::uint32_t dirBlobSize = 0;
        float         version = 0.0f;
        std::uint32_t headerCrc = 0;
        std::uint32_t fileBlobCrc = 0;
        std::uint32_t dirBlobCrc = 0;
        std::uint32_t archiverId = 0;
    };

    struct RasDirectoryEntry
    {
        std::string   name;       // Full path, trailing backslash: "\data\console\"
        RasTimestamp  timestamp{};
        std::uint32_t id = 0;     // Sequential directory blob index
    };

    struct RasFileEntry
    {
        std::string   name;       // Leaf filename: "file.pcx"
        std::string   key;        // "%05i" + name: "00002file.pcx"

        std::uint32_t dirId = 0;
        std::uint32_t logicalSize = 0;
        std::uint32_t storedSize = 0;
        std::uint32_t unknown2 = 0;
        std::int32_t  seed = 0;
        std::uint32_t method = 0;

        RasTimestamp  timestamp{};
        std::uint64_t offset = 0;
    };

    inline std::uint16_t le16(const std::uint8_t* p) noexcept
    {
        return static_cast<std::uint16_t>(
            static_cast<std::uint16_t>(p[0]) |
            (static_cast<std::uint16_t>(p[1]) << 8)
        );
    }

    inline std::uint32_t le32(const std::uint8_t* p) noexcept
    {
        return static_cast<std::uint32_t>(p[0])
             | (static_cast<std::uint32_t>(p[1]) << 8)
             | (static_cast<std::uint32_t>(p[2]) << 16)
             | (static_cast<std::uint32_t>(p[3]) << 24);
    }

    inline void storeLe32(std::uint8_t* p, std::uint32_t v) noexcept
    {
        p[0] = static_cast<std::uint8_t>(v & 0xFFu);
        p[1] = static_cast<std::uint8_t>((v >> 8) & 0xFFu);
        p[2] = static_cast<std::uint8_t>((v >> 16) & 0xFFu);
        p[3] = static_cast<std::uint8_t>((v >> 24) & 0xFFu);
    }

    inline float leFloat(const std::uint8_t* p) noexcept
    {
        std::uint32_t u = le32(p);
        float f = 0.0f;
        std::memcpy(&f, &u, sizeof(f));
        return f;
    }

    inline int rasStricmp(const char* a, const char* b)
    {
#ifdef _WIN32
        return _stricmp(a, b);
#else
        return strcasecmp(a, b);
#endif
    }

    inline RasTimestamp readTimestamp(const std::uint8_t* p) noexcept
    {
        RasTimestamp t{};
        t.year         = le16(p + 0);
        t.month        = le16(p + 2);
        t.dayOfWeek    = le16(p + 4);
        t.day          = le16(p + 6);
        t.hour         = le16(p + 8);
        t.minute       = le16(p + 10);
        t.second       = le16(p + 12);
        t.milliseconds = le16(p + 14);
        return t;
    }

    /*
        R_File::sub_100126A0 karşılığı.

        Bu gerçek Unix timestamp değildir.
        Remedy'nin kendi pseudo-timestamp hesabıdır.

        Formula:
            second
          + 60 * (
                minute
              + 60 * (
                    hour
                  + 24 * (
                        day
                      + 31 * (
                            month
                          + 12 * year
                        )
                    )
                )
              + 5060224
            )
    */
    inline std::int32_t packTimestamp(const RasTimestamp& t) noexcept
    {
        const std::uint32_t year   = t.year;
        const std::uint32_t month  = t.month;
        const std::uint32_t day    = t.day;
        const std::uint32_t hour   = t.hour;
        const std::uint32_t minute = t.minute;
        const std::uint32_t second = t.second;

        const std::uint32_t days =
            day + 31u * (month + 12u * year);

        const std::uint32_t value =
            second +
            60u * (
                minute +
                60u * (
                    hour +
                    24u * days
                ) +
                5060224u
            );

        return static_cast<std::int32_t>(value);
    }

    inline std::string readZString(
        const std::vector<std::uint8_t>& buf,
        std::size_t& pos
    )
    {
        const std::size_t start = pos;

        while (pos < buf.size() && buf[pos] != 0)
            ++pos;

        if (pos >= buf.size())
            throw std::runtime_error("Null-terminated string not found.");

        std::string s(
            reinterpret_cast<const char*>(&buf[start]),
            pos - start
        );

        ++pos; // null terminator
        return s;
    }

    inline std::uint32_t readU32(
        const std::vector<std::uint8_t>& buf,
        std::size_t& pos
    )
    {
        if (pos + 4 > buf.size())
            throw std::runtime_error("Unexpected end of blob while reading uint32.");

        const std::uint32_t v = le32(buf.data() + pos);
        pos += 4;
        return v;
    }

    inline std::string makeFileKey(std::uint32_t dirId, const std::string& fileName)
    {
        char prefix[16];
        std::snprintf(
            prefix,
            sizeof(prefix),
            "%05i",
            static_cast<int>(dirId)
        );

        std::string key;
        key.reserve(std::strlen(prefix) + fileName.size());
        key += prefix;
        key += fileName;
        return key;
    }

    inline void addSanitizedPathPart(fs::path& rel, const std::string& part)
    {
        if (part.empty() || part == "." || part == "..")
            return;

        std::string clean;
        clean.reserve(part.size());

        for (char ch : part)
        {
            const unsigned char c = static_cast<unsigned char>(ch);

            // Control characters ve Windows geçersiz karakterleri temizle.
            if (
                c < 32 ||
                c == '/' || c == '\\' || c == ':' ||
                c == '*' || c == '?' || c == '"' ||
                c == '<' || c == '>' || c == '|'
            )
            {
                clean.push_back('_');
            }
            else
            {
                clean.push_back(static_cast<char>(c));
            }
        }

        if (clean.empty() || clean == "." || clean == "..")
            clean = "_";

        rel /= fs::path(clean);
    }

    inline fs::path makeExtractionPath(
        const fs::path& outDir,
        const std::string& dirName,
        const std::string& fileName
    )
    {
        fs::path rel;

        auto splitAndAdd = [&](const std::string& s)
        {
            std::string cur;

            for (char ch : s)
            {
                if (ch == '/' || ch == '\\')
                {
                    addSanitizedPathPart(rel, cur);
                    cur.clear();
                }
                else
                {
                    cur.push_back(ch);
                }
            }

            addSanitizedPathPart(rel, cur);
        };

        splitAndAdd(dirName);
        splitAndAdd(fileName);

        return outDir / rel;
    }

} // namespace ras