#include "ras_archive.hpp"

#include <cstdio>
#include <string>
#include <vector>
#include <array>
#include <algorithm>

using namespace ras;

namespace
{
    void printUsage(const char* exe)
    {
        std::printf(
            "Usage:\n"
            "  %s <archive.ras> [info]\n"
            "  %s <archive.ras> list [count]\n"
            "  %s <archive.ras> extract <output_dir>\n"
            "  %s <archive.ras> audit\n"
            "\n"
            "Options:\n"
            "  --no-crc              Disable CRC verification.\n"
            "  --sort                Sort entries like game loader for search compatibility.\n"
            "  --require-archiver    Require archiver ID == 3.\n"
            "  --strict-padding      Fail if fileSize != dataStart + sum(storedSize).\n",
            exe, exe, exe, exe
        );
    }

    std::string directoryNameById(const RasArchive& archive, std::uint32_t id)
    {
        for (const RasDirectoryEntry& d : archive.directories())
        {
            if (d.id == id)
                return d.name;
        }

        return "DIR_" + std::to_string(id);
    }

    bool hasNonAscii(const std::string& s)
    {
        for (char ch : s)
        {
            if (static_cast<unsigned char>(ch) > 127)
                return true;
        }

        return false;
    }

    void printInfo(const RasArchive& archive)
    {
        const auto& h = archive.header();

        std::printf("Archive: %s\n", archive.files().empty() ? "" : "");
        std::printf("magic        : RAS\\0\n");
        std::printf("seed         : 0x%08X\n", static_cast<std::uint32_t>(h.seed));
        std::printf("fileCount    : %u\n", h.fileCount);
        std::printf("dirCount     : %u\n", h.dirCount);
        std::printf("fileBlobSize : %u (0x%X)\n", h.fileBlobSize, h.fileBlobSize);
        std::printf("dirBlobSize  : %u (0x%X)\n", h.dirBlobSize, h.dirBlobSize);
        std::printf("version      : %.7f\n", h.version);
        std::printf("headerCRC    : 0x%08X\n", h.headerCrc);
        std::printf("fileBlobCRC  : 0x%08X\n", h.fileBlobCrc);
        std::printf("dirBlobCRC   : 0x%08X\n", h.dirBlobCrc);
        std::printf("archiverID   : 0x%08X\n", h.archiverId);
        std::printf("CMPHEADER    : %c%c%c%c\n",
            static_cast<char>(RAS_CMPHEADER[0]),
            static_cast<char>(RAS_CMPHEADER[1]),
            static_cast<char>(RAS_CMPHEADER[2]),
            static_cast<char>(RAS_CMPHEADER[3])
        );
        std::printf("dataStart    : 0x%llX\n",
            static_cast<unsigned long long>(archive.dataStart())
        );
        std::printf("fileSize     : 0x%llX (%llu bytes)\n",
            static_cast<unsigned long long>(archive.fileSize()),
            static_cast<unsigned long long>(archive.fileSize())
        );
        std::printf("totalStored  : %llu bytes\n",
            static_cast<unsigned long long>(archive.totalStored())
        );
        std::printf("padding      : %lld bytes\n",
            static_cast<long long>(archive.padding())
        );
    }

    void printList(const RasArchive& archive, std::size_t limit)
    {
        const std::size_t n = std::min(archive.files().size(), limit);

        std::printf("\nFirst %zu files:\n", n);

        for (std::size_t i = 0; i < n; ++i)
        {
            const RasFileEntry& f = archive.files()[i];
            const std::string dir = directoryNameById(archive, f.dirId);

            std::printf(
                "%05u m=%u stored=%10u logical=%10u offset=0x%08llX %s%s\n",
                f.dirId,
                f.method,
                f.storedSize,
                f.logicalSize,
                static_cast<unsigned long long>(f.offset),
                dir.c_str(),
                f.name.c_str()
            );
        }

        if (archive.files().size() > limit)
        {
            std::printf(
                "... %zu more entries\n",
                archive.files().size() - limit
            );
        }
    }

    void printAudit(const RasArchive& archive)
    {
        std::array<std::uint64_t, 4> methodCount{};
        std::uint64_t otherMethodCount = 0;

        std::uint64_t unknown2NonZero = 0;
        std::uint64_t nonAsciiFileNames = 0;
        std::uint64_t nonAsciiDirNames = 0;

        std::uint64_t seedNonZeroForMethod3 = 0;
        std::uint64_t seedZeroForMethod2 = 0;

        for (const RasFileEntry& f : archive.files())
        {
            if (f.method < methodCount.size())
                ++methodCount[f.method];
            else
                ++otherMethodCount;

            if (f.unknown2 != 0)
                ++unknown2NonZero;

            if (hasNonAscii(f.name))
                ++nonAsciiFileNames;

            if (f.method == static_cast<std::uint32_t>(RasMethod::Stored) && f.seed != 0)
                ++seedNonZeroForMethod3;

            if (f.method == static_cast<std::uint32_t>(RasMethod::EncryptedCompressed) && f.seed == 0)
                ++seedZeroForMethod2;
        }

        for (const RasDirectoryEntry& d : archive.directories())
        {
            if (hasNonAscii(d.name))
                ++nonAsciiDirNames;
        }

        std::printf("\n[AUDIT]\n");
        std::printf("method 0 : %llu\n", static_cast<unsigned long long>(methodCount[0]));
        std::printf("method 1 : %llu\n", static_cast<unsigned long long>(methodCount[1]));
        std::printf("method 2 : %llu\n", static_cast<unsigned long long>(methodCount[2]));
        std::printf("method 3 : %llu\n", static_cast<unsigned long long>(methodCount[3]));
        std::printf("method other : %llu\n", static_cast<unsigned long long>(otherMethodCount));

        std::printf("unknown2 nonzero : %llu\n", static_cast<unsigned long long>(unknown2NonZero));
        std::printf("non-ASCII file names : %llu\n", static_cast<unsigned long long>(nonAsciiFileNames));
        std::printf("non-ASCII dir names  : %llu\n", static_cast<unsigned long long>(nonAsciiDirNames));

        std::printf("method 3 with nonzero seed : %llu\n", static_cast<unsigned long long>(seedNonZeroForMethod3));
        std::printf("method 2 with zero seed    : %llu\n", static_cast<unsigned long long>(seedZeroForMethod2));

        std::printf("\nFirst directories:\n");
        const std::size_t dirLimit = std::min<std::size_t>(archive.directories().size(), 20);

        for (std::size_t i = 0; i < dirLimit; ++i)
        {
            const RasDirectoryEntry& d = archive.directories()[i];

            std::printf(
                "%05u %s  ts=%04u-%02u-%02u %02u:%02u:%02u.%03u\n",
                d.id,
                d.name.c_str(),
                d.timestamp.year,
                d.timestamp.month,
                d.timestamp.day,
                d.timestamp.hour,
                d.timestamp.minute,
                d.timestamp.second,
                d.timestamp.milliseconds
            );
        }
    }
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        printUsage(argv[0]);
        return 1;
    }

    std::vector<std::string> positional;
    RasArchive::Options options;

    for (int i = 1; i < argc; ++i)
    {
        const std::string a = argv[i];

        if (a == "--no-crc")
        {
            options.verifyCrc = false;
        }
        else if (a == "--sort")
        {
            options.sortByGameOrder = true;
        }
        else if (a == "--require-archiver")
        {
            options.requireArchiverId = true;
        }
        else if (a == "--strict-padding")
        {
            options.strictPadding = true;
        }
        else
        {
            positional.push_back(a);
        }
    }

    if (positional.empty())
    {
        printUsage(argv[0]);
        return 1;
    }

    const fs::path archivePath = positional[0];

    std::string command = "info";
    std::string commandArg;

    if (positional.size() >= 2)
        command = positional[1];

    if (positional.size() >= 3)
        commandArg = positional[2];

    try
    {
        RasArchive archive;
        archive.open(archivePath, options);

        if (command == "info")
        {
            printInfo(archive);
        }
        else if (command == "list")
        {
            printInfo(archive);

            std::size_t limit = 50;

            if (!commandArg.empty())
            {
                try
                {
                    limit = static_cast<std::size_t>(std::stoull(commandArg));
                }
                catch (...)
                {
                    std::printf("Invalid list count: %s\n", commandArg.c_str());
                }
            }

            printList(archive, limit);
        }
        else if (command == "extract")
        {
            if (commandArg.empty())
            {
                std::printf("extract command needs output directory.\n");
                return 1;
            }

            archive.extractAll(commandArg);
            std::printf("Extracted %zu files to: %s\n",
                archive.files().size(),
                commandArg.c_str()
            );
        }
        else if (command == "audit")
        {
            printInfo(archive);
            printAudit(archive);
        }
        else
        {
            std::printf("Unknown command: %s\n", command.c_str());
            printUsage(argv[0]);
            return 1;
        }
    }
    catch (const std::exception& ex)
    {
        std::printf("Error: %s\n", ex.what());
        return 2;
    }

    return 0;
}