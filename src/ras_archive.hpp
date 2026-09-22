#pragma once

#include "ras_common.hpp"

#include <iosfwd>

namespace ras
{
    class RasArchive
    {
    public:
        struct Options
        {
            bool verifyCrc = true;
            bool requireVersion = true;
            bool requireArchiverId = false;
            bool strictPadding = false;
            bool sortByGameOrder = false;
        };

        void open(const fs::path &path, const Options &options = {});

        const RasArchiveHeader &header() const noexcept { return header_; }
        const std::vector<RasDirectoryEntry> &directories() const noexcept { return dirs_; }
        const std::vector<RasFileEntry> &files() const noexcept { return files_; }

        std::uint64_t dataStart() const noexcept { return dataStart_; }
        std::uint64_t fileSize() const noexcept { return fileSize_; }
        std::uint64_t totalStored() const noexcept { return totalStored_; }
        std::int64_t padding() const noexcept { return padding_; }

        std::vector<std::uint8_t> readRawFile(const RasFileEntry &f) const;
        std::vector<std::uint8_t> readFile(const RasFileEntry &f) const;

        void extractAll(const fs::path &outDir) const;

    private:
        fs::path path_;
        RasArchiveHeader header_{};
        std::vector<RasDirectoryEntry> dirs_;
        std::vector<RasFileEntry> files_;

        std::uint64_t dataStart_ = 0;
        std::uint64_t fileSize_ = 0;
        std::uint64_t totalStored_ = 0;
        std::int64_t padding_ = 0;

        static void readExact(std::istream &in, std::uint8_t *dst, std::size_t n);

        void parseDirectories(const std::vector<std::uint8_t> &blob);
        void parseFiles(const std::vector<std::uint8_t> &blob);

        std::vector<std::uint8_t> readFileData(
            const RasFileEntry &f,
            std::istream &in) const;

        std::vector<std::uint8_t> decodeFileData(
            const RasFileEntry &f,
            std::vector<std::uint8_t> raw) const;

        static void fitToSize(std::vector<std::uint8_t> &v, std::size_t n);
    };
}