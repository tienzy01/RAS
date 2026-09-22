#include "ras_archive.hpp"
#include "ras_crypto.hpp"
#include "ras_lzss.hpp"

#include <fstream>
#include <cmath>
#include <utility>

namespace ras
{
    void RasArchive::readExact(std::istream &in, std::uint8_t *dst, std::size_t n)
    {
        if (n == 0)
            return;

        in.read(
            reinterpret_cast<char *>(dst),
            static_cast<std::streamsize>(n));

        if (static_cast<std::size_t>(in.gcount()) != n)
            throw std::runtime_error("Unexpected EOF while reading file.");
    }

    void RasArchive::fitToSize(std::vector<std::uint8_t> &v, std::size_t n)
    {
        if (v.size() < n)
            v.resize(n, 0);
        else if (v.size() > n)
            v.resize(n);
    }

    void RasArchive::open(const fs::path &path, const Options &options)
    {
        path_ = path;

        std::ifstream in(path_, std::ios::binary);
        if (!in)
            throw std::runtime_error("Cannot open archive: " + path_.string());

        std::vector<std::uint8_t> hdr(RAS_HEADER_SIZE);
        readExact(in, hdr.data(), hdr.size());

        if (std::memcmp(hdr.data(), RAS_MAGIC.data(), RAS_MAGIC.size()) != 0)
            throw std::runtime_error("Bad RAS magic.");

        const std::int32_t seed =
            static_cast<std::int32_t>(le32(hdr.data() + 4));

                decryptWithSeed(hdr.data() + 8, 36, seed);

        header_.seed = seed;
        header_.fileCount = le32(hdr.data() + 0x08);
        header_.dirCount = le32(hdr.data() + 0x0C);
        header_.fileBlobSize = le32(hdr.data() + 0x10);
        header_.dirBlobSize = le32(hdr.data() + 0x14);
        header_.version = leFloat(hdr.data() + 0x18);
        header_.headerCrc = le32(hdr.data() + 0x1C);
        header_.fileBlobCrc = le32(hdr.data() + 0x20);
        header_.dirBlobCrc = le32(hdr.data() + 0x24);
        header_.archiverId = le32(hdr.data() + 0x28);

        if (options.requireVersion)
        {
            if (std::fabs(header_.version - RAS_EXPECTED_VERSION) > 1e-5f)
            {
                throw std::runtime_error(
                    "Unsupported archive version: " +
                    std::to_string(header_.version));
            }
        }

        if (options.requireArchiverId &&
            header_.archiverId != RAS_ARCHIVER_ID_MAX_PAYNE)
        {
            throw std::runtime_error("Unexpected archiver ID.");
        }

        if (options.verifyCrc)
        {
            std::vector<std::uint8_t> tmp = hdr;
            storeLe32(tmp.data() + 0x1C, 0);

            const std::uint32_t calc = crc32(tmp.data(), tmp.size());

            if (calc != header_.headerCrc)
            {
                throw std::runtime_error(
                    "Header CRC failed. stored=0x" +
                    [&]
                    { char b[16]; std::snprintf(b, sizeof(b), "%08X", header_.headerCrc); return std::string(b); }() +
                    " calc=0x" +
                    [&]
                    { char b[16]; std::snprintf(b, sizeof(b), "%08X", calc); return std::string(b); }());
            }
        }

        std::vector<std::uint8_t> fileBlob(header_.fileBlobSize);
        if (!fileBlob.empty())
        {
            readExact(in, fileBlob.data(), fileBlob.size());
            decryptWithSeed(fileBlob.data(), fileBlob.size(), seed);

            if (options.verifyCrc)
            {
                const std::uint32_t calc = crc32(fileBlob.data(), fileBlob.size());

                if (calc != header_.fileBlobCrc)
                    throw std::runtime_error("File blob CRC failed.");
            }
        }
        else if (options.verifyCrc && header_.fileBlobCrc != 0)
        {
            throw std::runtime_error("Empty file blob but CRC non-zero.");
        }

        std::vector<std::uint8_t> dirBlob(header_.dirBlobSize);
        if (!dirBlob.empty())
        {
            readExact(in, dirBlob.data(), dirBlob.size());
            decryptWithSeed(dirBlob.data(), dirBlob.size(), seed);

            if (options.verifyCrc)
            {
                const std::uint32_t calc = crc32(dirBlob.data(), dirBlob.size());

                if (calc != header_.dirBlobCrc)
                    throw std::runtime_error("Directory blob CRC failed.");
            }
        }
        else if (options.verifyCrc && header_.dirBlobCrc != 0)
        {
            throw std::runtime_error("Empty directory blob but CRC non-zero.");
        }

        dataStart_ =
            static_cast<std::uint64_t>(RAS_HEADER_SIZE) +
            static_cast<std::uint64_t>(header_.fileBlobSize) +
            static_cast<std::uint64_t>(header_.dirBlobSize);

        parseDirectories(dirBlob);
        parseFiles(fileBlob);

        fileSize_ = static_cast<std::uint64_t>(fs::file_size(path_));

        const std::uint64_t endOffset =
            dataStart_ + totalStored_;

        padding_ =
            static_cast<std::int64_t>(fileSize_) -
            static_cast<std::int64_t>(endOffset);

        if (options.strictPadding && padding_ != 0)
        {
            throw std::runtime_error(
                "Unexpected archive padding: " + std::to_string(padding_));
        }

        if (options.sortByGameOrder)
        {
            std::sort(
                dirs_.begin(),
                dirs_.end(),
                [](const RasDirectoryEntry &a, const RasDirectoryEntry &b)
                {
                    return rasStricmp(a.name.c_str(), b.name.c_str()) < 0;
                });

            std::sort(
                files_.begin(),
                files_.end(),
                [](const RasFileEntry &a, const RasFileEntry &b)
                {
                    return rasStricmp(a.key.c_str(), b.key.c_str()) < 0;
                });
        }
    }

    void RasArchive::parseDirectories(const std::vector<std::uint8_t> &blob)
    {
        dirs_.clear();
        dirs_.reserve(header_.dirCount);

        std::size_t pos = 0;

        for (std::uint32_t i = 0; i < header_.dirCount; ++i)
        {
            RasDirectoryEntry d;
            d.id = i;
            d.name = readZString(blob, pos);

            if (pos + 16 > blob.size())
                throw std::runtime_error("Directory timestamp out of bounds.");

            d.timestamp = readTimestamp(blob.data() + pos);
            pos += 16;

            dirs_.push_back(std::move(d));
        }
    }

    void RasArchive::parseFiles(const std::vector<std::uint8_t> &blob)
    {
        files_.clear();
        files_.reserve(header_.fileCount);

        std::size_t pos = 0;
        std::uint64_t runningOffset = dataStart_;

        for (std::uint32_t i = 0; i < header_.fileCount; ++i)
        {
            RasFileEntry f;

            f.name = readZString(blob, pos);

            if (pos + 40 > blob.size())
                throw std::runtime_error("File fixed record out of bounds.");

            const std::uint8_t *rec = blob.data() + pos;
            pos += 40;

            f.logicalSize = le32(rec + 0);
            f.storedSize = le32(rec + 4);
            f.unknown2 = le32(rec + 8);
            f.dirId = le32(rec + 12);
            f.seed = static_cast<std::int32_t>(le32(rec + 16));
            f.method = le32(rec + 20);
            f.timestamp = readTimestamp(rec + 24);

            f.key = makeFileKey(f.dirId, f.name);
            f.offset = runningOffset;

            runningOffset += static_cast<std::uint64_t>(f.storedSize);

            files_.push_back(std::move(f));
        }

        totalStored_ = runningOffset - dataStart_;
    }

    std::vector<std::uint8_t> RasArchive::readRawFile(const RasFileEntry &f) const
    {
        std::ifstream in(path_, std::ios::binary);
        if (!in)
            throw std::runtime_error("Cannot reopen archive for raw read.");

        in.seekg(
            static_cast<std::streamoff>(f.offset),
            std::ios::beg);

        std::vector<std::uint8_t> raw(f.storedSize);
        readExact(in, raw.data(), raw.size());

        return raw;
    }

    std::vector<std::uint8_t> RasArchive::readFile(const RasFileEntry &f) const
    {
        std::ifstream in(path_, std::ios::binary);
        if (!in)
            throw std::runtime_error("Cannot reopen archive for read.");

        return readFileData(f, in);
    }

    std::vector<std::uint8_t> RasArchive::readFileData(
        const RasFileEntry &f,
        std::istream &in) const
    {
        in.seekg(
            static_cast<std::streamoff>(f.offset),
            std::ios::beg);

        std::vector<std::uint8_t> raw(f.storedSize);
        readExact(in, raw.data(), raw.size());

        return decodeFileData(f, std::move(raw));
    }

    std::vector<std::uint8_t> RasArchive::decodeFileData(
        const RasFileEntry &f,
        std::vector<std::uint8_t> raw) const
    {
        switch (f.method)
        {
        case static_cast<std::uint32_t>(RasMethod::Invalid):
            throw std::runtime_error(
                "Invalid method 0 in file entry: " + f.name);

        case static_cast<std::uint32_t>(RasMethod::Compressed):
        {
            std::vector<std::uint8_t> out =
                lzssDecompress(raw.data(), raw.size(), f.logicalSize);

            fitToSize(out, f.logicalSize);
            return out;
        }

        case static_cast<std::uint32_t>(RasMethod::EncryptedCompressed):
        {
            decryptWithSeed(raw.data(), raw.size(), f.seed);

            std::vector<std::uint8_t> out =
                lzssDecompress(raw.data(), raw.size(), f.logicalSize);

            fitToSize(out, f.logicalSize);
            return out;
        }

        case static_cast<std::uint32_t>(RasMethod::Stored):
        {
            fitToSize(raw, f.logicalSize);
            return raw;
        }

        default:
            throw std::runtime_error(
                "Unknown file method: " + std::to_string(f.method));
        }
    }

    void RasArchive::extractAll(const fs::path &outDir) const
    {
        fs::create_directories(outDir);

        std::ifstream in(path_, std::ios::binary);
        if (!in)
            throw std::runtime_error("Cannot open archive for extraction.");

        std::vector<std::string> dirNameById(header_.dirCount);

        for (const RasDirectoryEntry &d : dirs_)
        {
            if (d.id < dirNameById.size())
                dirNameById[d.id] = d.name;
        }

        for (std::size_t idx = 0; idx < files_.size(); ++idx)
        {
            const RasFileEntry &f = files_[idx];

            std::string dirName;

            if (f.dirId < dirNameById.size())
                dirName = dirNameById[f.dirId];
            else
                dirName = "DIR_" + std::to_string(f.dirId);

            fs::path target = makeExtractionPath(outDir, dirName, f.name);

            if (target == outDir)
            {
                target = outDir / ("unnamed_" + std::to_string(idx));
            }

            if (!target.parent_path().empty())
                fs::create_directories(target.parent_path());

            std::vector<std::uint8_t> data = readFileData(f, in);

            std::ofstream o(target, std::ios::binary);
            if (!o)
                throw std::runtime_error("Cannot create output file: " + target.string());

            if (!data.empty())
            {
                o.write(
                    reinterpret_cast<const char *>(data.data()),
                    static_cast<std::streamsize>(data.size()));
            }
        }
    }
}