A C++20 reimplementation and analysis tool for Remedy's Archive System (RAS), originally used by Max Payne.

The project aims to reproduce the RAS filesystem and binary layout as closely as possible while providing tooling for inspecting, auditing, and extracting archives.

Features
RAS archive parsing
Header and metadata inspection
File and directory listing
File extraction
CRC verification
RAS encryption/decryption support
LZSS decompression
Game-compatible entry sorting
Archive structure auditing
Archiver ID validation
Padding validation
Usage
ras_tool <archive.ras> [info]
ras_tool <archive.ras> list [count]
ras_tool <archive.ras> extract <output_dir>
ras_tool <archive.ras> audit
Options
--no-crc
--sort
--require-archiver
--strict-padding
Examples

Inspect an archive:

ras_tool x_data.ras info

List files:

ras_tool x_data.ras list 100

Extract an archive:

ras_tool x_data.ras extract extracted/

Run an archive audit:

ras_tool x_data.ras audit
Building

Requirements:

CMake 3.20+
C++20 compiler

Build with CMake:

cmake -S . -B build
cmake --build build --config Release

The executable is placed in:

build/bin/
Project Structure
src/
├── ras_main.cpp
├── ras_archive.cpp
├── ras_archive.hpp
├── ras_common.hpp
├── ras_crypto.cpp
├── ras_crypto.hpp
├── ras_lzss.cpp
└── ras_lzss.hpp
Goal

This is primarily a reverse-engineering and reimplementation project.

The main goal is binary compatibility with the original Remedy Archive System: understanding the format, reproducing its filesystem behavior, and eventually generating archives that match the original implementation as closely as possible.

Status

Work in progress.

The format is being reconstructed from the original game binaries and RAS archives. Some fields and behaviors may still be under investigation.

License

This project is an independent reverse-engineering effort and is not affiliated with or endorsed by Remedy Entertainment.