# Intro

A C++20 reimplementation and analysis tool for Remedy's Archive System (RAS), originally used by **Max Payne**.

The project aims to reproduce the RAS filesystem and binary layout as closely as possible while providing tools for inspecting, auditing, and extracting archives.

## Features

- RAS archive parsing
- Header and metadata inspection
- File and directory listing
- File extraction
- CRC verification
- Encryption/decryption support
- LZSS decompression
- Game-compatible entry sorting
- Archive structure auditing
- Archiver ID validation
- Padding validation

## Usage

```text
ras_tool <archive.ras> [info]
ras_tool <archive.ras> list [count]
ras_tool <archive.ras> extract <output_dir>
ras_tool <archive.ras> audit
```

## Options

```text
--no-crc              Disable CRC verification.
--sort                Sort entries like the game loader.
--require-archiver    Require archiver ID == 3.
--strict-padding      Validate archive padding.
```

## Examples

Inspect an archive:

```bash
ras_tool x_data.ras info
```

List files:

```bash
ras_tool x_data.ras list 100
```

Extract an archive:

```bash
ras_tool x_data.ras extract extracted/
```

Audit an archive:

```bash
ras_tool x_data.ras audit
```

## Building

Requirements:

- CMake 3.20+
- C++20 compiler

```bash
cmake -S . -B build
cmake --build build --config Release
```

The executable is placed in:

```text
build/bin/
```

## Project Structure

```text
src/
├── ras_main.cpp
├── ras_archive.cpp
├── ras_archive.hpp
├── ras_common.hpp
├── ras_crypto.cpp
├── ras_crypto.hpp
├── ras_lzss.cpp
└── ras_lzss.hpp
```

## Goal

The main goal is **1:1 reimplementation of the Remedy Archive System**, including its filesystem behavior and binary layout.

The format is being reconstructed through reverse engineering of the original Remedy implementation and existing RAS archives.

## Status

Work in progress.

Some fields and behaviors are still being reverse-engineered.

## License

Independent reverse-engineering project. Not affiliated with or endorsed by Remedy Entertainment.