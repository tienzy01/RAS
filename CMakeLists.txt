cmake_minimum_required(VERSION 3.20)

project(RasTool
    VERSION 0.1.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(ras_tool
    src/ras_main.cpp
    src/ras_archive.cpp
    src/ras_crypto.cpp
    src/ras_lzss.cpp

    src/ras_common.hpp
    src/ras_archive.hpp
    src/ras_crypto.hpp
    src/ras_lzss.hpp
)

target_include_directories(ras_tool
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

if (MSVC)
    target_compile_options(ras_tool PRIVATE
        /W4
        /permissive-
        /EHsc
    )
else()
    target_compile_options(ras_tool PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()

set_target_properties(ras_tool PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

if (MSVC)
    set_target_properties(ras_tool PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin"
        RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/bin"
        RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/bin"
    )
endif()
