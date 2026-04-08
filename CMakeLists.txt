cmake_minimum_required(VERSION 3.12)
project(certainly C)

# C99 standard — Retro68's GCC 12 supports this fully
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler warnings
add_compile_options(-Wall -Wextra -Wno-unused-parameter)

# BearSSL
add_subdirectory(bearssl)

# Examples
add_subdirectory(examples/hello_toolbox)
