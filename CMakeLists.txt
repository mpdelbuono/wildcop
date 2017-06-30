# Preamble
cmake_minimum_required(VERSION 3.7)
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# We need LLVM against which to build. Require 4.0.
set(LLVM_ROOT_DIR ""
    CACHE "PATH" "Path to LLVM installation directory")
set(LLVM_FIND_VERSION "4.0.0")
find_package(LLVM REQUIRED)