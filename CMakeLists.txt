# Preamble
cmake_minimum_required(VERSION 3.7)
cmake_policy(SET CMP0048 NEW) # project() VERSION manages VERSION variables
project("Wildcop" 
    VERSION 0.1.0
    LANGUAGES CXX)
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# We need LLVM against which to build. Require 4.0.
set(LLVM_ROOT_DIR ""
    CACHE "PATH" "Path to LLVM installation directory")
set(LLVM_FIND_VERSION "4.0.0")
find_package(LLVM REQUIRED)

# Use the cmake exports so that we can properly include transitive dependencies
# This way, we can link to clangAST without explicitly specifying all of its dependencies
find_package(Clang REQUIRED CONFIG
    PATHS "${LLVM_ROOT_DIR}/lib/cmake/"
    NO_DEFAULT_PATH)

# Build wildcop 
add_subdirectory(src)

# Tests are optional
option(RUN_TESTS "Run Wildcop tests after build" ON)
if (${RUN_TESTS})
    enable_testing()
	add_subdirectory(tests)
endif()