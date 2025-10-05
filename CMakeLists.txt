cmake_minimum_required(VERSION 3.20)
project(EncryptedVectorSimilarity)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# OpenFHE paths
set(OpenFHE_ROOT "c:/Users/Deepak/openfhe-development")
set(OpenFHE_INCLUDE_DIRS 
    "${OpenFHE_ROOT}/src/pke/include" 
    "${OpenFHE_ROOT}/src/core/include" 
    "${OpenFHE_ROOT}/src/binfhe/include"
    "${OpenFHE_ROOT}/build/src/core"  # For config_core.h
    "${OpenFHE_ROOT}/build/src/pke"   # For config_pke.h
    "${OpenFHE_ROOT}/build/src/binfhe" # For config_binfhe.h
    "${OpenFHE_ROOT}/third-party/cereal/include"  # For cereal library
)

# Find OpenFHE libraries
find_library(OPENFHE_PKE_LIB 
    NAMES libOPENFHEpke.dll.a
    PATHS "${OpenFHE_ROOT}/build/lib"
    NO_DEFAULT_PATH
)

find_library(OPENFHE_CORE_LIB 
    NAMES libOPENFHEcore.dll.a
    PATHS "${OpenFHE_ROOT}/build/lib"
    NO_DEFAULT_PATH
)

find_library(OPENFHE_BINFHE_LIB 
    NAMES libOPENFHEbinfhe.dll.a
    PATHS "${OpenFHE_ROOT}/build/lib"
    NO_DEFAULT_PATH
)

# Check if libraries were found
if(NOT OPENFHE_PKE_LIB)
    message(FATAL_ERROR "Could not find OpenFHE PKE library. Please check the path: ${OpenFHE_ROOT}/build/lib")
endif()

if(NOT OPENFHE_CORE_LIB)
    message(FATAL_ERROR "Could not find OpenFHE Core library. Please check the path: ${OpenFHE_ROOT}/build/lib")
endif()

if(NOT OPENFHE_BINFHE_LIB)
    message(FATAL_ERROR "Could not find OpenFHE BinFHE library. Please check the path: ${OpenFHE_ROOT}/build/lib")
endif()

message(STATUS "Found OpenFHE PKE library: ${OPENFHE_PKE_LIB}")
message(STATUS "Found OpenFHE Core library: ${OPENFHE_CORE_LIB}")
message(STATUS "Found OpenFHE BinFHE library: ${OPENFHE_BINFHE_LIB}")

# Include directories
include_directories(include)
include_directories(${OpenFHE_INCLUDE_DIRS})

# Add OpenFHE definitions
add_definitions(-DOPENFHE_AVAILABLE)
add_definitions(-DBUILTIN_INFO_AVAILABLE)
add_definitions(-DPARALLEL)
add_definitions(-DMATHBACKEND=4)
add_definitions(-DOPENFHE_VERSION=1.4.0)

# Source files
set(SOURCES
    src/main.cpp
)

# Create main executable
add_executable(encrypted_similarity ${SOURCES})

# Link libraries for all executables
set(OPENFHE_LIBS
    ${OPENFHE_PKE_LIB}
    ${OPENFHE_CORE_LIB}
    ${OPENFHE_BINFHE_LIB}
)

# Add OpenMP for parallel processing
find_package(OpenMP REQUIRED)

# Link all executables
target_link_libraries(encrypted_similarity ${OPENFHE_LIBS} OpenMP::OpenMP_CXX)

# Create data directory for runtime data
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/data)
