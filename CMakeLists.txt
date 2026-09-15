cmake_minimum_required(VERSION 3.20)

project(ConstantTimePass LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_VERSION}")
message(STATUS "LLVM_DIR: ${LLVM_DIR}")

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

add_library(ConstantTimePass MODULE
    src/PassRegistration.cpp
    src/SecrecyLabeller.cpp
    src/TaintEngine.cpp
    src/ViolationDetector.cpp
    src/ConstantTimeTransformer.cpp
)

target_include_directories(ConstantTimePass
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
