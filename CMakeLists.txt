cmake_minimum_required(VERSION 3.13.4)
project(ConstantTimePass)

set(CMAKE_CXX_STANDARD 17)

# Find LLVM package
find_package(LLVM REQUIRED CONFIG)

# TELL IT WHERE YOUR HEADER FILES ARE:
include_directories(${CMAKE_SOURCE_DIR}/include)

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

# Tell LLVM what we want to compile
add_executable(labeller_test 
    src/labeller_test.cpp 
    src/SecrecyLabeller.cpp
)

# Link LLVM libraries required for IR parsing
llvm_map_components_to_libnames(llvm_libs support core irreader)
target_link_libraries(labeller_test PRIVATE ${llvm_libs})