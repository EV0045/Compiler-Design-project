<<<<<<< Updated upstream
cmake_minimum_required(VERSION 3.13.4)
project(ConstantTimePass LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(LLVM REQUIRED CONFIG)
include_directories(${CMAKE_SOURCE_DIR}/include ${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})
llvm_map_components_to_libnames(LLVM_LIBS support core irreader)
add_executable(labeller_test src/labeller_test.cpp src/SecrecyLabeller.cpp)
target_link_libraries(labeller_test PRIVATE ${LLVM_LIBS})
add_executable(member3_pipeline src/member3_pipeline.cpp src/TaintEngine.cpp src/SecrecyLabeller.cpp src/ViolationDetector.cpp)
target_link_libraries(member3_pipeline PRIVATE ${LLVM_LIBS})
add_executable(test_taint_engine tests/test_taint_engine.cpp src/TaintEngine.cpp src/ViolationDetector.cpp)
target_link_libraries(test_taint_engine PRIVATE ${LLVM_LIBS})
=======
cmake_minimum_required(VERSION 3.20)

project(ConstantTimePass LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(LLVM REQUIRED CONFIG)
llvm_map_components_to_libnames(LLVM_LIBS
    Core
    Support
    IRReader
    Analysis
)
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

target_link_libraries(ConstantTimePass PRIVATE ${LLVM_LIBS})

add_executable(labeller_test
    src/labeller_test.cpp
    src/SecrecyLabeller.cpp
)

target_include_directories(labeller_test
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(labeller_test
    PRIVATE
    ${LLVM_LIBS}
)

add_executable(member3_pipeline
    src/member3_pipeline.cpp
    src/SecrecyLabeller.cpp
    src/TaintEngine.cpp
    src/ViolationDetector.cpp
)

target_include_directories(member3_pipeline
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(member3_pipeline
    PRIVATE
    ${LLVM_LIBS}
)

add_executable(test_taint_engine
    tests/test_taint_engine.cpp
    src/TaintEngine.cpp
    src/ViolationDetector.cpp
)

target_include_directories(test_taint_engine
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(test_taint_engine
    PRIVATE
    ${LLVM_LIBS}
)

enable_testing()
add_test(NAME taint_engine_cpp COMMAND test_taint_engine)
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
    add_test(NAME taint_engine_python
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_taint_engine.py)
endif()
>>>>>>> Stashed changes
