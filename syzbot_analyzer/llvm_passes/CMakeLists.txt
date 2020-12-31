cmake_minimum_required(VERSION 3.4)

set(ENV{LLVM_DIR} /home/xzou017/tools/llvm-project/build/lib/cmake/llvm)

message(STATUS ${LLVM_DIR})

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(LLVM REQUIRED CONFIG)

add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})

add_subdirectory(generateInput)