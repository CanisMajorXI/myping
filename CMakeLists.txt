cmake_minimum_required(VERSION 3.8)
project(myping)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES main.c checksum.h cmake-build-debug/checksum.c checksum.c)
add_executable(myping ${SOURCE_FILES})