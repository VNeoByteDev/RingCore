cmake_minimum_required(VERSION 3.20)
project(RingCoreShellExt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SOURCES
    ShellExt.cpp
    ShellExt.def
)

add_library(${PROJECT_NAME} SHARED ${SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE .)

# Set output name without 'lib' prefix
set_target_properties(${PROJECT_NAME} PROPERTIES
    PREFIX ""
    SUFFIX ".dll"
    OUTPUT_NAME "RingCoreShellExt"
)

target_link_libraries(${PROJECT_NAME} PRIVATE ole32 shell32 uuid)
