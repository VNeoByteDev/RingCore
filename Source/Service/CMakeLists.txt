cmake_minimum_required(VERSION 3.20)
project(RingCoreSvc VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SOURCES
    ServiceMain.cpp
    ServiceCore.cpp
)

set(HEADERS
    ServiceCore.h
)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

target_link_libraries(${PROJECT_NAME} PRIVATE advapi32)

set_target_properties(${PROJECT_NAME} PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded"
)

install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
)
