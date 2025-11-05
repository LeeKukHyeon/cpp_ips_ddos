cmake_minimum_required(VERSION 3.16)
project(cpp-ips-ddos)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_BUILD_TYPE Release)

find_package(Pcap REQUIRED)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

file(GLOB SRC
    src/main.cpp
    src/capture/*.cpp
    src/parser/*.cpp
    src/engine/*.cpp
    src/logger/*.cpp
    src/utils/*.cpp
)

add_executable(cpp-ips-ddos ${SRC})
target_link_libraries(cpp-ips-ddos pcap pthread)
