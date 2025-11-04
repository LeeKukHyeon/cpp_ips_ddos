cmake_minimum_required(VERSION 3.10)
project(cpp_ips_ddos)
set(CMAKE_CXX_STANDARD 17)
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)
include_directories(${PCAP_INCLUDE_DIRS})
link_directories(${PCAP_LIBRARY_DIRS})
add_definitions(${PCAP_CFLAGS_OTHER})

add_executable(cpp-ips-ddos
  src/main.cpp
  src/capture/PcapCapture.cpp
  src/parser/PacketParser.cpp
  src/engine/FragmentReassembly.cpp
  src/engine/TCPReassembly.cpp
  src/engine/TrafficStats.cpp
  src/engine/Detector.cpp
  src/logger/LogManager.cpp
  src/utils/ThreadPool.cpp
)

target_include_directories(cpp-ips-ddos PRIVATE src)
target_link_libraries(cpp-ips-ddos ${PCAP_LIBRARIES})