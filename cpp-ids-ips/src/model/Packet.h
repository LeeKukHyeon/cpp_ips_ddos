#pragma once
#include <string>
#include <vector>
#include <netinet/in.h>

// 패킷 기본 구조체
struct Packet {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t protocol = 0; // TCP=6, UDP=17, ICMP=1 등
    std::vector<uint8_t> payload; // 안전하게 복사된 페이로드
    uint32_t id = 0; // IPv4 fragment ID
    bool is_fragment = false;
    uint16_t frag_offset = 0;
    bool more_fragments = false;
};
