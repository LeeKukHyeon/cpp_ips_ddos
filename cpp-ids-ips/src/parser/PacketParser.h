#pragma once
#include <string>
#include <cstdint>

// 파싱한 패킷 구조체 (간단화)
struct Packet {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    std::string protocol; // "TCP","UDP","ICMP"
    const u_char* payload = nullptr;
    int payload_len = 0;
    // IPv4 프래그먼트 관련
    uint16_t ip_id = 0;
    uint16_t ip_frag_offset = 0;
    bool ip_more_fragments = false;
    // TCP 관련
    uint32_t tcp_seq = 0;
    uint8_t tcp_flags = 0;
};
