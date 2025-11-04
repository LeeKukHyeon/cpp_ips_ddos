#pragma once

#include <string>
#include <cstdint>

// 파싱한 패킷 구조체
struct Packet {
    std::string src_ip;       // 출발지 IP (문자열)
    std::string dst_ip;       // 목적지 IP (문자열)
    uint16_t src_port = 0;    // 출발지 포트
    uint16_t dst_port = 0;    // 목적지 포트
    std::string protocol;     // "TCP", "UDP", "ICMP", ...
    const u_char* payload = nullptr; // 페이로드 포인터 (원본 pcap 버퍼 유효기간 내에서만 유효)
    int payload_len = 0;      // 페이로드 길이

    // IPv4 프래그먼트 관련
    uint16_t ip_id = 0;
    uint32_t ip_frag_offset = 0; // 바이트 단위 offset (offset*8)
    bool ip_more_fragments = false;

    // TCP 관련
    uint32_t tcp_seq = 0;
    uint8_t tcp_flags = 0;
};

// 이더넷 + IPv4 + (TCP|UDP|ICMP) 만 처리하는 간단 파서.
// pkt: pcap에서 받은 패킷 버퍼 포인터
// len: 패킷 길이 (pcap 헤더의 len)
// out: 파싱 결과를 채움
// 반환값: 파싱 성공(true) / 실패(false)
class PacketParser {
public:
    static bool parseEthernetAndIP(const u_char* pkt, int len, Packet& out);
};
