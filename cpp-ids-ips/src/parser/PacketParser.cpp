#include "PacketParser.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <cstring>
#include <iostream>

// 이더넷 헤더 길이(비-VLAN)
static const int ETHERNET_HEADER_LEN = 14;

// 안전한 범위 검사 헬퍼
static inline bool range_ok(const u_char* pkt, int pkt_len, const u_char* p, size_t want) {
    const ptrdiff_t offset = p - pkt;
    if (offset < 0) return false;
    if ((size_t)offset + want > (size_t)pkt_len) return false;
    return true;
}

bool PacketParser::parseEthernetAndIP(const u_char* pkt, int len, Packet& out) {
    // 기본 길이 체크
    if (pkt == nullptr || len < ETHERNET_HEADER_LEN + (int)sizeof(struct iphdr)) return false;

    const u_char* ipbase = pkt + ETHERNET_HEADER_LEN;
    // iphdr 포인터로 캐스팅 (주의: pcap 버퍼가 바로 읽을 수 있는 메모리여야 함)
    if (!range_ok(pkt, len, ipbase, sizeof(struct iphdr))) return false;
    const struct iphdr* iph = reinterpret_cast<const struct iphdr*>(ipbase);

    if (iph->version != 4) return false; // IPv4만 처리

    // 전체 IP 길이(네트워크 바이트오더 -> 호스트)
    uint16_t ip_total_len = ntohs(iph->tot_len);
    // IP 헤더 길이(바이트)
    int iphdrlen = iph->ihl * 4;
    if (iphdrlen < (int)sizeof(struct iphdr) || iphdrlen > ip_total_len) return false;

    // 패킷 버퍼가 IP 전체를 포함하는지 확인
    if ((int)ETHERNET_HEADER_LEN + (int)ip_total_len > len) {
        // 캡처된 프레임이 IP 전체를 포함하지 않음 (truncated)
        return false;
    }

    // IP 주소 문자열화
    char sbuf[INET_ADDRSTRLEN], dbuf[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &iph->saddr, sbuf, sizeof(sbuf)) == nullptr) return false;
    if (inet_ntop(AF_INET, &iph->daddr, dbuf, sizeof(dbuf)) == nullptr) return false;
    out.src_ip = sbuf;
    out.dst_ip = dbuf;

    // IP ID, fragment offset, MF flag 처리
    out.ip_id = ntohs(iph->id);
    uint16_t frag_off_n = ntohs(iph->frag_off);
    const uint16_t IP_MF_MASK = 0x2000;
    const uint16_t IP_OFFMASK = 0x1FFF;
    out.ip_more_fragments = (frag_off_n & IP_MF_MASK) != 0;
    out.ip_frag_offset = (uint32_t)((frag_off_n & IP_OFFMASK) * 8); // offset * 8 bytes

    // L4 시작 포인터, L4 길이
    const u_char* l4 = ipbase + iphdrlen;
    int l4len = (int)ip_total_len - iphdrlen;
    if (l4len < 0) return false;

    // 프로토콜별 처리
    if (iph->protocol == IPPROTO_TCP) {
        // TCP 헤더 최소 길이 검사
        if (!range_ok(pkt, len, l4, (size_t)sizeof(struct tcphdr))) return false;
        const struct tcphdr* tcph = reinterpret_cast<const struct tcphdr*>(l4);

        // TCP 포트 (호스트 바이트 오더)
        out.src_port = ntohs(tcph->th_sport);
        out.dst_port = ntohs(tcph->th_dport);
        // TCP 헤더 길이 계산 (doff 또는 th_off 필드)
        // 일부 플랫폼에서 필드명이 다를 수 있지만 tcphdr::th_off 또는 doff로 정의됨
        uint8_t doff = 0;
        // POSIX tcphdr: th_off is 4-bit data offset in 32-bit words (host order)
#ifdef __linux__
        doff = tcph->th_off; // 일반적으로 ok
#else
        // 안전한 대체: 상위 4비트를 추출 (네트워크 바이트 이슈 없음)
        doff = ((reinterpret_cast<const u_char*>(tcph))[12] >> 4) & 0x0F;
#endif
        int tcphlen = ((int)doff) * 4;
        if (tcphlen < (int)sizeof(struct tcphdr)) tcphlen = sizeof(struct tcphdr);
        if (tcphlen > l4len) return false; // 트렁케이트된 TCP header

        // 페이로드 위치/길이
        const u_char* payload = l4 + tcphlen;
        int payload_len = l4len - tcphlen;
        if (payload_len < 0) payload_len = 0;
        if (payload_len > 0) {
            if (!range_ok(pkt, len, payload, (size_t)payload_len)) return false;
            out.payload = payload;
            out.payload_len = payload_len;
        }
        else {
            out.payload = nullptr;
            out.payload_len = 0;
        }

        // 시퀀스 번호 (네트워크 바이트오더 -> 호스트)
        out.tcp_seq = ntohl(tcph->th_seq);

        // TCP flags: 표준적으로 offset+13 (바이트 인덱스) 에 존재
        // 안전하게는 struct 접근 대신 해당 바이트 읽기
        const u_char* tcph_bytes = reinterpret_cast<const u_char*>(tcph);
        uint8_t flags = 0;
        if (tcphlen >= 13 + 1 && range_ok(pkt, len, tcph_bytes, (size_t)(13 + 1))) {
            flags = *(tcph_bytes + 13);
        }
        else {
            // fallback: tcph->th_flags 존재하면 사용
#ifdef TH_FLAGS
            flags = tcph->th_flags;
#elif defined(__linux__)
            flags = tcph->th_flags;
#endif
        }
        out.tcp_flags = flags;
        out.protocol = "TCP";
        return true;
    }
    else if (iph->protocol == IPPROTO_UDP) {
        if (!range_ok(pkt, len, l4, (size_t)sizeof(struct udphdr))) return false;
        const struct udphdr* udph = reinterpret_cast<const struct udphdr*>(l4);
        out.src_port = ntohs(udph->uh_sport);
        out.dst_port = ntohs(udph->uh_dport);
        const u_char* payload = l4 + sizeof(struct udphdr);
        int payload_len = l4len - (int)sizeof(struct udphdr);
        if (payload_len > 0) {
            if (!range_ok(pkt, len, payload, (size_t)payload_len)) return false;
            out.payload = payload;
            out.payload_len = payload_len;
        }
        else {
            out.payload = nullptr;
            out.payload_len = 0;
        }
        out.protocol = "UDP";
        return true;
    }
    else if (iph->protocol == IPPROTO_ICMP) {
        // ICMP: payload는 l4 전체
        if (l4len > 0 && range_ok(pkt, len, l4, (size_t)l4len)) {
            out.payload = l4;
            out.payload_len = l4len;
        }
        else {
            out.payload = nullptr;
            out.payload_len = 0;
        }
        out.protocol = "ICMP";
        return true;
    }

    // 지원하지 않는 L4 프로토콜
    return false;
}
