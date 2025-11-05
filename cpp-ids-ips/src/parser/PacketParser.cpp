#include "PacketParser.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <cstring>
#include <iostream>

// Ethernet 헤더 길이
#define ETH_HDR_LEN 14

bool PacketParser::parseEthernetAndIP(const u_char* pkt, int len, Packet& out) {
    if (len < ETH_HDR_LEN + (int)sizeof(iphdr)) return false;

    const struct ip* iphdr = (struct ip*)(pkt + ETH_HDR_LEN);
    int iphdr_len = iphdr->ip_hl * 4;
    if (iphdr_len < 20) return false;

    out.src_ip = inet_ntoa(iphdr->ip_src);
    out.dst_ip = inet_ntoa(iphdr->ip_dst);
    out.protocol = iphdr->ip_p;
    out.id = ntohs(iphdr->ip_id);
    out.frag_offset = ntohs(iphdr->ip_off) & IP_OFFMASK;
    out.more_fragments = ntohs(iphdr->ip_off) & IP_MF;
    out.is_fragment = (out.frag_offset > 0 || out.more_fragments);

    // 페이로드 추출
    const u_char* payload = pkt + ETH_HDR_LEN + iphdr_len;
    int payload_len = len - (ETH_HDR_LEN + iphdr_len);
    if (payload_len <= 0) return true;

    // 안전하게 복사 (비동기 큐에 전달해도 안전)
    out.payload.assign(payload, payload + payload_len);

    // 프로토콜 별 포트 추출
    if (iphdr->ip_p == IPPROTO_TCP && payload_len >= (int)sizeof(tcphdr)) {
        const struct tcphdr* tcph = (struct tcphdr*)payload;
        out.src_port = ntohs(tcph->source);
        out.dst_port = ntohs(tcph->dest);
    }
    else if (iphdr->ip_p == IPPROTO_UDP && payload_len >= (int)sizeof(udphdr)) {
        const struct udphdr* udph = (struct udphdr*)payload;
        out.src_port = ntohs(udph->source);
        out.dst_port = ntohs(udph->dest);
    }

    return true;
}
