#include "PacketParser.h"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <cstring>

// 간단 PoC: 이더넷(14바이트)+IPv4만 처리
bool parseEthernetAndIP_internal(const u_char* pkt, int len, Packet& out) {
    if (len < 14 + (int)sizeof(iphdr)) return false;
    const u_char* ipbase = pkt + 14;
    struct iphdr iph; memcpy(&iph, ipbase, sizeof(iphdr));
    if (iph.version != 4) return false;
    char sb[64], db[64];
    inet_ntop(AF_INET, &iph.saddr, sb, sizeof(sb));
    inet_ntop(AF_INET, &iph.daddr, db, sizeof(db));
    out.src_ip = sb; out.dst_ip = db;
    out.ip_id = ntohs(iph.id);
    uint16_t frag_off = ntohs(iph.frag_off);
    out.ip_more_fragments = (frag_off & 0x2000) != 0;
    out.ip_frag_offset = (frag_off & 0x1fff) * 8; // offset * 8 bytes
    int iphdrlen = iph.ihl * 4;
    if (len < 14 + iphdrlen) return false;
    const u_char* l4 = ipbase + iphdrlen;
    int l4len = ntohs(iph.tot_len) - iphdrlen;
    if (iph.protocol == IPPROTO_TCP && l4len >= (int)sizeof(tcphdr)) {
        struct tcphdr tcph; memcpy(&tcph, l4, sizeof(tcphdr));
        out.protocol = "TCP";
        out.src_port = ntohs(tcph.source);
        out.dst_port = ntohs(tcph.dest);
        int tcphlen = tcph.th_off * 4;
        if (l4len > tcphlen) {
            out.payload = l4 + tcphlen;
            out.payload_len = l4len - tcphlen;
        }
        else { out.payload = nullptr; out.payload_len = 0; }
        uint32_t seq_net; memcpy(&seq_net, l4 + offsetof(tcphdr, seq), 4);
        out.tcp_seq = ntohl(seq_net);
        // flags: 일반적으로 header+13 바이트
        out.tcp_flags = *(l4 + 13);
        return true;
    }
    if (iph.protocol == IPPROTO_UDP && l4len >= (int)sizeof(udphdr)) {
        struct udphdr udph; memcpy(&udph, l4, sizeof(udphdr));
        out.protocol = "UDP";
        out.src_port = ntohs(udph.source);
        out.dst_port = ntohs(udph.dest);
        out.payload = l4 + sizeof(udphdr);
        out.payload_len = l4len - sizeof(udphdr);
        return true;
    }
    if (iph.protocol == IPPROTO_ICMP) { out.protocol = "ICMP"; out.payload = l4; out.payload_len = l4len; return true; }
    return false;
}

bool PacketParser::parseEthernetAndIP(const u_char* pkt, int len, Packet& out) {
    return parseEthernetAndIP_internal(pkt, len, out);
}
