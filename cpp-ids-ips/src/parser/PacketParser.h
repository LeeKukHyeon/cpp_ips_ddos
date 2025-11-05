#pragma once
#include "../model/Packet.h"

class PacketParser {
public:
    static bool parseEthernetAndIP(const u_char* pkt, int len, Packet& out);
};
