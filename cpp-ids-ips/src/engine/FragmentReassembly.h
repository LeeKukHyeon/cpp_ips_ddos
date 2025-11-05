#pragma once
#include <map>
#include <vector>
#include "../model/Packet.h"

// IPv4 조각 재조립
class FragmentReassembly {
public:
    Packet reassemble(const Packet& pkt, bool& complete);

private:
    struct FragBuffer {
        std::vector<Packet> fragments;
        size_t total_size = 0;
    };
    std::map<uint32_t, FragBuffer> frag_table_;
};
