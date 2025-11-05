#include "FragmentReassembly.h"

Packet FragmentReassembly::reassemble(const Packet& pkt, bool& complete) {
    complete = false;
    if (!pkt.is_fragment) {
        complete = true;
        return pkt;
    }

    auto& buf = frag_table_[pkt.id];
    buf.fragments.push_back(pkt);

    if (!pkt.more_fragments) {
        complete = true;
        Packet merged = pkt;
        merged.payload.clear();
        for (auto& f : buf.fragments) {
            merged.payload.insert(merged.payload.end(), f.payload.begin(), f.payload.end());
        }
        frag_table_.erase(pkt.id);
        return merged;
    }
    return pkt;
}
