#include "TCPReassembly.h"
#include <algorithm>
#include <vector>


TCPReassembly::TCPReassembly() {}
TCPReassembly::~TCPReassembly() {}

std::string TCPReassembly::push_segment(const TCPKey& k, uint32_t seq, const char* data, int len) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto& st = streams_[k];
    st.last_seen = std::chrono::steady_clock::now();
    std::string newly;
    if (st.next_seq == 0) {
        // 초기 세그먼트로 간주
        st.buf.append(data, data + len);
        newly.append(data, data + len);
        st.next_seq = seq + (uint32_t)len;
        // OOO 조각 병합
        while (true) {
            auto it = st.ooo.find(st.next_seq);
            if (it == st.ooo.end()) break;
            st.buf.append(it->second);
            newly.append(it->second);
            st.next_seq += (uint32_t)it->second.size();
            st.ooo.erase(it);
        }
        return newly;
    }
    uint32_t seg_start = seq;
    uint32_t seg_end = seq + (uint32_t)len;
    if (seg_end <= st.next_seq) return newly; // 이미 처리된 중복
    if (seg_start <= st.next_seq && seg_end > st.next_seq) {
        uint32_t offset = st.next_seq - seg_start;
        const char* p = data + offset;
        int addlen = (int)(seg_end - st.next_seq);
        st.buf.append(p, p + addlen);
        newly.append(p, p + addlen);
        st.next_seq += (uint32_t)addlen;
        while (true) {
            auto it = st.ooo.find(st.next_seq);
            if (it == st.ooo.end()) break;
            st.buf.append(it->second);
            newly.append(it->second);
            st.next_seq += (uint32_t)it->second.size();
            st.ooo.erase(it);
        }
        return newly;
    }
    if (seg_start == st.next_seq) {
        st.buf.append(data, data + len);
        newly.append(data, data + len);
        st.next_seq += (uint32_t)len;
        while (true) {
            auto it = st.ooo.find(st.next_seq);
            if (it == st.ooo.end()) break;
            st.buf.append(it->second);
            newly.append(it->second);
            st.next_seq += (uint32_t)it->second.size();
            st.ooo.erase(it);
        }
        return newly;
    }
    // out-of-order
    auto it = st.ooo.find(seg_start);
    if (it == st.ooo.end() || it->second.size() < (size_t)len) st.ooo[seg_start] = std::string(data, data + len);
    return newly;
}

void TCPReassembly::remove_stream(const TCPKey& k) {
    std::lock_guard<std::mutex> lk(mtx_);
    streams_.erase(k);
}

void TCPReassembly::cleanup_expired(std::chrono::seconds max_idle) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto now = std::chrono::steady_clock::now();
    std::vector<TCPKey> to_rm;
    for (auto& kv : streams_) {
        if (now - kv.second.last_seen > max_idle) to_rm.push_back(kv.first);
    }
    for (auto& k : to_rm) streams_.erase(k);
}

std::string TCPReassembly::tail_of_stream(const TCPKey& k, size_t n) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = streams_.find(k);
    if (it == streams_.end()) return std::string();
    auto& b = it->second.buf;
    if (b.size() <= n) return b;
    return b.substr(b.size() - n);
}
