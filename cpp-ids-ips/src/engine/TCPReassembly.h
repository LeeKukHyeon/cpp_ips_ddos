#pragma once
#include <string>
#include <unordered_map>
#include <mutex>
#include <map>
#include <chrono>

// 간단한 TCP 재조립(양방향 미지원, 방향별 추적)
struct TCPKey {
    std::string src; std::string dst; uint16_t sport; uint16_t dport;
    bool operator==(TCPKey const& o) const noexcept { return src == o.src && dst == o.dst && sport == o.sport && dport == o.dport; }
};
struct TCPKeyHash {
    size_t operator()(TCPKey const& k) const noexcept {
        std::hash<std::string> hs; std::hash<uint16_t> hp; return hs(k.src) ^ (hs(k.dst) << 1) ^ (hp(k.sport) << 2) ^ (hp(k.dport) << 3);
    }
};

class TCPReassembly {
public:
    TCPReassembly();
    ~TCPReassembly();
    // 세그먼트 추가: seq(host order), data,len
    std::string push_segment(const TCPKey& k, uint32_t seq, const char* data, int len);
    void remove_stream(const TCPKey& k);
    void cleanup_expired(std::chrono::seconds max_idle);
    std::string tail_of_stream(const TCPKey& k, size_t n);
private:
    struct Stream { uint32_t next_seq = 0; std::string buf; std::map<uint32_t, std::string> ooo; std::chrono::steady_clock::time_point last_seen; };
    std::unordered_map<TCPKey, Stream, TCPKeyHash> streams_;
    std::mutex mtx_;
};
