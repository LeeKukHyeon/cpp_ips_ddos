#pragma once
#include <string>
#include <map>
#include <mutex>
#include <chrono>

// 단방향(클라이언트->서버) 간단한 TCP 세그먼트 재조립 구조
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
    // seq: 호스트 바이트오더의 seq
    // data: 새로 받은 데이터(문자열 포인터)
    // len: 길이
    // 반환: 새로 완성되어 사용 가능한 문자열(빈 문자열이면 새로 추가된게 없음)
    std::string push_segment(const TCPKey& k, uint32_t seq, const char* data, int len);
    void remove_stream(const TCPKey& k);
    void cleanup_expired(std::chrono::seconds max_idle);
    std::string tail_of_stream(const TCPKey& k, size_t n);
private:
    struct Stream {
        uint32_t next_seq = 0;
        std::string buf;
        std::map<uint32_t, std::string> ooo;
        std::chrono::steady_clock::time_point last_seen;
    };
    std::map<TCPKey, Stream> streams_;
    std::mutex mtx_;
};
