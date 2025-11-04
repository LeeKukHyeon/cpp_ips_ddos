#pragma once
#include <string>
#include <map>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <chrono>

// 프래그먼트 키
struct FragKey {
    std::string src;
    std::string dst;
    uint16_t id;
    uint8_t proto;
    bool operator==(FragKey const& o) const noexcept {
        return src == o.src && dst == o.dst && id == o.id && proto == o.proto;
    }
};
struct FragKeyHash {
    size_t operator()(FragKey const& k) const noexcept {
        std::hash<std::string> hs; std::hash<uint16_t> hi; std::hash<uint8_t> hp;
        return hs(k.src) ^ (hs(k.dst) << 1) ^ (hi(k.id) << 2) ^ (hp(k.proto) << 3);
    }
};

// 각 조각 저장 구조
struct FragPiece {
    uint32_t offset; // 바이트 오프셋
    std::vector<uint8_t> data;
};

class FragmentReassembly {
public:
    FragmentReassembly();
    ~FragmentReassembly();
    // 프래그먼트 추가: payload 포인터와 길이, offset, mf flag
    // 반환: 재조립이 완료되었을 경우 완전한 페이로드(벡터) 반환. 아니면 빈 벡터.
    std::vector<uint8_t> push_fragment(const std::string& src, const std::string& dst, uint16_t id, uint8_t proto,
        uint32_t offset, bool mf, const uint8_t* data, size_t len);
    // 주기적 정리(타임아웃)
    void cleanup(std::chrono::seconds max_idle);
    // 통계/검지 값 조회(선택)
private:
    struct Stream {
        std::map<uint32_t, std::vector<uint8_t>> pieces; // offset -> data
        uint32_t total_len = 0; // 0이면 아직 unknown
        std::chrono::steady_clock::time_point last_seen;
        int piece_count = 0;
    };
    std::unordered_map<FragKey, Stream, FragKeyHash> table_;
    std::mutex mtx_;
    // 탐지 임계치
    int tiny_fragment_threshold = 50; // 초당 같은 src의 tiny fragments 수(간단화)
    int per_stream_piece_limit = 1024; // 방지용
};
