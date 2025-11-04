#include "FragmentReassembly.h"
#include <algorithm>
#include <iostream>

FragmentReassembly::FragmentReassembly() {}
FragmentReassembly::~FragmentReassembly() {}

static FragKey make_key(const std::string& s, const std::string& d, uint16_t id, uint8_t proto) {
    FragKey k; k.src = s; k.dst = d; k.id = id; k.proto = proto; return k;
}

std::vector<uint8_t> FragmentReassembly::push_fragment(const std::string& src, const std::string& dst, uint16_t id, uint8_t proto,
    uint32_t offset, bool mf, const uint8_t* data, size_t len) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto key = make_key(src, dst, id, proto);
    auto& st = table_[key];
    st.last_seen = std::chrono::steady_clock::now();
    if (len == 0 && !mf) {
        // 빈 페이로드이면서 MF==0는 이상, 무시
    }
    // 저장 전에 overlap 체크: 새 조각이 기존 범위와 겹치면 경고(간단 로깅)
    uint32_t seg_start = offset;
    uint32_t seg_end = offset + (uint32_t)len;
    for (auto& p : st.pieces) {
        uint32_t ex_start = p.first;
        uint32_t ex_end = p.first + (uint32_t)p.second.size();
        // 겹침 검사
        if (!(seg_end <= ex_start || seg_start >= ex_end)) {
            // 오버랩 발견 -> 로그(경보는 Detector에서 처리하도록 할 수 있음)
            std::cerr << "[frag] overlap detected: " << src << " id=" << id << " off=" << offset << " len=" << len << "\n";
            // 여기서는 오버랩을 허용하되 우회 가능성을 줄이기 위해 덮어쓰기 정책 적용: 새 데이터로 덮어씀
            // 간단 정책: 덮어쓰기 (실무는 호스트 재조립 정책과 동일하게 맞춰야 함)
        }
    }
    // add piece (덮어쓰기 처리)
    std::vector<uint8_t> v(data, data + len);
    st.pieces[offset] = std::move(v);
    st.piece_count++;
    if (st.piece_count > per_stream_piece_limit) {
        std::cerr << "[frag] piece limit exceeded for stream " << src << "->" << dst << " id=" << id << "\n";
        // 자원 보호: 버림
        table_.erase(key);
        return std::vector<uint8_t>();
    }
    if (!mf) {
        // 마지막 조각 도착: total length = offset + len
        st.total_len = offset + (uint32_t)len;
    }
    // 재조립 가능 여부 판단
    if (st.total_len == 0) return std::vector<uint8_t>(); // 아직 마지막 조각 없음
    // 체크: 조각들이 모두 존재하는지(간단히 이어지는지 확인)
    std::vector<uint8_t> out;
    out.reserve(st.total_len);
    uint32_t cursor = 0;
    for (auto& piece : st.pieces) {
        uint32_t off = piece.first;
        if (off > cursor) {
            // gap 존재: 아직 완전하지 않음
            return std::vector<uint8_t>();
        }
        // 만약 오프셋이 cursor보다 작으면 일부 중복(겹침) - 정렬해서 필요한 부분만 append
        if (off < cursor) {
            uint32_t skip = cursor - off;
            if (skip >= piece.second.size()) continue;
            out.insert(out.end(), piece.second.begin() + skip, piece.second.end());
            cursor += (uint32_t)piece.second.size() - skip;
        }
        else {
            out.insert(out.end(), piece.second.begin(), piece.second.end());
            cursor += (uint32_t)piece.second.size();
        }
        if (cursor >= st.total_len) break;
    }
    if (cursor < st.total_len) return std::vector<uint8_t>(); // 아직 모자람
    // 성공적으로 재조립
    table_.erase(key);
    return out;
}

void FragmentReassembly::cleanup(std::chrono::seconds max_idle) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto now = std::chrono::steady_clock::now();
    std::vector<FragKey> to_rm;
    for (auto& it : table_) {
        if (now - it.second.last_seen > max_idle) to_rm.push_back(it.first);
    }
    for (auto& k : to_rm) table_.erase(k);
}
