#include "Detector.h"
#include <sstream>
#include <iostream>
#include <cstdlib>

Detector::Detector(TrafficStats& stats, FragmentReassembly& frag, TCPReassembly& treasm, LogManager& logger)
    : stats_(stats), frag_(frag), treasm_(treasm), log_(logger) {
}

void Detector::on_packet(const Packet& p) {
    // 프래그먼트 처리(필요시)
    if (p.is_fragment) {
        bool complete = false;
        Packet re = frag_.reassemble(p, complete);
        stats_.on_packet(p);
        if (complete) {
            std::ostringstream ss;
            ss << "{\"event\":\"frag_reassembled\",\"src\":\"" << re.src_ip << "\",\"dst\":\"" << re.dst_ip << "\",\"id\":" << re.id << "}";
            log_.writeAlert(ss.str());
            // 재조립된 패킷 재처리(간단히 stats에 재전달)
            stats_.on_packet(re);
        }
        return;
    }

    // 일반 패킷 통계 반영
    stats_.on_packet(p);

    // TCP 재조립 시도 (간단: 헤더가 파서에서 이미 제거되었으므로 seq/flags 정보가 필요하면
    // Packet 구조에 필드 추가 후 여기서 push_segment 호출)
    // Slow POST heuristic: payload 내에 "POST " 문자열을 찾으면 conn_add
    if (!p.payload.empty()) {
        std::string s(reinterpret_cast<const char*>(p.payload.data()), p.payload.size());
        if (s.find("POST ") != std::string::npos) {
            std::ostringstream key;
            key << p.src_ip << ":" << p.src_port << "-" << p.dst_ip << ":" << p.dst_port;
            stats_.conn_add(key.str(), p.src_ip);
        }
        else {
            std::ostringstream key;
            key << p.src_ip << ":" << p.src_port << "-" << p.dst_ip << ":" << p.dst_port;
            stats_.conn_update_bytes(key.str(), p.src_ip, p.payload.size());
        }
    }
}

void Detector::tick() {
    // 간단한 정책 체크
    auto ips = stats_.list_known_ips();
    for (auto& ip : ips) {
        IPStats s = stats_.get_stats_copy(ip);
        if (s.pkts > pps_thresh_) {
            check_and_block(ip, "pps_threshold");
        }
        if (s.conns.size() > conn_thresh_) {
            check_and_block(ip, "conn_threshold");
        }
        for (auto& c : s.conns) {
            auto dur = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - c.second.start).count();
            if (dur > (long)slowpost_dur_ && c.second.bytes < slowpost_bytes_) {
                std::ostringstream ss;
                ss << "{\"event\":\"slow_post\",\"src\":\"" << ip << "\",\"conn\":\"" << c.first << "\",\"duration\":" << dur << ",\"bytes\":" << c.second.bytes << "}";
                log_.writeAlert(ss.str());
                check_and_block(ip, "slow_post");
            }
        }
    }
    stats_.tick();
    stats_.cleanup_stale(std::chrono::seconds(60));
    treasm_.cleanup_expired(std::chrono::seconds(60));
}

void Detector::check_and_block(const std::string& ip, const std::string& reason) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (blocked_.count(ip)) return;
    // PoC: iptables 호출 (주의: 테스트 환경)
    std::string cmd = "sudo iptables -I INPUT -s " + ip + " -j DROP";
    int r = system(cmd.c_str());
    (void)r;
    blocked_.insert(ip);
    std::ostringstream ss;
    ss << "{\"event\":\"block\",\"ip\":\"" << ip << "\",\"reason\":\"" << reason << "\"}";
    log_.writeAlert(ss.str());
}

void Detector::alert_json(const std::string& json) {
    log_.writeAlert(json);
}
