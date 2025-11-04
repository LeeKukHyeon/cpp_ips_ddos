#include "Detector.h"
#include <sstream>
#include <iostream>
#include <cstdlib>

Detector::Detector(TrafficStats& stats, FragmentReassembly& frag, TCPReassembly& treasm, LogManager& logger)
    : stats_(stats), frag_(frag), treasm_(treasm), log_(logger) {
}

void Detector::on_packet(const Packet& p) {
    // 1) Fragment 처리 (IPv4 프래그먼트이면 frag 모듈로 전달)
    if (p.ip_frag_offset > 0 || p.ip_more_fragments) {
        // payload 복사 필요 (원본 포인터 유효범위가 pcap 버퍼에 의존)
        if (p.payload && p.payload_len > 0) {
            std::vector<uint8_t> tmp(p.payload, p.payload + p.payload_len);
            auto reasm = frag_.push_fragment(p.src_ip, p.dst_ip, p.ip_id, 0 /*proto*/, p.ip_frag_offset, p.ip_more_fragments, tmp.data(), tmp.size());
            if (!reasm.empty()) {
                // 재조립된 전체 페이로드 -> 추가 분석 (예: ICMP/TCP 재구성 등)
                std::ostringstream ss; ss << "{\"event\":\"frag_reassembled\",\"src\":\"" << p.src_ip << "\",\"dst\":\"" << p.dst_ip << "\",\"id\":" << p.ip_id << "}";
                log_.writeAlert(ss.str());
                // PoC: 재조립 페이로드는 분석 대상(추가 파싱 필요)
            }
        }
        else {
            // 빈 조각(예: fragment header only)도 기록
        }
        // 프래그먼트는 트래픽 통계에도 반영
        stats_.on_packet(p.src_ip, p.dst_ip, p.src_port, p.dst_port, p.protocol, p.payload_len, p.tcp_flags);
        return;
    }

    // 2) 일반 패킷 통계 업데이트
    stats_.on_packet(p.src_ip, p.dst_ip, p.src_port, p.dst_port, p.protocol, p.payload_len, p.tcp_flags);

    // 3) TCP 재조립: 재조립으로 새로 얻은 바이트를 검사(예: HTTP content) - PoC는 간단히 tail 검사
    if (p.protocol == "TCP" && p.tcp_seq && p.payload_len > 0) {
        TCPKey k{ p.src_ip, p.dst_ip, p.src_port, p.dst_port };
        auto newly = treasm_.push_segment(k, p.tcp_seq, (const char*)p.payload, p.payload_len);
        if (!newly.empty()) {
            std::string tail = treasm_.tail_of_stream(k, 2048);
            // 예: "POST " 체크로 slow-post 시작 마킹
            if (tail.find("POST ") != std::string::npos) {
                std::ostringstream key; key << p.src_ip << ":" << p.src_port << "-" << p.dst_ip << ":" << p.dst_port;
                stats_.conn_add(key.str(), p.src_ip);
            }
        }
    }
    else if (p.protocol == "TCP" && p.payload_len > 0) {
        // 모양만으로 POST 시작 감지 (단순)
        std::string s((const char*)p.payload, p.payload_len);
        if (s.find("POST ") != std::string::npos) {
            std::ostringstream key; key << p.src_ip << ":" << p.src_port << "-" << p.dst_ip << ":" << p.dst_port;
            stats_.conn_add(key.str(), p.src_ip);
        }
        else {
            std::ostringstream key; key << p.src_ip << ":" << p.src_port << "-" << p.dst_ip << ":" << p.dst_port;
            stats_.conn_update_bytes(key.str(), p.src_ip, p.payload_len);
        }
    }
}

void Detector::tick() {
    // 1초 주기 검사
    auto ips = stats_.list_known_ips();
    for (auto& ip : ips) {
        auto s = stats_.get_stats_copy(ip);
        // PPS 근사: pkts 값이 1초 윈도우 내인지~ (PoC 단순화)
        if (s.pkts > pps_thresh) {
            check_and_block(ip, "pps_threshold");
        }
        if (s.syns > syn_thresh) {
            check_and_block(ip, "syn_threshold");
        }
        if (s.conns.size() > conn_thresh) {
            check_and_block(ip, "conn_threshold");
        }
        // slow-post 검사: 모든 연결을 확인
        for (auto& c : s.conns) {
            auto dur = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - c.second.start).count();
            if (dur > (long)slowpost_duration && c.second.bytes < slowpost_bytes_low) {
                std::ostringstream ss; ss << "{\"event\":\"slow_post\",\"src\":\"" << ip << "\",\"conn\":\"" << c.first << "\",\"duration\":" << dur << ",\"bytes\": " << c.second.bytes << "}";
                log_.writeAlert(ss.str());
                check_and_block(ip, "slow_post");
            }
        }
    }
    // TrafficStats 윈도우 리셋
    stats_.tick();
    // fragment cleanup
    frag_.cleanup(std::chrono::seconds(30));
    treasm_.cleanup_expired(std::chrono::seconds(60));
}

void Detector::cleanup() {
    // 필요시 추가 정리
}

void Detector::check_and_block(const std::string& ip, const std::string& reason) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (blocked_.count(ip)) return;
    // PoC: iptables 직접 호출 (주의: 테스트 환경에서만)
    std::string cmd = "sudo iptables -I INPUT -s " + ip + " -j DROP";
    int r = system(cmd.c_str());
    (void)r;
    blocked_.insert(ip);
    std::ostringstream ss; ss << "{\"event\":\"block\",\"ip\":\"" << ip << "\",\"reason\":\"" << reason << "\"}";
    log_.writeAlert(ss.str());
}

void Detector::alert(const std::string& json) {
    log_.writeAlert(json);
}
