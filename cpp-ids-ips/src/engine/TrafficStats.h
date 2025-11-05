#pragma once
#include <unordered_map>
#include <string>
#include <chrono>
#include <mutex>
#include <vector>
#include "../model/Packet.h"

// 연결 정보 (단일 src->dst:port stream)
struct ConnInfo {
    std::chrono::steady_clock::time_point start;
    std::chrono::steady_clock::time_point last_seen;
    uint64_t bytes = 0;
    bool http_post = false;
};

struct IPStats {
    uint64_t pkts = 0;
    uint64_t bytes = 0;
    uint64_t syns = 0;
    uint64_t new_conns = 0;
    std::unordered_map<std::string, ConnInfo> conns; // key: "src:sport-dst:dport"
    std::chrono::steady_clock::time_point last_seen;
};

class TrafficStats {
public:
    TrafficStats();
    // 패킷 수집: 비동기에서 호출 가능 (스레드 안전)
    void on_packet(const Packet& p);

    // 1초 주기 호출: 윈도우 초기화 등
    void tick();

    // IP 기준 통계 사본 반환 (스레드 안전)
    IPStats get_stats_copy(const std::string& ip);

    // connection helper
    void conn_add(const std::string& key, const std::string& src);
    void conn_update_bytes(const std::string& key, const std::string& src, uint64_t add);
    void conn_remove(const std::string& key, const std::string& src);

    std::vector<std::string> list_known_ips();

    void cleanup_stale(std::chrono::seconds idle);
private:
    std::unordered_map<std::string, IPStats> map_;
    std::mutex mtx_;
};
