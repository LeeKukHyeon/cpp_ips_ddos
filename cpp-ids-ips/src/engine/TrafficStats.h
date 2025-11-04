#pragma once
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <string>

struct ConnInfo {
    std::chrono::steady_clock::time_point start;
    std::chrono::steady_clock::time_point last_seen;
    uint64_t bytes = 0;
    bool http_post = false;
    size_t post_bytes = 0;
};

struct IPStats {
    uint64_t pkts = 0;
    uint64_t bytes = 0;
    uint64_t syns = 0;
    uint64_t new_conns = 0;
    std::unordered_map<std::string, ConnInfo> conns;
    std::chrono::steady_clock::time_point last_seen;
};

class TrafficStats {
public:
    TrafficStats();
    void on_packet(const std::string& src, const std::string& dst, uint16_t sport, uint16_t dport,
        const std::string& proto, int len, uint8_t tcp_flags);
    void tick(); // 1초 주기: 윈도우 리셋 등
    IPStats get_stats_copy(const std::string& ip);
    void conn_add(const std::string& key, const std::string& src);
    void conn_update_bytes(const std::string& key, const std::string& src, uint64_t add);
    void conn_remove(const std::string& key, const std::string& src);
    void cleanup_stale(std::chrono::seconds idle);
    std::vector<std::string> list_known_ips();
private:
    std::unordered_map<std::string, IPStats> map_;
    std::mutex mtx_;
};
