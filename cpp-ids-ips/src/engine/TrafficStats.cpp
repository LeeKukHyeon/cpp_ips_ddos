#include "TrafficStats.h"
#include <sstream>
#include <vector>

TrafficStats::TrafficStats() {}

void TrafficStats::on_packet(const std::string& src, const std::string& dst, uint16_t sport, uint16_t dport,
    const std::string& proto, int len, uint8_t tcp_flags) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto& s = map_[src];
    s.pkts += 1;
    s.bytes += (uint64_t)len;
    s.last_seen = std::chrono::steady_clock::now();
    if (proto == "TCP") {
        if (tcp_flags & 0x02) s.syns += 1;
        if (tcp_flags & 0x02) s.new_conns += 1;
    }
    std::ostringstream k; k << src << ":" << sport << "-" << dst << ":" << dport;
    auto& cms = s.conns;
    auto it = cms.find(k.str());
    if (it == cms.end()) {
        ConnInfo ci; ci.start = ci.last_seen = std::chrono::steady_clock::now(); ci.bytes = (uint64_t)len;
        cms[k.str()] = ci;
    }
    else {
        it->second.last_seen = std::chrono::steady_clock::now();
        it->second.bytes += (uint64_t)len;
    }
}

void TrafficStats::tick() {
    std::lock_guard<std::mutex> lk(mtx_);
    // 간단 윈도우 관리: new_conns/syns는 여기서 리셋
    for (auto& it : map_) {
        it.second.new_conns = 0;
        it.second.syns = 0;
    }
}

IPStats TrafficStats::get_stats_copy(const std::string& ip) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (map_.count(ip)) return map_[ip];
    return IPStats();
}

void TrafficStats::conn_add(const std::string& key, const std::string& src) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto& s = map_[src];
    ConnInfo ci; ci.start = ci.last_seen = std::chrono::steady_clock::now(); ci.bytes = 0; ci.http_post = true;
    s.conns[key] = ci;
}

void TrafficStats::conn_update_bytes(const std::string& key, const std::string& src, uint64_t add) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto& s = map_[src];
    auto it = s.conns.find(key);
    if (it != s.conns.end()) { it->second.bytes += add; it->second.last_seen = std::chrono::steady_clock::now(); }
}

void TrafficStats::conn_remove(const std::string& key, const std::string& src) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto& s = map_[src];
    s.conns.erase(key);
}

void TrafficStats::cleanup_stale(std::chrono::seconds idle) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto now = std::chrono::steady_clock::now();
    std::vector<std::string> to_rm;
    for (auto& it : map_) {
        std::vector<std::string> keys;
        for (auto& c : it.second.conns) {
            if (now - c.second.last_seen > idle) keys.push_back(c.first);
        }
        for (auto& k : keys) it.second.conns.erase(k);
        if (now - it.second.last_seen > idle * 10) to_rm.push_back(it.first);
    }
    for (auto& k : to_rm) map_.erase(k);
}

std::vector<std::string> TrafficStats::list_known_ips() {
    std::lock_guard<std::mutex> lk(mtx_);
    std::vector<std::string> ret;
    for (auto& it : map_) ret.push_back(it.first);
    return ret;
}
