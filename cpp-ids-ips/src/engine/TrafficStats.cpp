#include "TrafficStats.h"
#include <sstream>
#include <vector>

TrafficStats::TrafficStats() {}

void TrafficStats::on_packet(const Packet& p) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto& s = map_[p.src_ip];
    s.pkts += 1;
    s.bytes += p.payload.size();
    s.last_seen = std::chrono::steady_clock::now();

    // TCP SYN 카운트: 패킷에 tcp_flags 필드가 없으므로 확인할 수 없다면 상위에서 통지 필요.
    // PoC: new_conns 증가(간단화)
    // 연결키
    std::ostringstream oss;
    oss << p.src_ip << ":" << p.src_port << "-" << p.dst_ip << ":" << p.dst_port;
    std::string key = oss.str();
    auto it = s.conns.find(key);
    if (it == s.conns.end()) {
        ConnInfo ci;
        ci.start = ci.last_seen = std::chrono::steady_clock::now();
        ci.bytes = p.payload.size();
        s.conns[key] = ci;
    }
    else {
        it->second.last_seen = std::chrono::steady_clock::now();
        it->second.bytes += p.payload.size();
    }
}

void TrafficStats::tick() {
    std::lock_guard<std::mutex> lk(mtx_);
    for (auto& kv : map_) {
        // 윈도우성 지표를 리셋해야 하면 여기서 처리
        kv.second.new_conns = 0;
        kv.second.syns = 0;
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
    ConnInfo ci;
    ci.start = ci.last_seen = std::chrono::steady_clock::now();
    ci.bytes = 0;
    ci.http_post = true;
    s.conns[key] = ci;
}

void TrafficStats::conn_update_bytes(const std::string& key, const std::string& src, uint64_t add) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto& s = map_[src];
    auto it = s.conns.find(key);
    if (it != s.conns.end()) {
        it->second.bytes += add;
        it->second.last_seen = std::chrono::steady_clock::now();
    }
}

void TrafficStats::conn_remove(const std::string& key, const std::string& src) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto& s = map_[src];
    s.conns.erase(key);
}

std::vector<std::string> TrafficStats::list_known_ips() {
    std::lock_guard<std::mutex> lk(mtx_);
    std::vector<std::string> ret;
    for (auto& kv : map_) ret.push_back(kv.first);
    return ret;
}

void TrafficStats::cleanup_stale(std::chrono::seconds idle) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto now = std::chrono::steady_clock::now();
    std::vector<std::string> to_rm;
    for (auto& kv : map_) {
        // remove stale conns
        std::vector<std::string> to_del;
        for (auto& c : kv.second.conns) {
            if (now - c.second.last_seen > idle) to_del.push_back(c.first);
        }
        for (auto& k : to_del) kv.second.conns.erase(k);
        if (now - kv.second.last_seen > idle * 10) to_rm.push_back(kv.first);
    }
    for (auto& k : to_rm) map_.erase(k);
}
