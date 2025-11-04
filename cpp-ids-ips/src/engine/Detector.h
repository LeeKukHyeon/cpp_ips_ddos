#pragma once
#include "../parser/PacketParser.h"
#include "TrafficStats.h"
#include "FragmentReassembly.h"
#include "TCPReassembly.h"
#include "../logger/LogManager.h"
#include <chrono>
#include <unordered_set>
#include <mutex>

class Detector {
public:
    Detector(TrafficStats& stats, FragmentReassembly& frag, TCPReassembly& treasm, LogManager& logger);
    void on_packet(const Packet& p); // pcap 콜백에서 비동기 호출
    void tick(); // 1초 주기 검사
    void cleanup(); // 정리 호출
private:
    TrafficStats& stats_;
    FragmentReassembly& frag_;
    TCPReassembly& treasm_;
    LogManager& log_;
    // 정책 임계치 (기본값)
    uint64_t pps_thresh = 10000;       // pkts per sec per IP
    uint64_t syn_thresh = 1000;        // syn/sec
    uint64_t conn_thresh = 500;        // 동시 연결 수
    uint64_t slowpost_duration = 30;   // 초
    uint64_t slowpost_bytes_low = 100;
    std::unordered_set<std::string> blocked_;
    std::mutex mtx_;
    void check_and_block(const std::string& ip, const std::string& reason);
    void alert(const std::string& json);
};
