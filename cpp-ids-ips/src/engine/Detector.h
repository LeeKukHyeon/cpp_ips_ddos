#pragma once
#include "../engine/TrafficStats.h"
#include "../engine/FragmentReassembly.h"
#include "../engine/TCPReassembly.h"
#include "../logger/LogManager.h"
#include "../model/Packet.h"
#include <unordered_set>
#include <mutex>

class Detector {
public:
    Detector(TrafficStats& stats, FragmentReassembly& frag, TCPReassembly& treasm, LogManager& logger);
    // p는 값 복사로 전달(스레드풀 enqueue에서 안전)
    void on_packet(const Packet& p);
    void tick();
private:
    TrafficStats& stats_;
    FragmentReassembly& frag_;
    TCPReassembly& treasm_;
    LogManager& log_;
    std::unordered_set<std::string> blocked_;
    std::mutex mtx_;

    // 임계치 (간단한 기본값)
    uint64_t pps_thresh_ = 10000;
    uint64_t conn_thresh_ = 500;
    uint64_t slowpost_dur_ = 30;
    uint64_t slowpost_bytes_ = 100;

    void check_and_block(const std::string& ip, const std::string& reason);
    void alert_json(const std::string& json);
};
