#include <iostream>
#include <signal.h>
#include <atomic>
#include <thread>
#include "capture/PcapCapture.h"
#include "parser/PacketParser.h"
#include "engine/FragmentReassembly.h"
#include "engine/TCPReassembly.h"
#include "engine/TrafficStats.h"
#include "engine/Detector.h"
#include "logger/LogManager.h"
#include "utils/ThreadPool.h"

static std::atomic<bool> keep_running(true);

int main(int argc, char** argv) {
    std::string iface;
    std::string alerts = "/tmp/ids_alerts.jsonl";

    // 명령행 인자 처리
    for (int i = 1; i < argc; i++) {
        std::string a(argv[i]);
        if (a == "--iface" && i + 1 < argc) iface = argv[++i];
        else if (a == "--alerts" && i + 1 < argc) alerts = argv[++i];
    }

    if (iface.empty()) {
        std::cerr << "[에러] NIC 인터페이스를 지정해야 합니다 (--iface eth0)" << std::endl;
        return 1;
    }

    signal(SIGINT, [](int) { keep_running = false; });

    LogManager logger(alerts);
    FragmentReassembly frag;
    TCPReassembly treasm;
    TrafficStats stats;
    Detector detector(stats, frag, treasm, logger);

    PcapCapture cap(iface);
    std::string err;
    ThreadPool pool(4);

    bool ok = cap.start([&](const u_char* pkt, int len) {
        Packet p;
        if (!PacketParser::parseEthernetAndIP(pkt, len, p)) return;
        pool.enqueue([p, &detector]() { detector.on_packet(p); });
        }, err);

    if (!ok) {
        std::cerr << "pcap open 실패: " << err << std::endl;
        return 1;
    }

    std::thread ticker([&]() {
        while (keep_running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            detector.tick();
        }
        });

    while (keep_running)
        std::this_thread::sleep_for(std::chrono::seconds(1));

    cap.stop();
    ticker.join();
    return 0;
}
