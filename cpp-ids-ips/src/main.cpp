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
void sigint_handler(int) { keep_running = false; }

int main(int argc, char** argv) {
    std::string iface;
    std::string alerts = "/tmp/ids_alerts.jsonl";

    // --- 명령행 인자 처리 ---
    for (int i = 1; i < argc; i++) {
        std::string arg(argv[i]);
        if (arg == "--iface" && i + 1 < argc) {
            iface = argv[++i];
        }
        else if (arg == "--alerts" && i + 1 < argc) {
            alerts = argv[++i];
        }
        else if (arg == "--help") {
            std::cout << "사용법:\n"
                << "  sudo ./cpp-ids --iface <인터페이스명> [--alerts <로그파일>]\n\n"
                << "예시:\n"
                << "  sudo ./cpp-ids --iface ens33 --alerts /var/log/ids_alert.jsonl\n";
            return 0;
        }
    }

    // 필수 인자 검증
    if (iface.empty()) {
        std::cerr << "[ERROR] 네트워크 인터페이스(--iface)가 지정되지 않았습니다.\n";
        std::cerr << "사용법: sudo ./cpp-ids --iface <인터페이스명>\n";
        return 1;
    }

    signal(SIGINT, sigint_handler);

    std::cout << "=====================================\n";
    std::cout << "   🛡️  C++ IDS / IPS / DDoS Detector  \n";
    std::cout << "=====================================\n";
    std::cout << "[INFO] 인터페이스: " << iface << "\n";
    std::cout << "[INFO] 로그 파일 : " << alerts << "\n";

    // 구성 요소 초기화
    LogManager logger(alerts);
    FragmentReassembly frag;
    TCPReassembly treasm;
    TrafficStats stats;
    Detector detector(stats, frag, treasm, logger);
    

    // NIC 캡처 초기화
    PcapCapture cap(iface);
    std::string err;
    ThreadPool pool(4);

    bool ok = cap.start([&](const u_char* pkt, int len) {
        Packet p;
        if (!PacketParser::parseEthernetAndIP(pkt, len, p)) return;
        pool.enqueue([p, &detector]() {
            detector.on_packet(p);
            });
        }, err);

    if (!ok) {
        std::cerr << "[ERROR] pcap open 실패: " << err << "\n";
        return 1;
    }

    // Tick 스레드 (1초마다 통계/탐지 갱신)
    std::thread ticker([&]() {
        while (keep_running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            detector.tick();
        }
        });

    // 메인 루프
    while (keep_running)
        std::this_thread::sleep_for(std::chrono::seconds(1));

    cap.stop();
    ticker.join();

    std::cout << "[INFO] IDS 종료 완료.\n";
    return 0;
}
