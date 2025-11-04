#pragma once
#include <pcap.h>
#include <string>
#include <functional>

// 캡처 콜백: 원시 패킷과 길이 전달
class PcapCapture {
public:
    using Callback = std::function<void(const u_char* pkt, int len)>;
    explicit PcapCapture(const std::string& iface);
    ~PcapCapture();

    // 캡처 시작, 실패 시 err에 메시지 저장
    bool start(Callback cb, std::string& err);
    void stop();
private:
    pcap_t* handle_{ nullptr };
    std::string dev_;
    bool running_ = false;
};
