#include "PcapCapture.h"
#include <iostream>

PcapCapture::PcapCapture(const std::string& iface)
    : iface_(iface), running_(false), handle_(nullptr) {
}

bool PcapCapture::start(PacketHandler handler, std::string& err) {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle_ = pcap_open_live(iface_.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle_) {
        err = errbuf;
        return false;
    }

    running_ = true;
    thread_ = std::thread([this, handler]() {
        while (running_) {
            struct pcap_pkthdr* header;
            const u_char* pkt_data;
            int res = pcap_next_ex(handle_, &header, &pkt_data);
            if (res == 1 && header && pkt_data) {
                handler(pkt_data, header->len);
            }
        }
        });
    return true;
}

void PcapCapture::stop() {
    running_ = false;
    if (handle_) pcap_close(handle_);
    if (thread_.joinable()) thread_.join();
}
