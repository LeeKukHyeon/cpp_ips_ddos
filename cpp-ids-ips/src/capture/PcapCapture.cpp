#include "PcapCapture.h"
#include <thread>
#include <iostream>

PcapCapture::PcapCapture(const std::string& iface) : dev_(iface) {}
PcapCapture::~PcapCapture() { stop(); }

bool PcapCapture::start(Callback cb, std::string& err) {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle_ = pcap_open_live(dev_.c_str(), 65536, 1, 1000, errbuf);
    if (!handle_) { err = errbuf; return false; }
    running_ = true;
    std::thread([this, cb]() {
        while (running_) {
            struct pcap_pkthdr* hdr; const u_char* data;
            int res = pcap_next_ex(handle_, &hdr, &data);
            if (res <= 0) continue;
            cb(data, hdr->len);
        }
        }).detach();
    return true;
}

void PcapCapture::stop() {
    running_ = false;
    if (handle_) { pcap_close(handle_); handle_ = nullptr; }
}
