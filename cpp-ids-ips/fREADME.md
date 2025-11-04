# cpp-ids-ips


Minimal, modular IDS-like project in C++ (libpcap). Designed for staged development and easy extension.


## Build


```bash
sudo apt update
sudo apt install -y build-essential cmake libpcap-dev
mkdir build && cd build
cmake ..
make -j$(nproc)

# 반드시 NIC 지정 필요
sudo ./cpp-ids --iface xx
sudo ./cpp-ids --iface eth0 --alerts /var/log/ids_alerts.jsonl