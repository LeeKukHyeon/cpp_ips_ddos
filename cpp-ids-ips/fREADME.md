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
sudo ./cpp_ips_ddos --iface eth0 --alerts /tmp/ids_alerts.jsonl

1단계: Ping 정상 요청
ping -c 3 <IDS_IP>

2단계: Ping Flood (단순 DoS)
ping -f <IDS_IP>

3단계: Ping of Death
sudo hping3 -1 -d 65500 <IDS_IP>

4단계: TCP SYN Flood
sudo hping3 -S -p 80 --flood <IDS_IP>

5단계: UDP Flood
sudo hping3 --udp -p 53 --flood <IDS_IP>

6단계: Port Scan
sudo nmap -sS <IDS_IP>

7단계: TCP Connect Scan
sudo nmap -sT <IDS_IP>

8단계: XMAS Scan
sudo nmap -sX <IDS_IP>

9단계: Null Scan
sudo nmap -sN <IDS_IP>

10단계: FIN Scan
sudo nmap -sF <IDS_IP>

11단계: Fragment 조작 (Tiny Fragment)
sudo hping3 -c 5 -p 80 --frag <IDS_IP>

12단계: Fragment Overlap 공격
sudo python3 fragment_overlap.py <IDS_IP>

13단계: Slowloris (HTTP 헤더 지연)
slowhttptest -c 200 -H -i 10 -r 200 -t GET -u http://<IDS_IP>/ -x 24 -p 3

14단계: Slow POST (HTTP Body 지연)
slowhttptest -c 200 -B -i 10 -r 200 -t POST -u http://<IDS_IP>/ -x 24 -p 3

15단계: HTTP Flood
ab -n 10000 -c 500 http://<IDS_IP>/

16단계: DNS Flood
sudo hping3 --udp -p 53 --flood --rand-source <IDS_IP>

17단계: 랜덤 IP Flood
sudo hping3 -S --flood --rand-source <IDS_IP>

18단계: SYN/ACK Flood
sudo hping3 -A -p 80 --flood <IDS_IP>

19단계: Mixed TCP Flood (랜덤 플래그)
sudo hping3 -p 80 --flood --rand-source --rand-dest <IDS_IP>

20단계: 시나리오 종합 공격 (멀티 프로세스)
# 병렬로 여러 공격 동시에 실행
sudo hping3 -S -p 80 --flood <IDS_IP> &
sudo hping3 --udp -p 53 --flood <IDS_IP> &
slowhttptest -c 200 -B -i 10 -r 200 -t POST -u http://<IDS_IP>/ -x 24 -p 3 &

