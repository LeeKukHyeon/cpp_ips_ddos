#pragma once
#include <string>

class LogManager {
public:
    explicit LogManager(const std::string& path);
    ~LogManager();
    // JSON 형태의 한 줄 로그를 기록
    void writeAlert(const std::string& jsonline);
private:
    std::string path_;
    FILE* fp_;
    std::mutex mtx_;
};
