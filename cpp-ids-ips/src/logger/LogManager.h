#pragma once
#include <string>

class LogManager {
public:
    explicit LogManager(const std::string& path);
    ~LogManager();
    void writeAlert(const std::string& jsonline);
private:
    std::string path_;
    FILE* fp_ = nullptr;
};
