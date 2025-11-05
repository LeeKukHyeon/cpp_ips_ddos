#include "LogManager.h"
#include <cstdio>
#include <mutex>

LogManager::LogManager(const std::string& path) : path_(path), fp_(nullptr) {
    fp_ = fopen(path_.c_str(), "a");
}

LogManager::~LogManager() {
    if (fp_) fclose(fp_);
}

void LogManager::writeAlert(const std::string& jsonline) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (!fp_) return;
    fprintf(fp_, "%s\n", jsonline.c_str());
    fflush(fp_);
}
