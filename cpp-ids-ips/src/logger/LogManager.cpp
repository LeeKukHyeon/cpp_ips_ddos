#include "LogManager.h"
#include <cstdio>
#include <mutex>

static std::mutex gfp_mtx;
LogManager::LogManager(const std::string& path) : path_(path) {
    fp_ = fopen(path.c_str(), "a");
}
LogManager::~LogManager() { if (fp_) fclose(fp_); }

void LogManager::writeAlert(const std::string& jsonline) {
    std::lock_guard<std::mutex> lk(gfp_mtx);
    if (!fp_) return;
    fprintf(fp_, "%s\n", jsonline.c_str());
    fflush(fp_);
}
