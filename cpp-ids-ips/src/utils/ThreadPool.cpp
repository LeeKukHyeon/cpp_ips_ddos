#include "ThreadPool.h"

ThreadPool::ThreadPool(size_t n) {
    if (n == 0) n = 1;
    for (size_t i = 0; i < n; ++i) {
        workers_.emplace_back([this]() {
            while (true) {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lk(this->mtx_);
                    this->cv_.wait(lk, [this]() { return this->stopping_ || !this->tasks_.empty(); });
                    if (this->stopping_ && this->tasks_.empty()) return;
                    task = std::move(this->tasks_.front());
                    this->tasks_.pop();
                }
                try { task(); }
                catch (...) { /* 예외 무시 */ }
            }
            });
    }
}

ThreadPool::~ThreadPool() {
    {
        std::unique_lock<std::mutex> lk(mtx_);
        stopping_ = true;
    }
    cv_.notify_all();
    for (auto& t : workers_) if (t.joinable()) t.join();
}

void ThreadPool::enqueue(std::function<void()> f) {
    {
        std::unique_lock<std::mutex> lk(mtx_);
        tasks_.push(std::move(f));
    }
    cv_.notify_one();
}
