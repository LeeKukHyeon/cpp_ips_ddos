#include "ThreadPool.h"

ThreadPool::ThreadPool(size_t n) {
    for (size_t i = 0; i < n; i++) workers.emplace_back([this]() {
        while (true) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lk(this->mtx);
                this->cv.wait(lk, [this] {return this->stopping || !this->tasks.empty(); });
                if (this->stopping && this->tasks.empty()) return;
                task = std::move(this->tasks.front()); this->tasks.pop();
            }
            try { task(); }
            catch (...) {}
        }
        });
}
ThreadPool::~ThreadPool() {
    { std::unique_lock<std::mutex> lk(mtx); stopping = true; }
    cv.notify_all();
    for (auto& t : workers) if (t.joinable()) t.join();
}
void ThreadPool::enqueue(std::function<void()> f) {
    { std::unique_lock<std::mutex> lk(mtx); tasks.push(std::move(f)); }
    cv.notify_one();
}
