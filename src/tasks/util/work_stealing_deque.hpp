// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef LIBRARY_FAST_TASK_SRC_TASKS_UTIL_WORK_STEALING_DEQUE
#define LIBRARY_FAST_TASK_SRC_TASKS_UTIL_WORK_STEALING_DEQUE
#include <atomic>
#include <cassert>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#ifndef FAST_TASK_HDI_SIZE
    #define FAST_TASK_HDI_SIZE
    // Cap at 64 bytes to match fixed inline storage alignment in worker_context / worker_pool
    // (GCC AArch64 reports std::hardware_destructive_interference_size == 256).
    #ifdef __cpp_lib_hardware_interference_size
constexpr std::size_t hardware_destructive_interference_size =
    std::hardware_destructive_interference_size < 64 ? std::hardware_destructive_interference_size : 64;
    #else
constexpr std::size_t hardware_destructive_interference_size = 64;
    #endif
#endif

template <typename T>
class work_stealing_deque {
public:
    explicit work_stealing_deque(std::int64_t capacity = 1024)
        : _capacity(capacity), _mask(capacity - 1), _buffer(std::make_unique<std::atomic<T>[]>(capacity)) {
        assert(capacity > 0 && (capacity & (capacity - 1)) == 0 && "Capacity must be a power of 2!");
    }

    work_stealing_deque(const work_stealing_deque&) = delete;
    work_stealing_deque& operator=(const work_stealing_deque&) = delete;

    work_stealing_deque(work_stealing_deque&&) = delete;
    work_stealing_deque& operator=(work_stealing_deque&&) = delete;

    ~work_stealing_deque() noexcept = default;

    bool empty() const noexcept {
        return size() == 0;
    }

    std::size_t size() const noexcept {
        const auto b = _bottom.load(std::memory_order_relaxed);
        const auto t = _top.load(std::memory_order_relaxed);
        return static_cast<std::size_t>(b > t ? b - t : 0);
    }

    bool emplace(const T& item) {
        auto b = _bottom.load(std::memory_order_relaxed);
        auto t = _top.load(std::memory_order_acquire);

        if (b - t >= _capacity)
            return false;

        _buffer[b & _mask].store(item, std::memory_order_relaxed);

        _bottom.store(b + 1, std::memory_order_release);
        return true;
    }

    bool pop(T& item) noexcept {
        auto b = _bottom.load(std::memory_order_relaxed);
        auto t = _top.load(std::memory_order_acquire);

        if (t >= b)
            return false;

        b--;
        _bottom.store(b, std::memory_order_relaxed);

        std::atomic_thread_fence(std::memory_order_seq_cst);

        t = _top.load(std::memory_order_relaxed);

        if (t < b) {
            item = _buffer[b & _mask].load(std::memory_order_relaxed);
            return true;
        }

        if (t > b) {
            _bottom.store(b + 1, std::memory_order_release);
            return false;
        }

        if (_top.compare_exchange_strong(t, t + 1, std::memory_order_seq_cst, std::memory_order_relaxed)) {
            item = _buffer[b & _mask].load(std::memory_order_relaxed);
            _bottom.store(b + 1, std::memory_order_release);
            return true;
        } else {
            _bottom.store(b + 1, std::memory_order_release);
            return false;
        }
    }

    bool steal(T& item) noexcept {
        while (true) {
            auto t = _top.load(std::memory_order_acquire);
            std::atomic_thread_fence(std::memory_order_seq_cst);
            auto b = _bottom.load(std::memory_order_acquire);

            if (t >= b)
                return false;
            item = _buffer[t & _mask].load(std::memory_order_relaxed);
            if (_top.compare_exchange_strong(t, t + 1, std::memory_order_seq_cst, std::memory_order_relaxed))
                return true;
        }
    }

private:
    const std::int64_t _capacity;
    const std::int64_t _mask;

    alignas(hardware_destructive_interference_size) std::atomic<std::int64_t> _top{0};
    alignas(hardware_destructive_interference_size) std::atomic<std::int64_t> _bottom{0};

    std::unique_ptr<std::atomic<T>[]> _buffer;
};

#endif /* LIBRARY_FAST_TASK_SRC_TASKS_UTIL_WORK_STEALING_DEQUE */
