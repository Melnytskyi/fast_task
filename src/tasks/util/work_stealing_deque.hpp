
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

#ifdef __cpp_lib_hardware_interference_size
constexpr std::size_t hardware_destructive_interference_size = std::hardware_destructive_interference_size;
#else
constexpr std::size_t hardware_destructive_interference_size = 64;
#endif

template <typename T>
class work_stealing_deque {
public:
    explicit work_stealing_deque(std::int64_t capacity = 1024)
        : _capacity(capacity), _mask(capacity - 1), _buffer(std::make_unique<T[]>(capacity)) {
        assert(capacity > 0 && (capacity & (capacity - 1)) == 0 && "Capacity must be a power of 2!");
    }

    work_stealing_deque(const work_stealing_deque&) = delete;
    work_stealing_deque& operator=(const work_stealing_deque&) = delete;

    work_stealing_deque(work_stealing_deque&&) = delete;
    work_stealing_deque& operator=(work_stealing_deque&&) = delete;

    ~work_stealing_deque() noexcept {
        for (std::int64_t i = _top.load(std::memory_order_relaxed); i < _bottom.load(std::memory_order_relaxed); ++i) {
            _buffer[i & _mask].~T();
        }
    }

    bool empty() const noexcept {
        return size() == 0;
    }

    std::size_t size() const noexcept {
        const auto b = _bottom.load(std::memory_order_relaxed);
        const auto t = _top.load(std::memory_order_relaxed);
        return static_cast<std::size_t>(b > t ? b - t : 0);
    }

    template <typename... Args>
    bool emplace(Args&&... args) {
        auto b = _bottom.load(std::memory_order_relaxed);
        auto t = _top.load(std::memory_order_acquire);

        if (b - t >= _capacity) {
            return false;
        }

        new (&_buffer[b & _mask]) T(std::forward<Args>(args)...);

        _bottom.store(b + 1, std::memory_order_release);
        return true;
    }

    bool pop(T& item) noexcept {
        auto b = _bottom.load(std::memory_order_relaxed);
        auto t = _top.load(std::memory_order_acquire);

        if (t >= b) {
            return false;
        }

        b--;
        _bottom.store(b, std::memory_order_relaxed);

        std::atomic_thread_fence(std::memory_order_seq_cst);

        t = _top.load(std::memory_order_relaxed);

        if (t < b) {
            item = std::move(_buffer[b & _mask]);
            _buffer[b & _mask].~T();
            return true;
        }

        if (t > b) {
            _bottom.store(b + 1, std::memory_order_relaxed);
            return false;
        }

        if (_top.compare_exchange_strong(t, t + 1, std::memory_order_seq_cst, std::memory_order_relaxed)) {
            _bottom.store(b + 1, std::memory_order_relaxed);
            item = std::move(_buffer[b & _mask]);
            _buffer[b & _mask].~T();
            return true;
        } else {
            _bottom.store(b + 1, std::memory_order_relaxed);
            return false;
        }
    }

    bool steal(T& item) noexcept {
        auto t = _top.load(std::memory_order_acquire);

        while (true) {
            auto b = _bottom.load(std::memory_order_acquire);

            if (t >= b) {
                return false;
            }

            std::atomic_thread_fence(std::memory_order_seq_cst);
            if (_top.compare_exchange_strong(t, t + 1, std::memory_order_seq_cst, std::memory_order_relaxed)) {
                item = std::move(_buffer[t & _mask]);
                return true;
            }
        }
    }

private:
    const std::int64_t _capacity;
    const std::int64_t _mask;

    alignas(hardware_destructive_interference_size) std::atomic<std::int64_t> _top{0};
    alignas(hardware_destructive_interference_size) std::atomic<std::int64_t> _bottom{0};

    std::unique_ptr<T[]> _buffer;
};

#endif /* LIBRARY_FAST_TASK_SRC_TASKS_UTIL_WORK_STEALING_DEQUE */
