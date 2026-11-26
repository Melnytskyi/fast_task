// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_SHARED_SEQLOCK
#define FAST_TASK_INCLUDE_SHARED_SEQLOCK

#include "../native/spin_lock.hpp"
#include "primitives.hpp"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <type_traits>

namespace fast_task {
    // Wait-free optimistic reader lock for trivially copyable read-mostly data.
    // Readers perform ZERO atomic writes (no cache-line invalidation across cores).
    // Uses atomic word loads/stores internally to stay data-race-free under C++20/TSan.
    template <class T>
        requires std::is_trivially_copyable_v<T>
    class seqlock {
        static constexpr size_t WORD_SIZE = sizeof(uintptr_t);
        static constexpr size_t WORD_COUNT = (sizeof(T) + WORD_SIZE - 1) / WORD_SIZE;

        alignas(64) std::atomic<uint64_t> seq_{0};
        fast_task::native::spin_lock write_lock_;
        std::atomic<uintptr_t> words_[WORD_COUNT]{};

        void store_words(const T& val) noexcept {
            uintptr_t buf[WORD_COUNT]{};
            std::memcpy(buf, &val, sizeof(T));
            for (size_t i = 0; i < WORD_COUNT; ++i)
                words_[i].store(buf[i], std::memory_order_relaxed);
        }

        void load_words(T& out) const noexcept {
            uintptr_t buf[WORD_COUNT];
            for (size_t i = 0; i < WORD_COUNT; ++i)
                buf[i] = words_[i].load(std::memory_order_relaxed);
            std::memcpy(&out, buf, sizeof(T));
        }

    public:
        seqlock() noexcept {
            T init{};
            store_words(init);
        }

        explicit seqlock(const T& initial) noexcept {
            store_words(initial);
        }

        seqlock(const seqlock&) = delete;
        seqlock& operator=(const seqlock&) = delete;
        seqlock(seqlock&&) = delete;
        seqlock& operator=(seqlock&&) = delete;

        void write(const T& val) noexcept {
            fast_task::lock_guard<fast_task::native::spin_lock> guard(write_lock_);
            const uint64_t s = seq_.load(std::memory_order_relaxed);
            seq_.store(s + 1, std::memory_order_relaxed);
            std::atomic_thread_fence(std::memory_order_release);
            store_words(val);
            seq_.store(s + 2, std::memory_order_release);
        }

        T read() const noexcept {
            T out;
            for (;;) {
                const uint64_t s1 = seq_.load(std::memory_order_acquire);
                if ((s1 & 1u) != 0)
                    continue;
                load_words(out);
                std::atomic_thread_fence(std::memory_order_acquire);
                const uint64_t s2 = seq_.load(std::memory_order_relaxed);
                if (s1 == s2)
                    return out;
            }
        }

        std::optional<T> try_read() const noexcept {
            const uint64_t s1 = seq_.load(std::memory_order_acquire);
            if ((s1 & 1u) != 0)
                return std::nullopt;
            T out;
            load_words(out);
            std::atomic_thread_fence(std::memory_order_acquire);
            if (seq_.load(std::memory_order_relaxed) != s1)
                return std::nullopt;
            return out;
        }
    };
}

#endif /* FAST_TASK_INCLUDE_SHARED_SEQLOCK */
