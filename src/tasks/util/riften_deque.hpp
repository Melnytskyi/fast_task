// This part of namespace `riften` is adapted code from https://github.com/ConorWilliams/ConcurrentDeque
// The namespace licensed under Mozilla Public License Version 2.0 as stated in commit 1552c895c60b2ca8986abd3f3e4fd38847687d25
//
// changes:
//   dropped requirement for the types be trivially destructible
//   The buffer now has fixed capacity
//

#ifndef RIFTEN_DEQUE
#define RIFTEN_DEQUE
#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <optional>
#include <utility>
#include <vector>

namespace riften {

#ifdef __cpp_lib_hardware_interference_size
    constexpr std::size_t hardware_destructive_interference_size = std::hardware_destructive_interference_size * 2;
#else
    constexpr std::size_t hardware_destructive_interference_size = 128;
#endif
    namespace detail {

        // Basic wrapper around a c-style array of atomic objects that provides modulo load/stores. Capacity
        // must be a power of 2.
        template <std::default_initializable T>
        struct RingBuff {
        public:
            explicit RingBuff(std::int64_t cap)
                : _cap{cap}, _mask{cap - 1} {
                assert(cap && (!(cap & (cap - 1))) && "Capacity must be buf power of 2!");
            }

            std::int64_t capacity() const noexcept {
                return _cap;
            }

            // Store (copy) at modulo index
            void store(std::int64_t i, T&& x) noexcept
                requires std::is_nothrow_move_assignable_v<T>
            {
                _buff[i & _mask] = std::move(x);
            }

            // Load (copy) at modulo index
            T load(std::int64_t i) const noexcept
                requires std::is_nothrow_move_constructible_v<T>
            {
                return std::move(_buff[i & _mask]);
            }

        private:
            std::int64_t _cap;  // Capacity of the buffer
            std::int64_t _mask; // Bit mask to perform modulo capacity operations

            std::unique_ptr<T[]> _buff = std::make_unique_for_overwrite<T[]>(_cap);
        };

    } // namespace detail

    // Lock-free single-producer multiple-consumer deque. Only the deque owner can perform pop and push
    // operations where the deque behaves like a stack. Others can (only) steal data from the deque, they see
    // a FIFO queue. All threads must have finished using the deque before it is destructed. T must be
    // default initializable, trivially destructible and have nothrow move constructor/assignment operators.
    template <std::default_initializable T>
    class Deque {
    public:
        // Constructs the deque with a given capacity the capacity of the deque (must be power of 2)
        explicit Deque(std::int64_t cap = 1024);

        // Move/Copy is not supported
        Deque(Deque const& other) = delete;
        Deque& operator=(Deque const& other) = delete;

        //  Query the size at instance of call
        std::size_t size() const noexcept;

        // Query the capacity at instance of call
        int64_t capacity() const noexcept;

        // Test if empty at instance of call
        bool empty() const noexcept;

        // Emplace an item to the deque. Only the owner thread can insert an item to the deque. The
        // operation can trigger the deque to resize its cap if more space is required. Provides the
        // strong exception guarantee.
        template <typename... Args>
        bool emplace(Args&&... args);

        // Pops out an item from the deque. Only the owner thread can pop out an item from the deque.
        // The return can be a std::nullopt if this operation fails (empty deque).
        std::optional<T> pop() noexcept;

        // Steals an item from the deque Any threads can try to steal an item from the deque. The return
        // can be a std::nullopt if this operation failed (not necessarily empty).
        std::optional<T> steal() noexcept;

        // Destruct the deque, all threads must have finished using the deque.
        ~Deque() noexcept;

    private:
        alignas(hardware_destructive_interference_size) std::atomic<std::int64_t> _top;
        alignas(hardware_destructive_interference_size) std::atomic<std::int64_t> _bottom;
        detail::RingBuff<T> _buffer;

        // Convenience aliases.
        static constexpr std::memory_order relaxed = std::memory_order_relaxed;
        static constexpr std::memory_order consume = std::memory_order_consume;
        static constexpr std::memory_order acquire = std::memory_order_acquire;
        static constexpr std::memory_order release = std::memory_order_release;
        static constexpr std::memory_order seq_cst = std::memory_order_seq_cst;
    };

    template <std::default_initializable T>
    Deque<T>::Deque(std::int64_t cap)
        : _top(0), _bottom(0), _buffer(cap) {
    }

    template <std::default_initializable T>
    std::size_t Deque<T>::size() const noexcept {
        int64_t b = _bottom.load(relaxed);
        int64_t t = _top.load(relaxed);
        return static_cast<std::size_t>(b >= t ? b - t : 0);
    }

    template <std::default_initializable T>
    int64_t Deque<T>::capacity() const noexcept {
        return _buffer.capacity();
    }

    template <std::default_initializable T>
    bool Deque<T>::empty() const noexcept {
        return !size();
    }

    template <std::default_initializable T>
    template <typename... Args>
    bool Deque<T>::emplace(Args&&... args) {
        // Construct before acquiring slot in-case constructor throws
        T object(std::forward<Args>(args)...);

        std::int64_t b = _bottom.load(relaxed);
        std::int64_t t = _top.load(acquire);

        if (_buffer.capacity() < (b - t) + 1)
            return false;

        // Construct new object, this does not have to be atomic as no one can steal this item until after we
        // store the new value of bottom, ordering is maintained by surrounding atomics.
        _buffer.store(b, std::move(object));

        std::atomic_thread_fence(release);
        _bottom.store(b + 1, relaxed);
        return true;
    }

    template <std::default_initializable T>
    std::optional<T> Deque<T>::pop() noexcept {
        std::int64_t b = _bottom.load(relaxed) - 1;

        _bottom.store(b, relaxed); // Stealers can no longer steal

        std::atomic_thread_fence(seq_cst);
        std::int64_t t = _top.load(relaxed);

        if (t <= b) {
            // Non-empty deque
            if (t == b) {
                // The last item could get stolen, by a stealer that loaded bottom before our write above
                if (!_top.compare_exchange_strong(t, t + 1, seq_cst, relaxed)) {
                    // Failed race, thief got the last item.
                    _bottom.store(b + 1, relaxed);
                    return std::nullopt;
                }
                _bottom.store(b + 1, relaxed);
            }

            // Can delay load until after acquiring slot as only this thread can push(), this load is not
            // required to be atomic as we are the exclusive writer.
            return _buffer.load(b);

        } else {
            _bottom.store(b + 1, relaxed);
            return std::nullopt;
        }
    }

    template <std::default_initializable T>
    std::optional<T> Deque<T>::steal() noexcept {
        std::int64_t t = _top.load(acquire);
        std::atomic_thread_fence(seq_cst);
        std::int64_t b = _bottom.load(acquire);

        if (t < b) {
            // Must load *before* acquiring the slot as slot may be overwritten immediately after acquiring.
            // This load is NOT required to be atomic even-though it may race with an overrite as we only
            // return the value if we win the race below garanteeing we had no race during our read. If we
            // loose the race then 'x' could be corrupt due to read-during-write race but as T is trivially
            // destructible this does not matter.
            T x = _buffer.load(t);

            if (!_top.compare_exchange_strong(t, t + 1, seq_cst, relaxed)) {
                // Failed race.
                return std::nullopt;
            }

            return x;

        } else {
            // Empty deque.
            return std::nullopt;
        }
    }

    template <std::default_initializable T>
    Deque<T>::~Deque() noexcept {}

} // namespace riften

#endif /* RIFTEN_DEQUE */
