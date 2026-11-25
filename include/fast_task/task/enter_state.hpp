#ifndef FAST_TASK_INCLUDE_TASK_ENTER_STATE
#define FAST_TASK_INCLUDE_TASK_ENTER_STATE

#include "../shared.hpp"
#include <cstddef>
#include <new>

namespace fast_task {
    struct FT_API enter_state {
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ < 14
        // GCC < 14 can emit aligned movaps to 8-byte-aligned coroutine frame slots on x86_64.
        alignas(void*) char data[120];
#else
        alignas(std::max_align_t) char data[120];
#endif
        void(*destruct)(void*) = nullptr;

        template <class T>
        T* use() {
            static_assert(sizeof(enter_state::data) >= sizeof(T), "enter_state inline storage too small for this type");
            static_assert(alignof(enter_state) >= alignof(T), "enter_state inline storage alignment too small for this type");
            if (destruct) {
                auto fn = destruct;
                destruct = nullptr;
                fn(data);
            }
            T* ptr = new (data) T{};
            destruct = [](void* self) { reinterpret_cast<T*>(self)->~T(); };
            return ptr;
        }

        void release() {
            if (destruct) {
                auto fn = destruct;
                destruct = nullptr;
                fn(data);
            }
        }

        enter_state() = default;
        enter_state(const enter_state&) = delete;
        enter_state& operator=(const enter_state&) = delete;
        enter_state(enter_state&&) = delete;
        enter_state& operator=(enter_state&&) = delete;
        ~enter_state() {
            release();
        }
    };
}

#endif /* FAST_TASK_INCLUDE_TASK_ENTER_STATE */
