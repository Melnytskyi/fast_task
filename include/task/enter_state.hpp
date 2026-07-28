#ifndef FAST_TASK_INCLUDE_TASK_ENTER_STATE
#define FAST_TASK_INCLUDE_TASK_ENTER_STATE

#include "../shared.hpp"

namespace fast_task {
    struct FT_API enter_state {
        char data[56];
        void(*destruct)(void*) = nullptr;

        template <class T>
        T* use() {
            static_assert(sizeof(enter_state::data) >= sizeof(T), "enter_state inline storage too small for this type");
            if(destruct)
                destruct(data);
            destruct = [](void* self){ reinterpret_cast<T*>(self)->~T(); };
            return new (&data) T{};
        }

        void release() {
            if (destruct)
                destruct(data);
            destruct = nullptr;
        }

        enter_state() = default;
        ~enter_state(){
            release();
        }
    };
}

#endif /* FAST_TASK_INCLUDE_TASK_ENTER_STATE */
