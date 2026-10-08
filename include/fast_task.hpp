#ifndef INCLUDE_FAST_TASK
#define INCLUDE_FAST_TASK
#include "fast_task/allocator.hpp"
#include "fast_task/debug.hpp"
#include "fast_task/file.hpp"
#include "fast_task/interrupt.hpp"
#include "fast_task/native.hpp"
#include "fast_task/net.hpp"
#include "fast_task/task.hpp"
#include "fast_task/exceptions.hpp"

#if __cplusplus >= 202002
    #include "fast_task/coroutine.hpp"
#endif
#endif /* INCLUDE_FAST_TASK */
