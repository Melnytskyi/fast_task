// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_CONTEXT_SWITCH
#define FAST_TASK_CORE_CONTEXT_SWITCH

#include <chrono>

#include <boost/context/continuation.hpp>

#include <fast_task/shared.hpp>
#include <fast_task/task.hpp>

namespace fast_task {
    std::chrono::nanoseconds FT_API_LOCAL next_quantum(task_priority priority, std::chrono::nanoseconds& current_available_quantum);
    std::chrono::nanoseconds FT_API_LOCAL peek_quantum(task_priority priority, std::chrono::nanoseconds current_available_quantum);
    void FT_API_LOCAL task_switch(task_priority priority, std::chrono::nanoseconds& current_available_quantum, std::chrono::nanoseconds elapsed);
    std::chrono::nanoseconds FT_API_LOCAL init_quantum(task_priority priority);

    void FT_API_LOCAL swapCtx();
    void FT_API_LOCAL swapCtxRelock(const mutex_unify& mut0);
    void FT_API_LOCAL swapCtxUnlock(const mutex_unify& mut0);
    boost::context::continuation FT_API_LOCAL context_exec(boost::context::continuation&& sink);
    boost::context::continuation FT_API_LOCAL context_ex_handle(boost::context::continuation&& sink);
    bool FT_API_LOCAL checkCancellation() noexcept;
    void FT_API_LOCAL forceCancelCancellation(const task_cancellation& restart);
}

#endif /* FAST_TASK_CORE_CONTEXT_SWITCH */
