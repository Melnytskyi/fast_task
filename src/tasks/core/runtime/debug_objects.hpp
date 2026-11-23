// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_CORE_DEBUG_OBJECTS
#define FAST_TASK_CORE_DEBUG_OBJECTS

#include <string>

#include <fast_task/shared.hpp>
#include <tasks/util/_dbg_macro.hpp>

namespace fast_task {
    class condition_variable;
    class deadline_timer;
    class limiter;
    class mutex;
    class queue;
    class recursive_mutex;
    class rw_mutex;
    class semaphore;
    struct task_object;

    bool FT_API_LOCAL _set_name_thread_dbg(const std::string& name, unsigned long thread_id);
    bool FT_API_LOCAL _set_name_thread_dbg(const std::string& name);
    std::string FT_API_LOCAL _get_name_thread_dbg(unsigned long thread_id);
    unsigned long FT_API_LOCAL _thread_id();
    bool FT_API_LOCAL is_debugger_attached();

    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(recursive_mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(rw_mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(condition_variable*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(task_object*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(semaphore*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(limiter*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(queue*));
    FT_DEBUG_ONLY(void FT_API_LOCAL register_object(deadline_timer*));

    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(recursive_mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(rw_mutex*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(condition_variable*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(task_object*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(semaphore*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(limiter*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(queue*));
    FT_DEBUG_ONLY(void FT_API_LOCAL unregister_object(deadline_timer*));
}

#endif /* FAST_TASK_CORE_DEBUG_OBJECTS */
