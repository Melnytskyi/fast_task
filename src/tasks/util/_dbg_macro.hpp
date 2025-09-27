
// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
#ifndef FAST_TASK_SRC_TASKS_UTIL_DBG_MACRO
#define FAST_TASK_SRC_TASKS_UTIL_DBG_MACRO
#ifdef FT_DEBUG_API_ENABLED
    #define FT_DEBUG_ONLY(x) x
    #define FT_DEBUG_FIELD(type, name) type name
#else
    #define FT_DEBUG_ONLY(x)
    #define FT_DEBUG_FIELD(type, name)
#endif

#endif /* FAST_TASK_SRC_TASKS_UTIL_DBG_MACRO */
