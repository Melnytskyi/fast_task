// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks/_internal.hpp>

#if PLATFORM_WINDOWS
    #include <Windows.h>
    #include <locale>
#elif PLATFORM_LINUX
#endif

namespace fast_task {
    thread_local executors_local loc;
    executor_global glob;

    bool can_be_scheduled_task_to_hot() {
        if (task::max_running_tasks)
            if (task::max_running_tasks <= (glob.tasks_in_swap + glob.tasks.size()))
                return false;
        return true;
    }


#if PLATFORM_WINDOWS
    bool _set_name_thread_dbg(const std::string& name, unsigned long thread_id) {
        std::wstring_convert<std::codecvt<wchar_t, char, mbstate_t>> convert;
        std::wstring wname = convert.from_bytes(name);
        HANDLE thread = OpenThread(THREAD_SET_LIMITED_INFORMATION, false, thread_id);
        if (!thread)
            return false;
        bool result = SUCCEEDED(SetThreadDescription(thread, wname.c_str()));
        CloseHandle(thread);
        return result;
    }

    bool _set_name_thread_dbg(const std::string& name) {
        std::wstring_convert<std::codecvt<wchar_t, char, mbstate_t>> convert;
        std::wstring wname = convert.from_bytes(name);
        return SUCCEEDED(SetThreadDescription(GetCurrentThread(), wname.c_str()));
    }

    std::string _get_name_thread_dbg(unsigned long thread_id) {
        HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, thread_id);
        if (!thread)
            return "";
        WCHAR* res;
        if (SUCCEEDED(GetThreadDescription(thread, &res))) {
            std::wstring_convert<std::codecvt<wchar_t, char, mbstate_t>> convert;
            std::string result = convert.to_bytes(res);
            LocalFree(res);
            CloseHandle(thread);
            return result;
        } else {
            CloseHandle(thread);
            return "";
        }
    }

    unsigned long _thread_id() {
        return GetCurrentThreadId();
    }

#elif PLATFORM_LINUX
    bool _set_name_thread_dbg(const std::string& name) {
        if (name.size() > 15)
            return false;
        return pthread_setname_np(pthread_self(), name.c_str()) == 0;
    }

    bool _set_name_thread_dbg(const std::string& name, unsigned long id) {
        if (name.size() > 15)
            return false;
        return pthread_setname_np(id, name.c_str()) == 0;
    }

    std::string _get_name_thread_dbg(unsigned long thread_id) {
        char name[16];
        if (pthread_getname_np(pthread_t(thread_id), name, 16) != 0)
            return "";
        return name;
    }

    unsigned long _thread_id() {
        return pthread_self();
    }
#endif
}
