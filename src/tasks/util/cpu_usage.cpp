// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks/util/cpu_usage.hpp>

static double calculate_cpu_load(fast_task::util::cpu::usage_prev_stat& prev_stat, uint64_t idle_ticks, uint64_t total_ticks) {
    uint64_t total_ticks_since_last_time = total_ticks - prev_stat.total_ticks;
    uint64_t idle_ticks_since_last_time = idle_ticks - prev_stat.idle_ticks;

    double result = 1.0 -
                    ((total_ticks_since_last_time > 0)
                         ? ((double)idle_ticks_since_last_time) / total_ticks_since_last_time
                         : 0);

    prev_stat.total_ticks = total_ticks;
    prev_stat.idle_ticks = idle_ticks;
    return result;
}
#if _WIN64
    #define NOMINMAX
    #include <windows.h>

namespace fast_task::util::cpu {
    static uint64_t file_time_to_int64(FILETIME ft) {
        return (((uint64_t)(ft.dwHighDateTime)) << 32) | ((uint64_t)ft.dwLowDateTime);
    }

    double get_usage(usage_prev_stat& prev_stat) {
        FILETIME idle_time, kernel_time, user_time;
        if (GetSystemTimes(&idle_time, &kernel_time, &user_time))
            return calculate_cpu_load(prev_stat, file_time_to_int64(idle_time), file_time_to_int64(kernel_time) + file_time_to_int64(user_time));
        else
            return -1.0f;
    }
}
#else
    #include <fcntl.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>

namespace fast_task::util::cpu {
    namespace {
        struct proc_stat_reader {
            int fd = -1;
            char buffer[UINT16_MAX + 1];

            proc_stat_reader() noexcept : fd(open("/proc/stat", O_RDONLY | O_CLOEXEC, 0)) {}

            ~proc_stat_reader() {
                if (fd != -1)
                    close(fd);
            }

            proc_stat_reader(const proc_stat_reader&) = delete;
            proc_stat_reader& operator=(const proc_stat_reader&) = delete;
        };
    }

    double get_usage(usage_prev_stat& prev_stat) {
        thread_local proc_stat_reader reader;

        if (reader.fd == -1)
            return -1.0f;
        if (lseek(reader.fd, 0L, SEEK_SET) == (off_t)-1)
            return -1.0f;
        ssize_t res = read(reader.fd, reader.buffer, UINT16_MAX);
        if (res <= 0)
            return -1.0f;
        reader.buffer[res] = 0;

        unsigned long cpu_use = 0;
        unsigned long cpu_nic = 0;
        unsigned long cpu_sys = 0;
        unsigned long cpu_idl = 0;

        const char* point = strstr(reader.buffer, "cpu ");
        if (!point)
            return -1.0f;
        if (sscanf(point, "cpu  %lu %lu %lu %lu", &cpu_use, &cpu_nic, &cpu_sys, &cpu_idl) != 4)
            return -1.0f;
        return calculate_cpu_load(prev_stat, cpu_idl, cpu_use + cpu_nic + cpu_sys + cpu_idl);
    }
}
#endif

namespace fast_task::util::cpu {
    double get_usage_percents(usage_prev_stat& prev_stat) {
        auto tmp = get_usage(prev_stat);
        return tmp < 0 ? tmp : tmp * 100;
    }
}