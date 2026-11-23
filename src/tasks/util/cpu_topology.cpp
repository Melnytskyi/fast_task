// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks/util/cpu_topology.hpp>

#if PLATFORM_LINUX

    #include <cstdio>
    #include <cstdlib>
    #include <cstring>

    #include <fcntl.h>
    #include <sched.h>
    #include <unistd.h>

namespace fast_task::util {
    namespace {
        // Enough for any `shared_cpu_list` of a machine the table tracks.
        constexpr size_t list_capacity = 512;
        // Distinct last-level caches a host may report; beyond that the extra
        // domains collapse into the last id, which only costs steal order.
        constexpr uint8_t max_domains = 64;

        size_t read_small_file(const char* path, char* out, size_t capacity) noexcept {
            const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
            if (fd < 0)
                return 0;
            const ssize_t n = ::read(fd, out, capacity - 1);
            ::close(fd);
            if (n <= 0)
                return 0;
            size_t len = static_cast<size_t>(n);
            while (len != 0 && (out[len - 1] == '\n' || out[len - 1] == '\r'))
                --len;
            out[len] = '\0';
            return len;
        }

        // The `shared_cpu_list` of the highest-level unified cache of `cpu`.
        // Level 2 is used when a machine has no L3 (some embedded parts), so the
        // level is discovered instead of assumed.
        bool llc_list_of_cpu(int cpu, char* out, size_t capacity) noexcept {
            char best[list_capacity] = {};
            int best_level = 0;
            char path[160];
            char value[64];

            for (int index = 0; index < 8; ++index) {
                std::snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cache/index%d/type", cpu, index);
                if (read_small_file(path, value, sizeof(value)) == 0)
                    continue;
                if (std::strcmp(value, "Unified") != 0)
                    continue;

                std::snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cache/index%d/level", cpu, index);
                if (read_small_file(path, value, sizeof(value)) == 0)
                    continue;
                const int level = std::atoi(value);
                if (level <= best_level)
                    continue;

                std::snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cache/index%d/shared_cpu_list", cpu, index);
                if (read_small_file(path, best, sizeof(best)) == 0)
                    continue;
                best_level = level;
            }

            if (best_level == 0)
                return false;
            std::memcpy(out, best, capacity < sizeof(best) ? capacity : sizeof(best));
            out[capacity - 1] = '\0';
            return true;
        }

        struct topology {
            uint8_t llc_of_cpu[tracked_cpu_count]{};
            uint8_t domains = 1;
        };

        topology build() noexcept {
            topology result;
            char list[list_capacity];
            char seen[max_domains][list_capacity] = {};
            uint8_t distinct = 0;

            for (int cpu = 0; cpu < tracked_cpu_count; ++cpu) {
                if (!llc_list_of_cpu(cpu, list, sizeof(list)))
                    break;

                uint8_t domain = 0;
                for (; domain < distinct; ++domain)
                    if (std::strcmp(seen[domain], list) == 0)
                        break;
                if (domain == distinct) {
                    if (distinct < max_domains) {
                        std::strncpy(seen[distinct], list, list_capacity - 1);
                        ++distinct;
                    } else
                        domain = max_domains - 1;
                }
                result.llc_of_cpu[cpu] = domain;
            }

            result.domains = distinct == 0 ? 1 : distinct;
            return result;
        }

        const topology& table() noexcept {
            static const topology built = build();
            return built;
        }
    }

    uint8_t llc_of_cpu(int cpu) noexcept {
        if (cpu < 0 || cpu >= tracked_cpu_count)
            return 0;
        return table().llc_of_cpu[cpu];
    }

    uint8_t current_llc() noexcept {
        return llc_of_cpu(::sched_getcpu());
    }

    uint8_t llc_count() noexcept {
        return table().domains;
    }
}

#else

namespace fast_task::util {
    uint8_t llc_of_cpu(int) noexcept {
        return 0;
    }

    uint8_t current_llc() noexcept {
        return 0;
    }

    uint8_t llc_count() noexcept {
        return 1;
    }
}

#endif
