// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include "benchmark_helpers.hpp"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <string>

#ifdef _WIN32
    #include <windows.h>

    #include <winbase.h>
#else
    #include <sys/wait.h>
    #include <unistd.h>
#endif

static void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " <command> [args]\n"
              << "Commands:\n"
              << "  list          List all registered benchmarks\n"
              << "  count         Print the number of registered benchmarks\n"
              << "  run <name>    Run a single benchmark by name\n"
              << "  run-all       Run all benchmarks sequentially\n";
}

static void run_benchmark(const benchmark_registry::benchmark_entry& entry) {
    entry.run_fn();
}

#ifdef _WIN32

static bool spawn_child(const char* prog, const char* name) {
    std::string cmd = std::string(prog) + " --_run_child " + name;
    STARTUPINFO si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);

    if (!CreateProcess(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        std::cerr << "Failed to spawn child process for benchmark: " << name << "\n";
        return false;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return exit_code == 0;
}

#else

static bool spawn_child(const char* prog, const char* name) {
    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "fork() failed for benchmark: " << name << "\n";
        return false;
    }
    if (pid == 0) {
        execl(prog, prog, "--_run_child", name, nullptr);
        std::cerr << "execl() failed for benchmark: " << name << "\n";
        _exit(1);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

#endif

static void run_benchmark_child(const char* prog, const benchmark_registry::benchmark_entry& entry) {
    bool ok = spawn_child(prog, entry.name);
    if (!ok)
        std::cerr << "Benchmark " << entry.name << " failed.\n";
}

class number_sep : public std::numpunct<char> {
    virtual char do_thousands_sep() const {
        return '\'';
    }

    virtual char do_decimal_point() const {
        return '.';
    }

    virtual std::string do_grouping() const {
        return "\03";
    }
};

int main(int argc, char** argv) {
    std::cout.imbue(std::locale(std::locale::classic(), new number_sep()));
    if (argc == 3 && std::strcmp(argv[1], "--_run_child") == 0) {
        const char* name = argv[2];
        auto& registry = benchmark_registry::get_registry();
        for (auto& entry : registry) {
            if (std::strcmp(entry.name, name) == 0) {
                run_benchmark(entry);
                return 0;
            }
        }
        std::cerr << "Benchmark not found: " << name << "\n";
        return 1;
    }

    auto registry = auto(benchmark_registry::get_registry());
    std::sort(registry.begin(), registry.end(), [](auto& it, auto& it2) {
        return std::strcmp(it.name, it2.name) > 0;
    });
    if (argc < 2) {
        for (auto& entry : registry)
            run_benchmark_child(argv[0], entry);
        return 0;
    }

    const char* command = argv[1];
    if (std::strcmp(command, "list") == 0) {
        for (auto& entry : registry)
            std::cout << entry.name << (entry.tracks_memory ? " [memory]" : "") << "\n";
    } else if (std::strcmp(command, "count") == 0) {
        std::cout << registry.size() << "\n";
    } else if (std::strcmp(command, "run") == 0) {
        if (argc < 3) {
            std::cerr << "run requires a benchmark name\n";
            return 1;
        }
        const char* name = argv[2];
        bool found = false;
        for (auto& entry : registry) {
            if (std::strcmp(entry.name, name) == 0) {
                run_benchmark_child(argv[0], entry);
                found = true;
                break;
            }
        }
        if (!found) {
            std::cerr << "Benchmark not found: " << name << "\n";
            return 1;
        }
    } else if (std::strcmp(command, "run-all") == 0) {
        for (auto& entry : registry)
            run_benchmark_child(argv[0], entry);
    } else {
        std::cerr << "Unknown command: " << command << "\n";
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}