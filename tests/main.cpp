#include <gtest/gtest.h>
#include <iostream>
#include <string>

#ifdef _WIN32
    #include <windows.h>
LONG WINAPI FreezeOnCrash(EXCEPTION_POINTERS* ExceptionInfo) {
    std::cerr << "\n[FATAL] Unhandled Exception occurred!\n";
    std::cerr << "[FATAL] Process frozen. PID: " << GetCurrentProcessId() << "\n";
    std::cerr << "[FATAL] Waiting for debugger to attach...\n";

    while (!IsDebuggerPresent()) {
        Sleep(1000);
    }
    DebugBreak();

    return EXCEPTION_CONTINUE_SEARCH;
}


int main(int argc, char** argv) {
    bool haltOnException = false;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "-halt_on_exception") {
            haltOnException = true;
            break;
        }
    }

    if (haltOnException) {
        SetUnhandledExceptionFilter(FreezeOnCrash);
    }

    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#else 
#include<csignal>
#include <fstream>
#include <unistd.h>

bool IsDebuggerAttached() {
    std::ifstream statusFile("/proc/self/status");
    std::string line;
    while (std::getline(statusFile, line)) {
        if (line.find("TracerPid:") == 0) {
            return line.find_first_not_of(" \t0", 10) != std::string::npos;
        }
    }
    return false;

}

void FreezeAndBreak() {
    int pid = getpid();

    std::cerr << "\n[FATAL] Unhandled Crash occurred!\n";
    std::cerr << "[FATAL] Process frozen. PID: " << pid << "\n";
    std::cerr << "[FATAL] Waiting for debugger to attach...\n";

    while (!IsDebuggerAttached()) {
        sleep(1);
    }

    raise(SIGTRAP);
}

void LinuxSignalHandler(int signum) {
    FreezeAndBreak();

    std::signal(signum, SIG_DFL);
    raise(signum);
}

int main(int argc, char** argv) {
    bool haltOnException = false;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "-halt_on_exception") {
            haltOnException = true;
            break;
        }
    }

    if (haltOnException) {
        std::signal(SIGSEGV, LinuxSignalHandler);
        std::signal(SIGABRT, LinuxSignalHandler);
        std::signal(SIGILL, LinuxSignalHandler);
        std::signal(SIGFPE, LinuxSignalHandler);
    }

    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif