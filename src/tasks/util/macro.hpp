#ifndef SRC_TASKS_UTIL_MACRO
#define SRC_TASKS_UTIL_MACRO
//platforms: windows, linux, macos, ios, android, unknown
#if defined(_WIN32) || defined(_WIN64)
    #define PLATFORM_WINDOWS 1
#elif defined(__ANDROID__) || defined(__ANDROID_API__) || defined(ANDROID)
    #define PLATFORM_ANDROID 1
#elif defined(__linux__) || defined(__LINUX__) || defined(__linux) || defined(__gnu_linux__)
    #define PLATFORM_LINUX 1
#elif defined(__APPLE__)
    #include <TargetConditionals.h>
    #if (defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE) || defined(__IPHONE_OS_VERSION_MIN_REQUIRED) || defined(__IPHONE_OS_VERSION_MAX_ALLOWED)
        #define PLATFORM_IOS 1
    #else
        #define PLATFORM_MACOS 1
    #endif
#elif (defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE) || defined(__IPHONE_OS_VERSION_MIN_REQUIRED) || defined(__IPHONE_OS_VERSION_MAX_ALLOWED)
    #define PLATFORM_IOS 1
#elif defined(__MACH__)
    #define PLATFORM_MACOS 1
#else
    #define PLATFORM_UNKNOWN 1
#endif

#if defined(_MSC_VER)
    #define NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
    #define NOINLINE __attribute__((noinline))
#else
    #define NOINLINE
#endif

#endif /* SRC_TASKS_UTIL_MACRO */
