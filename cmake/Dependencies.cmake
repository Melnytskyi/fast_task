
add_library(fast_task_dependencies INTERFACE)
#cpptrace
if(FAST_TASK_ENABLE_DEBUG_API)
    find_package(cpptrace CONFIG)
    if(NOT cpptrace_FOUND)
        FetchContent_Declare(
            cpptrace
            GIT_REPOSITORY https://github.com/jeremy-rifkin/cpptrace.git
            GIT_TAG        v1.0.4
        )
        FetchContent_MakeAvailable(cpptrace)
    endif()
    target_link_libraries(fast_task_dependencies INTERFACE cpptrace::cpptrace)
endif()

#BOOST::context
set(BOOST_INCLUDE_LIBRARIES context)
find_package(Boost CONFIG COMPONENTS context)
if(NOT Boost_FOUND)
    cmake_policy(PUSH)
    if(POLICY CMP0135)
        cmake_policy(SET CMP0135 NEW)
    endif()

    FetchContent_Declare(
        Boost
        URL "https://github.com/boostorg/boost/releases/download/boost-1.90.0/boost-1.90.0-cmake.tar.xz"
    )
    FetchContent_MakeAvailable(Boost)
    cmake_policy(POP)
endif()
target_link_libraries(fast_task_dependencies INTERFACE Boost::context)
target_include_directories(fast_task_dependencies INTERFACE ${Boost_INCLUDE_DIRS})
unset(BOOST_INCLUDE_LIBRARIES)

#concurrentqueue
find_package(concurrentqueue CONFIG)
if(NOT concurrentqueue_FOUND)
    FetchContent_Declare(
        concurrentqueue
        GIT_REPOSITORY https://github.com/cameron314/concurrentqueue.git
        GIT_TAG        v1.0.5
    )
    FetchContent_MakeAvailable(concurrentqueue)
    if(NOT TARGET concurrentqueue::concurrentqueue)
        add_library(concurrentqueue::concurrentqueue ALIAS concurrentqueue)
    endif()
    file(GLOB _cq_public_headers "${concurrentqueue_SOURCE_DIR}/*.h")
    file(MAKE_DIRECTORY "${concurrentqueue_SOURCE_DIR}/concurrentqueue/moodycamel")
    file(COPY ${_cq_public_headers} DESTINATION "${concurrentqueue_SOURCE_DIR}/concurrentqueue/moodycamel")
    set(CONCURRENTQUEUE_EXTRA_INCLUDE_DIR "${concurrentqueue_SOURCE_DIR}")
endif()
target_link_libraries(fast_task_dependencies INTERFACE concurrentqueue::concurrentqueue)
target_include_directories(fast_task_dependencies INTERFACE ${concurrentqueue_INCLUDE_DIRS} ${CONCURRENTQUEUE_EXTRA_INCLUDE_DIR})
unset(CONCURRENTQUEUE_EXTRA_INCLUDE_DIR)



if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    #liburing
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBURING IMPORTED_TARGET liburing)
    if(LIBURING_FOUND)
        target_include_directories(fast_task_dependencies INTERFACE ${LIBURING_INCLUDE_DIRS})
        target_link_libraries(fast_task_dependencies INTERFACE PkgConfig::LIBURING)
    else()
        include(ExternalProject)
        ExternalProject_Add(
            liburing
            GIT_REPOSITORY https://github.com/axboe/liburing.git
            GIT_TAG        liburing-2.13
            CONFIGURE_COMMAND <SOURCE_DIR>/configure
            BUILD_COMMAND make -C <SOURCE_DIR> src/liburing.a
            INSTALL_COMMAND ""
            BUILD_IN_SOURCE 1
        )
        ExternalProject_Get_Property(liburing SOURCE_DIR)
        target_include_directories(fast_task_dependencies INTERFACE ${SOURCE_DIR}/src/include)
        add_dependencies(fast_task_dependencies liburing)
        target_link_libraries(fast_task_dependencies INTERFACE ${SOURCE_DIR}/src/liburing.a)
    endif()

        
    #c-ares
    find_package(c-ares CONFIG)
    if(NOT c-ares_FOUND)
        FetchContent_Declare(
            c_ares
            GIT_REPOSITORY https://github.com/c-ares/c-ares.git
            GIT_TAG        v1.34.5
        )
        FetchContent_MakeAvailable(c_ares)
    endif()
    target_link_libraries(fast_task_dependencies INTERFACE c-ares::cares)
    target_include_directories(fast_task_dependencies INTERFACE ${c-ares_INCLUDE_DIRS})

    #valgrind
    find_path(VALGRIND_INCLUDE_DIR valgrind/valgrind.h)
    if(VALGRIND_INCLUDE_DIR)
        target_include_directories(fast_task_dependencies INTERFACE ${VALGRIND_INCLUDE_DIR})
    else()
        target_include_directories(fast_task_dependencies INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/valgrind-stubs)
    endif()
endif()