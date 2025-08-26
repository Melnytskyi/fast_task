cmake_minimum_required(VERSION 3.31)
project(fast_task CXX)
set(CMAKE_CXX_STANDARD 23)
set(Boost_NO_WARN_NEW_VERSIONS ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(fast_task_src_INCLUDE_DIR "src")
set(fast_task_INCLUDE_DIR ${fast_task_src_INCLUDE_DIR})

if(MSVC)
  string(APPEND CMAKE_CXX_FLAGS " /MP /Zc:preprocessor /EHa /permissive-")
  enable_language(ASM_MASM)
else(MSVC)
  add_definitions(-m64 -g -Wall -Wextra -pedantic)
  set(Boost_USE_STATIC_LIBS ON)
  set(Boost_USE_STATIC_RUNTIME ON)
endif(MSVC)
set(ENABLE_BOOST_PREPROCESSOR ON)

FILE(GLOB SRCFILES 
        src/asm.asm 
        src/*.cpp
        src/*/*.cpp
        src/*/*/*.cpp
        src/*/*/*/*.cpp
)

find_package(Boost REQUIRED COMPONENTS context)
include_directories(${Boost_INCLUDE_DIRS} ${fast_task_INCLUDE_DIR})

add_library(fast_task STATIC ${SRCFILES})
set_property(TARGET fast_task PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
target_link_libraries(fast_task PRIVATE ${Boost_LIBRARIES})