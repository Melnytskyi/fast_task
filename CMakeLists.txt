cmake_minimum_required(VERSION 3.20)
project(fast_task CXX)
set(CMAKE_CXX_STANDARD 23)
set(Boost_NO_WARN_NEW_VERSIONS ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(fast_task_src_INCLUDE_DIR "src")
set(fast_task_INCLUDE_DIR ${fast_task_src_INCLUDE_DIR})

if(MSVC)  
  add_definitions(/MP)
  add_definitions(/Zc:preprocessor)
  enable_language(ASM_MASM)
  string(REPLACE "/MD" "/MT" CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})
  string(REPLACE "/MD" "/MT" CMAKE_CXX_FLAGS_DEBUG ${CMAKE_CXX_FLAGS_DEBUG})
  string(REPLACE "/MD" "/MT" CMAKE_CXX_FLAGS_RELEASE ${CMAKE_CXX_FLAGS_RELEASE})
  string(REPLACE "/Gv" "/Gr" CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS_RELEASE})
  string(REPLACE "/Gv" "/Gr" CMAKE_CXX_FLAGS_DEBUG ${CMAKE_CXX_FLAGS_DEBUG})
  string(REPLACE "/Gv" "/Gr" CMAKE_CXX_FLAGS_RELEASE ${CMAKE_CXX_FLAGS_RELEASE})
else(MSVC)
  add_compile_options(-m64)
  add_compile_options(-g)
  set(Boost_USE_STATIC_LIBS ON)
  set(Boost_USE_STATIC_RUNTIME ON)
endif(MSVC)
set(ENABLE_BOOST_PREPROCESSOR ON)

FILE(GLOB SRCFILES 
        src/*.cpp
        src/tasks/*.cpp
        src/tasks/classes/*.cpp
        src/tasks/classes/misc/*.cpp
        src/tasks/classes/synchronization/*.cpp
        src/tasks/classes/task/*.cpp
        src/tasks/util/*.cpp
)


IF(MSVC)
  SET(CMAKE_CXX_FLAGS "/EHsc")
ENDIF(MSVC)

find_package(Boost REQUIRED COMPONENTS context)
include_directories(${Boost_INCLUDE_DIRS} ${fast_task_INCLUDE_DIR})

add_library(fast_task STATIC ${SRCFILES})
set_property(TARGET fast_task PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
target_link_libraries(fast_task PRIVATE ${Boost_LIBRARIES})