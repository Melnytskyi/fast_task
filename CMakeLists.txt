cmake_minimum_required(VERSION 3.31)

if(MSVC)
  project(fast_task CXX ASM_MASM)
  set(ASM_FILE src/asm.asm)
else(MSVC)
  project(fast_task CXX)
  set(ASM_FILE )
endif(MSVC)
option(FAST_TASK_STATIC "Enable static build for fast task library" ON)

set(fast_task_INCLUDE_DIR "src" "include")

FILE(GLOB SRCFILES 
        ${ASM_FILE}
        src/*.cpp
        src/*/*.cpp
        src/*/*/*.cpp
        src/*/*/*/*.cpp
)
if(FAST_TASK_STATIC)
  add_library(fast_task STATIC ${SRCFILES})
  target_compile_definitions(fast_task PUBLIC -DFT_API_STATIC)
else()
  add_library(fast_task SHARED ${SRCFILES})
endif()

include(GenerateExportHeader)
generate_export_header(
  fast_task
  BASE_NAME fast_task
  EXPORT_MACRO_NAME FT_API
  NO_EXPORT_MACRO_NAME FT_API_LOCAL
  STATIC_DEFINE FT_API_STATIC
)
target_include_directories(fast_task PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
  $<INSTALL_INTERFACE:include>
)
target_compile_definitions(fast_task PRIVATE ENABLE_BOOST_PREPROCESSOR ON)
if(MSVC)
else()
  target_compile_definitions(fast_task Boost_USE_STATIC_LIBS ${FAST_TASK_STATIC})
  target_compile_definitions(fast_task Boost_USE_STATIC_RUNTIME ${FAST_TASK_STATIC})
endif()

find_package(Boost REQUIRED COMPONENTS context)
target_include_directories(fast_task PRIVATE ${Boost_INCLUDE_DIRS} ${fast_task_INCLUDE_DIR})
set_target_properties(fast_task
  PROPERTIES
  CXX_STANDARD 23
  CXX_EXTENSIONS OFF
)
target_link_libraries(fast_task PUBLIC ${Boost_LIBRARIES})

if(MSVC)
  set_property(TARGET fast_task PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  target_compile_options(fast_task PUBLIC $<$<COMPILE_LANGUAGE:CXX>:/EHa>)
  target_compile_options(fast_task PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/utf-8>)
  target_compile_options(fast_task PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/wd4100>)
  target_compile_options(fast_task PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/wd4505>)
  target_compile_options(fast_task PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/wd4324>)
  target_compile_options(fast_task PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/wd4717>)
  target_compile_options(fast_task PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/sdl>)
  target_compile_options(fast_task PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/GF>)
  target_compile_options(fast_task PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/W4>)
  target_compile_options(fast_task PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/WX>)
  target_compile_options(fast_task PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/MP>)
  target_compile_options(fast_task PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/Zc:preprocessor>)

  target_compile_options(fast_task PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/permissive->)
else()
  target_compile_options(fast_task PUBLIC -m64)
  target_compile_options(fast_task PRIVATE -g)
  target_compile_options(fast_task PRIVATE -Wall)
  target_compile_options(fast_task PRIVATE -Wextra)
  target_compile_options(fast_task PRIVATE --pedantic)
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  target_compile_options(fast_task PRIVATE -Wno-unused-function)
  
  if(MSVC)
    target_compile_options(fast_task PRIVATE /clang:-ftemplate-backtrace-limit=0)
  endif(MSVC)
endif()