# FAST_TASK_BUILD_MODULE   `fast_task::module`.
#
# Requirements:
#   - CMake >= 3.28 (for CXX_MODULES / FILE_SET support)
#   - A compiler with C++20 modules support (GCC 14+, Clang 16+, MSVC 19.34+)
#   - Ninja or Visual Studio generators (module dependency scanning)

if(NOT FAST_TASK_BUILD_MODULE)
  return()
endif()

if(CMAKE_VERSION VERSION_LESS 3.28)
  message(FATAL_ERROR
    "FAST_TASK_BUILD_MODULE requires CMake 3.28 or newer "
    "(found ${CMAKE_VERSION}) for C++20 module support.")
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 14)
  message(FATAL_ERROR
    "FAST_TASK_BUILD_MODULE requires GCC 14 or newer for C++20 modules "
    "(found ${CMAKE_CXX_COMPILER_VERSION}).")
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 16)
  message(FATAL_ERROR
    "FAST_TASK_BUILD_MODULE requires Clang 16 or newer for C++20 modules "
    "(found ${CMAKE_CXX_COMPILER_VERSION}).")
elseif(MSVC AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 19.34)
  message(FATAL_ERROR
    "FAST_TASK_BUILD_MODULE requires MSVC 19.34 (VS 17.4) or newer for C++20 modules "
    "(found ${CMAKE_CXX_COMPILER_VERSION}).")
endif()

add_library(fast_task_module STATIC)
add_library(fast_task::module ALIAS fast_task_module)

target_sources(fast_task_module
  PUBLIC
    FILE_SET CXX_MODULES
    BASE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include"
    FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/fast_task.cppm"
)

set_target_properties(fast_task_module
  PROPERTIES
  CXX_STANDARD 20
  CXX_STANDARD_REQUIRED ON
  CXX_EXTENSIONS OFF
)

target_link_libraries(fast_task_module
  PUBLIC
    fast_task
  PRIVATE
    fast_task_flags
    fast_task_dependencies
)

target_include_directories(fast_task_module
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# ---------------------------------------------------------------------------
# Installation / export
# ---------------------------------------------------------------------------
include(GNUInstallDirs)

install(TARGETS fast_task_module
  EXPORT fast_taskTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  FILE_SET CXX_MODULES DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/fast_task
)

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/fast_task.cppm"
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
