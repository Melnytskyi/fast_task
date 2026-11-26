cmake_minimum_required(VERSION 3.20..4.3.3)

project(fast_task VERSION 0.1.0 LANGUAGES CXX)

include(GenerateExportHeader)
include(FetchContent)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

include(cmake/Options.cmake)
include(cmake/Dependencies.cmake)
include(cmake/CompilerOptions.cmake)

add_subdirectory(src)

target_link_libraries(fast_task PRIVATE $<BUILD_INTERFACE:fast_task_flags>)
target_link_libraries(fast_task PRIVATE $<BUILD_INTERFACE:fast_task_dependencies>)
target_include_directories(fast_task PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_include_directories(fast_task PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")

target_compile_options(fast_task PUBLIC $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CXX_COMPILER_ID:MSVC>>:/Zc:__cplusplus>)

include(cmake/Module.cmake)

install(TARGETS fast_task
  EXPORT fast_taskTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/fast_task"
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/include/fast_task.hpp"
  "${CMAKE_CURRENT_BINARY_DIR}/src/fast_task_export.h"
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT fast_taskTargets
  FILE fast_taskTargets.cmake
  NAMESPACE fast_task::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/fast_task
)

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/fast_taskConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/fast_taskConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/fast_task
)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/fast_taskConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/fast_taskConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/fast_taskConfigVersion.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/fast_task
)

if(FAST_TASK_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(FAST_TASK_BUILD_BENCHMARKS)
    add_subdirectory(benchmark)
endif()
