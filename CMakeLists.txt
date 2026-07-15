cmake_minimum_required(VERSION 3.20..4.3.3)

project(fast_task CXX)

include(GenerateExportHeader)
include(FetchContent)

include(cmake/Options.cmake)
include(cmake/Dependencies.cmake)
include(cmake/CompilerOptions.cmake)

add_subdirectory(src)

target_link_libraries(fast_task PRIVATE fast_task_flags)
target_link_libraries(fast_task PRIVATE fast_task_dependencies)
set_property(TARGET fast_task PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
target_include_directories(fast_task PUBLIC "include")
target_include_directories(fast_task PRIVATE "src")

if(FAST_TASK_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
