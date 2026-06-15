file(GLOB_RECURSE SRCFILES CONFIGURE_DEPENDS "*.cpp")
if(WIN32 AND (FAST_TASK_INCLUDE_THREAD_INTERRUPT_CODE OR FAST_TASK_ENABLE_PREEMPTIVE_SCHEDULER))
  enable_language(ASM_MASM)
  list(APPEND SRCFILES asm.asm)
endif()

if(FAST_TASK_STATIC)
  add_library(fast_task STATIC ${SRCFILES})
  target_compile_definitions(fast_task PUBLIC FT_API_STATIC)
else()
  add_library(fast_task SHARED ${SRCFILES})
endif()
set_target_properties(fast_task
  PROPERTIES
  CXX_STANDARD 20
  CXX_EXTENSIONS OFF
)
target_link_options(fast_task PRIVATE -flto=auto)

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