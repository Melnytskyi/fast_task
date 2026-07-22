
option(FAST_TASK_STATIC "Enable static build for fast task library" ON)
option(FAST_TASK_BUILD_TESTS "Build the test suite" OFF)
option(FAST_TASK_BUILD_BENCHMARKS "Build the benchmark suite" OFF)
option(FAST_TASK_DISABLE_IO_TESTS "Disable I/O tests" ON)
option(FAST_TASK_ENABLE_DEBUG_API "Enable the debugging and introspection API" OFF)
option(FAST_TASK_ENABLE_ABORT_IF_ALREADY_STARTED "Abort if the task already started" OFF)
option(FAST_TASK_ENABLE_ABORT_IF_NEVER_STARTED "Abort if task's destructor called before the task even started" OFF)
option(FAST_TASK_ENABLE_PREEMPTIVE_SCHEDULER "Enables time sliced preemption for tasks, the tasks should use interrupt_unsafe_region on regions where preemption should be disabled." OFF)
option(FAST_TASK_INCLUDE_THREAD_INTERRUPT_CODE "Allows the code to stop the thread and execute custom function on top of its stack, doesn't have effect if FAST_TASK_ENABLE_PREEMPTIVE_SCHEDULER enabled" ON)
option(FAST_TASK_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

set(FAST_TASK_GUARD_PAGE_COUNT 1 CACHE STRING
  "Number of PROT_NONE (Linux) / PAGE_GUARD (Windows) pages placed at the bottom of each task stack. Set to 0 to disable guard pages entirely.")
if(NOT FAST_TASK_GUARD_PAGE_COUNT MATCHES "^[0-9]+$")
  message(FATAL_ERROR "FAST_TASK_GUARD_PAGE_COUNT must be a non-negative integer.")
endif()

set(FAST_TASK_TASK_TRANSFERS_LIMIT 8 CACHE 
STRING 
"Limits the count of the cooperative task transfers without making the context switch
  - 0: No limit, the task can be transferred any number of times.
  - N: The task can only be transferred N times, after that the transfer requests would be ignored.")

if(NOT FAST_TASK_TASK_TRANSFERS_LIMIT MATCHES "^[0-9]+$")
  message(FATAL_ERROR "FAST_TASK_TASK_TRANSFERS_LIMIT must be a non-negative integer.")
endif()

set(FAST_TASK_MAX_EXECUTORS 1024 CACHE STRING "Limits the max amount of work stealing entries")

if(NOT FAST_TASK_MAX_EXECUTORS MATCHES "^[0-9]+$")
  message(FATAL_ERROR "FAST_TASK_MAX_EXECUTORS must be a non-negative integer.")
endif()

set(FAST_TASK_BINDED_MAX_SLOTS 64 CACHE STRING "Max threads per binded pool")

if(NOT FAST_TASK_BINDED_MAX_SLOTS MATCHES "^[0-9]+$")
  message(FATAL_ERROR "FAST_TASK_BINDED_MAX_SLOTS must be a non-negative integer.")
endif()

set(FAST_TASK_MAX_STEAL_ATTEMPTS 3 CACHE STRING "Limits count of steal attempts from random worker")

if(NOT FAST_TASK_MAX_STEAL_ATTEMPTS MATCHES "^[0-9]+$")
  message(FATAL_ERROR "FAST_TASK_MAX_STEAL_ATTEMPTS must be a non-negative integer.")
endif()

set(FAST_TASK_TIMER_PRECISION "1ms" CACHE 
STRING 
"Timer wheel precision and resolution: 1us (microsecond), 1ms (millisecond), 10ms (decisecond)
  - 1us: 1 microsecond ticks. Uses platform hi-res timer if available, otherwise spin loop with _mm_pause.
  - 1ms: 1 millisecond ticks. Standard precision.
  - 10ms: 10 millisecond ticks. Low-precision, low-overhead. Good for infrequent timers.")

set_property(CACHE FAST_TASK_TIMER_PRECISION PROPERTY STRINGS "1us" "1ms" "10ms")

set(FAST_TASK_EXCEPTION_POLICY "NONE" CACHE 
STRING 
"Sets the exception handling policy for context switches:
  - NONE: No checks.
  - CHECK: abort if a context switch occurs in catch block or in other exception handling stage. (Has performance cost)
  - PRESERVE: Preserve the exception on context switch and rethrow when switched back. (Has performance cost)")

set_property(CACHE FAST_TASK_EXCEPTION_POLICY PROPERTY STRINGS "NONE" "CHECK" "PRESERVE")



set(FAST_TASK_PREEMPT_BACKGROUND_BASIC_QUANTUM_NS "15 * 1000000" CACHE STRING "Sets the preemption time slicing config")
set(FAST_TASK_PREEMPT_LOW_BASIC_QUANTUM_NS "30 * 1000000" CACHE STRING "Sets the preemption time slicing config")
set(FAST_TASK_PREEMPT_LOWER_BASIC_QUANTUM_NS "40 * 1000000" CACHE STRING "Sets the preemption time slicing config")
set(FAST_TASK_PREEMPT_NORMAL_BASIC_QUANTUM_NS "80 * 1000000" CACHE STRING "Sets the preemption time slicing config")
set(FAST_TASK_PREEMPT_HIGHER_BASIC_QUANTUM_NS "90 * 1000000" CACHE STRING "Sets the preemption time slicing config")
set(FAST_TASK_PREEMPT_HIGH_BASIC_QUANTUM_NS "120 * 1000000" CACHE STRING "Sets the preemption time slicing config")

set(FAST_TASK_PREEMPT_BACKGROUND_MAX_QUANTUM_NS "30 * 1000000" CACHE STRING "Sets the preemption time slicing config")
set(FAST_TASK_PREEMPT_LOW_MAX_QUANTUM_NS "60 * 1000000" CACHE STRING "Sets the preemption time slicing config")
set(FAST_TASK_PREEMPT_LOWER_MAX_QUANTUM_NS "80 * 1000000" CACHE STRING "Sets the preemption time slicing config")
set(FAST_TASK_PREEMPT_NORMAL_MAX_QUANTUM_NS "160 * 1000000" CACHE STRING "Sets the preemption time slicing config")
set(FAST_TASK_PREEMPT_HIGHER_MAX_QUANTUM_NS "180 * 1000000" CACHE STRING "Sets the preemption time slicing config")
set(FAST_TASK_PREEMPT_HIGH_MAX_QUANTUM_NS "240 * 1000000" CACHE STRING "Sets the preemption time slicing config")

mark_as_advanced(FAST_TASK_ENABLE_PREEMPTIVE_SCHEDULER)
mark_as_advanced(FAST_TASK_EXCEPTION_POLICY)
mark_as_advanced(FAST_TASK_TASK_TRANSFERS_LIMIT)
mark_as_advanced(FAST_TASK_GUARD_PAGE_COUNT)
mark_as_advanced(FAST_TASK_TIMER_PRECISION)
mark_as_advanced(FAST_TASK_PREEMPT_BACKGROUND_BASIC_QUANTUM_NS)
mark_as_advanced(FAST_TASK_PREEMPT_LOW_BASIC_QUANTUM_NS)
mark_as_advanced(FAST_TASK_PREEMPT_LOWER_BASIC_QUANTUM_NS)
mark_as_advanced(FAST_TASK_PREEMPT_NORMAL_BASIC_QUANTUM_NS)
mark_as_advanced(FAST_TASK_PREEMPT_HIGHER_BASIC_QUANTUM_NS)
mark_as_advanced(FAST_TASK_PREEMPT_HIGH_BASIC_QUANTUM_NS)
mark_as_advanced(FAST_TASK_PREEMPT_BACKGROUND_MAX_QUANTUM_NS)
mark_as_advanced(FAST_TASK_PREEMPT_LOW_MAX_QUANTUM_NS)
mark_as_advanced(FAST_TASK_PREEMPT_LOWER_MAX_QUANTUM_NS)
mark_as_advanced(FAST_TASK_PREEMPT_NORMAL_MAX_QUANTUM_NS)
mark_as_advanced(FAST_TASK_PREEMPT_HIGHER_MAX_QUANTUM_NS)
mark_as_advanced(FAST_TASK_PREEMPT_HIGH_MAX_QUANTUM_NS)