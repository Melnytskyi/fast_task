#ifndef FAST_TASK_INCLUDE_SHARED
#define FAST_TASK_INCLUDE_SHARED
// Every public header includes this one, so the clock aliases are always in
// scope before any deadline/time_point signature is parsed.
#include "clock.hpp"
#ifdef FT_API_STATIC
    #define FT_API
    #define FT_API_LOCAL
#else
    #include "fast_task_export.h"
#endif
#endif
