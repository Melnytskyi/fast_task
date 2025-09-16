#ifndef FAST_TASK_INCLUDE_SHARED
#define FAST_TASK_INCLUDE_SHARED
#ifdef FT_API_STATIC
    #define FT_API
    #define FT_API_LOCAL
#else
    #include "fast_task_export.h"
#endif

#endif
