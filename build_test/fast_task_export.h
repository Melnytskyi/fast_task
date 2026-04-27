
#ifndef FT_API_H
#define FT_API_H

#ifdef FT_API_STATIC
#  define FT_API
#  define FT_API_LOCAL
#else
#  ifndef FT_API
#    ifdef fast_task_EXPORTS
        /* We are building this library */
#      define FT_API 
#    else
        /* We are using this library */
#      define FT_API 
#    endif
#  endif

#  ifndef FT_API_LOCAL
#    define FT_API_LOCAL 
#  endif
#endif

#ifndef FAST_TASK_DEPRECATED
#  define FAST_TASK_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef FAST_TASK_DEPRECATED_EXPORT
#  define FAST_TASK_DEPRECATED_EXPORT FT_API FAST_TASK_DEPRECATED
#endif

#ifndef FAST_TASK_DEPRECATED_NO_EXPORT
#  define FAST_TASK_DEPRECATED_NO_EXPORT FT_API_LOCAL FAST_TASK_DEPRECATED
#endif

/* NOLINTNEXTLINE(readability-avoid-unconditional-preprocessor-if) */
#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef FAST_TASK_NO_DEPRECATED
#    define FAST_TASK_NO_DEPRECATED
#  endif
#endif

#endif /* FT_API_H */
