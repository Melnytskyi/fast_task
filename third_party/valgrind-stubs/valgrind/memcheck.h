// Minimal memcheck stub used when the real Valgrind headers are not installed.
#ifndef VALGRIND_MEMCHECK_STUB_H
#define VALGRIND_MEMCHECK_STUB_H

#include "valgrind.h"

#define VALGRIND_MAKE_MEM_DEFINED(addr, size)   do {} while (0)
#define VALGRIND_MAKE_MEM_UNDEFINED(addr, size) do {} while (0)
#define VALGRIND_MAKE_MEM_NOACCESS(addr, size)  do {} while (0)
#define VALGRIND_CHECK_MEM_IS_DEFINED(addr, size) ((unsigned int)0)

#endif /* VALGRIND_MEMCHECK_STUB_H */
