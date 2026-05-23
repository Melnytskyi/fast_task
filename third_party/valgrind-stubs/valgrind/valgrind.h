// Minimal valgrind stub used when the real Valgrind headers are not installed.
// All macros expand to no-ops; RUNNING_ON_VALGRIND is always 0 at runtime.
#ifndef VALGRIND_STUB_H
#define VALGRIND_STUB_H

#define RUNNING_ON_VALGRIND 0

#define VALGRIND_STACK_REGISTER(start, end) ((unsigned int)0)
#define VALGRIND_STACK_DEREGISTER(id)       do {} while (0)
#define VALGRIND_STACK_CHANGE(id, start, end) do {} while (0)

#endif /* VALGRIND_STUB_H */
