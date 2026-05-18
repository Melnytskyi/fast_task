// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <algorithm>
#include <atomic>
#include <boost/lockfree/queue.hpp>
#include <cassert>
#include <concurrentqueue/moodycamel/concurrentqueue.h>
#include <vector>

#include <tasks/_internal.hpp>
#include <tasks/util/light_stack.hpp>

namespace fast_task {
    typedef boost::context::stack_context stack_context;

    moodycamel::ConcurrentQueue<light_stack::stack_context> stack_allocations(10000);
    std::atomic_size_t stack_allocations_buffer = 0;
    bool light_stack::flush_used_stacks = 0;
    size_t light_stack::max_buffer_size = 0;
}
#if PLATFORM_WINDOWS
    #include <Windows.h>
size_t page_size = []() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwPageSize;
}();

namespace fast_task {
    stack_context create_stack(size_t size) {
        const size_t guard_page_size = page_size;

        void* vp = ::VirtualAlloc(0, size, MEM_RESERVE, PAGE_READWRITE);
        if (!vp)
            throw std::bad_alloc();

        // needs at least 3 pages to fully construct the coroutine and switch to it
        const auto init_commit_size = page_size * 3;
        auto pPtr = static_cast<PBYTE>(vp) + size;
        pPtr -= init_commit_size;
        if (!VirtualAlloc(pPtr, init_commit_size, MEM_COMMIT, PAGE_READWRITE)) {
            VirtualFree(vp, size, MEM_FREE);
            throw std::bad_alloc();
        }

        // create guard page so the OS can catch page faults and grow our stack
        pPtr -= guard_page_size;
        if (!VirtualAlloc(pPtr, guard_page_size, MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD)) {
            VirtualFree(vp, size, MEM_FREE);
            throw std::bad_alloc();
        }
        stack_context sctx;
        sctx.size = size;
        sctx.sp = static_cast<char*>(vp) + sctx.size;
        return sctx;
    }

    light_stack::light_stack(size_t size) BOOST_NOEXCEPT_OR_NOTHROW : size(size) {}

    stack_context light_stack::allocate() {
        const size_t guard_page_size = page_size;
        const size_t pages = (size + guard_page_size + page_size - 1) / page_size;
        // add one page at bottom that will be used as guard-page
        const size_t size__ = (pages + 1) * page_size;

        stack_context result;
        if (stack_allocations.try_dequeue(result)) {
            stack_allocations_buffer--;
            if (!flush_used_stacks)
                return result;
            else {
                memset(static_cast<char*>(result.sp) - result.size, 0xCC, result.size);
                return result;
            }
        } else
            return create_stack(size__);
    }

    void unlimited_buffer(stack_context& sctx) {
        if (!stack_allocations.enqueue(sctx))
            ::VirtualFree(static_cast<char*>(sctx.sp) - sctx.size, 0, MEM_RELEASE);
        else
            stack_allocations_buffer++;
    }

    void limited_buffer(stack_context& sctx) {
        if (++stack_allocations_buffer < light_stack::max_buffer_size) {
            if (!stack_allocations.enqueue(sctx)) {
                ::VirtualFree(static_cast<char*>(sctx.sp) - sctx.size, 0, MEM_RELEASE);
                stack_allocations_buffer--;
            }
        } else {
            ::VirtualFree(static_cast<char*>(sctx.sp) - sctx.size, 0, MEM_RELEASE);
            stack_allocations_buffer--;
        }
    }

    void light_stack::deallocate(stack_context& sctx) {
        assert(sctx.sp);
        if (!max_buffer_size)
            unlimited_buffer(sctx);
        else if (max_buffer_size != SIZE_MAX)
            limited_buffer(sctx);
        else
            ::VirtualFree(static_cast<char*>(sctx.sp) - sctx.size, 0, MEM_RELEASE);
    }
}
#elif PLATFORM_LINUX
    #include <mutex>
    #include <signal.h>
    #include <sys/mman.h>
    #include <sys/stat.h>
    #include <unistd.h>
    #include <valgrind/memcheck.h>
    #include <valgrind/valgrind.h>
    #if defined(__x86_64__)
        #include <ucontext.h>
    #endif

namespace fast_task {
    static const size_t page_size = boost::context::stack_traits::page_size();
    static const size_t guard_page_size = boost::context::stack_traits::page_size();

    // Called when a stack overflow is detected: resumes (outside signal handler)
    // on the task's now-accessible guard page and raises the stack_overflow exception.
    // The C++ exception machinery then unwinds the task's call stack normally,
    // running all destructors before the catch(...) in context_exec catches it.
    [[noreturn]] __attribute__((noinline)) static void __stack_overflow_raise() {
        throw stack_overflow();
    }

    static struct sigaction __old_sigsegv_action = {};

    static void __sigsegv_handler(int sig, siginfo_t* si, void* ctx) {
        bool handled = false;

        // Only act when a task is currently executing on this thread and has a stack.
        if (loc.curr_task) {
            // Access execution_data directly to avoid any heap allocation inside a signal handler.
            // Use auto* to avoid naming the private nested type task::execution_data.
            auto* exdata = get_data(loc.curr_task).exdata;
            if (exdata && exdata->stack_ptr) {
                void* fault_addr = si->si_addr;
                void* stack_bottom = exdata->stack_ptr;
                uintptr_t stack_top = reinterpret_cast<uintptr_t>(stack_bottom) + exdata->stack_size;

                // Guard page occupies [stack_bottom, stack_bottom + guard_page_size).
                if (fault_addr >= stack_bottom &&
                    fault_addr < static_cast<char*>(stack_bottom) + guard_page_size) {
                    // Make the guard page accessible so the C++ unwinder has a little
                    // room on the stack to execute landing pads and destructors.
                    if (mprotect(stack_bottom, guard_page_size, PROT_READ | PROT_WRITE) != 0)
                        goto pass_handler; // mprotect failed — fall back to default handling

#if defined(__x86_64__)
                    {
                        ucontext_t* uc = static_cast<ucontext_t*>(ctx);

                        // Position RSP at the high end of the (now accessible) guard page,
                        // simulating a CALL instruction (RSP % 16 == 8, RA slot filled
                        // with the actual return address so the DWARF unwinder can walk
                        // through all existing recursion frames on the real stack above).
                        uintptr_t guard_top = reinterpret_cast<uintptr_t>(stack_bottom) + guard_page_size;
                        uintptr_t new_rsp = (guard_top & ~static_cast<uintptr_t>(15)) - 8;

                        // Read the return address that the faulting frame would use so the
                        // stack-unwind chain is intact: [RBP + sizeof(ptr)] holds the
                        // return address in x86-64 ABI (after push rbp / mov rbp, rsp).
                        // Validate RBP points into the valid (non-guard) stack region
                        // before dereferencing to avoid a second fault inside the handler.
                        uintptr_t rbp = static_cast<uintptr_t>(uc->uc_mcontext.gregs[REG_RBP]);
                        uintptr_t ra_addr = rbp + sizeof(uintptr_t);
                        if (rbp < guard_top || ra_addr + sizeof(uintptr_t) > stack_top)
                            goto pass_handler; // corrupt frame pointer — fall back

                        uintptr_t ret_addr = *reinterpret_cast<uintptr_t*>(ra_addr);
                        *reinterpret_cast<uintptr_t*>(new_rsp) = ret_addr;
                        uc->uc_mcontext.gregs[REG_RSP] = static_cast<greg_t>(new_rsp);
                        uc->uc_mcontext.gregs[REG_RIP] = reinterpret_cast<greg_t>(__stack_overflow_raise);
                        handled = true;
                    }
#endif
                }
            }
        }

    pass_handler:
        if (!handled) {
            if (__old_sigsegv_action.sa_flags & SA_SIGINFO)
                __old_sigsegv_action.sa_sigaction(sig, si, ctx);
            else if (__old_sigsegv_action.sa_handler == SIG_DFL) {
                signal(sig, SIG_DFL);
                raise(sig);
            } else if (__old_sigsegv_action.sa_handler != SIG_IGN)
                __old_sigsegv_action.sa_handler(sig);
        }
    }

    void __install_signal_handler_mem() {
        // Per-thread: allocate and register a dedicated alternate signal stack so the
        // SIGSEGV handler can run even when the task's stack is exhausted.
        static thread_local bool alt_stack_set = false;
        if (!alt_stack_set) {
            void* alt_mem = mmap(nullptr, SIGSTKSZ, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (alt_mem != MAP_FAILED) {
                stack_t ss;
                ss.ss_sp = alt_mem;
                ss.ss_size = SIGSTKSZ;
                ss.ss_flags = 0;
                if (sigaltstack(&ss, nullptr) != 0)
                    munmap(alt_mem, SIGSTKSZ); // best-effort cleanup on failure
            }
            alt_stack_set = true;
        }

        // Process-wide: install the SIGSEGV handler exactly once.
        static std::once_flag handler_flag;
        std::call_once(handler_flag, []() {
            struct sigaction sa;
            sigemptyset(&sa.sa_mask);
            sa.sa_sigaction = __sigsegv_handler;
            sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
            sigaction(SIGSEGV, &sa, &__old_sigsegv_action);
        });
    }

    //create proper guard page
    stack_context create_stack(size_t size) {
        size_t total_size = std::max(size, page_size * 3);
        void* vp = mmap(nullptr, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (vp == MAP_FAILED)
            throw std::bad_alloc();

        // Create a PROT_NONE guard page at the bottom of the stack to catch stack overflows
        if (mprotect(vp, guard_page_size, PROT_NONE) == -1) {
            munmap(vp, total_size);
            throw std::bad_alloc();
        }

        if (RUNNING_ON_VALGRIND) {
            void* stack_bottom = static_cast<uint8_t*>(vp) + guard_page_size;
            void* stack_top = static_cast<uint8_t*>(vp) + total_size;
            get_execution_data(loc.curr_task).valgrind_stack_id = VALGRIND_STACK_REGISTER(stack_bottom, stack_top);
        }

        stack_context sctx;
        sctx.size = size;
        sctx.sp = static_cast<char*>(vp) + sctx.size;
        return sctx;
    }

    void destroy_stack(stack_context& sctx) {
        if (!sctx.sp)
            return;

        if (RUNNING_ON_VALGRIND)
            VALGRIND_STACK_DEREGISTER(get_execution_data(loc.curr_task).valgrind_stack_id);

        munmap(static_cast<char*>(sctx.sp) - sctx.size, sctx.size);
        sctx.sp = nullptr;
        sctx.size = 0;
    }

    light_stack::light_stack(size_t size) BOOST_NOEXCEPT_OR_NOTHROW : size(size) {}

    stack_context light_stack::allocate() {
        const size_t pages = (size + guard_page_size + page_size - 1) / page_size;
        // add one page at bottom that will be used as guard-page
        const size_t size__ = (pages + 1) * page_size;

        stack_context result;
        if (stack_allocations.try_dequeue(result)) {
            stack_allocations_buffer--;
            if (!flush_used_stacks)
                return result;
            else {
                memset(static_cast<char*>(result.sp) - result.size, 0xCC, result.size);
                return result;
            }
        } else
            return create_stack(size__);
    }

    void unlimited_buffer(stack_context& sctx) {
        // Restore the guard page before returning the stack to the pool so the
        // next task using this stack gets proper overflow detection.
        // If restoring protection fails, destroy the stack rather than recycling
        // an unprotected one.
        if (mprotect(static_cast<char*>(sctx.sp) - sctx.size, guard_page_size, PROT_NONE) != 0) {
            destroy_stack(sctx);
            return;
        }
        if (!stack_allocations.enqueue(sctx))
            destroy_stack(sctx);
        else
            stack_allocations_buffer++;
    }

    void limited_buffer(stack_context& sctx) {
        // Restore the guard page before returning the stack to the pool.
        // Destroy the stack if protection cannot be restored.
        if (mprotect(static_cast<char*>(sctx.sp) - sctx.size, guard_page_size, PROT_NONE) != 0) {
            destroy_stack(sctx);
            return;
        }
        if (++stack_allocations_buffer < light_stack::max_buffer_size) {
            if (!stack_allocations.enqueue(sctx)) {
                destroy_stack(sctx);
                stack_allocations_buffer--;
            }
        } else {
            destroy_stack(sctx);
            stack_allocations_buffer--;
        }
    }

    void light_stack::deallocate(stack_context& sctx) {
        assert(sctx.sp);
        if (!max_buffer_size)
            unlimited_buffer(sctx);
        else if (max_buffer_size != SIZE_MAX)
            limited_buffer(sctx);
        else
            destroy_stack(sctx);
    }
}

#else
    #error Unsupported platform
#endif