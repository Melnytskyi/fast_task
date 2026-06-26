// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <tasks/_internal.hpp>

#if PLATFORM_WINDOWS
    #define NOMINMAX
    #include <Windows.h>
    #include <locale>
#elif PLATFORM_LINUX
    #include <fstream>
    #include <iostream>
#endif

#if defined(__x86_64__) || defined(__i386__) || defined(_M_IX86) || defined(_M_X64)
    #define __IS_X86_OR_X64
#endif
namespace fast_task {
    NOINLINE executors_local& get_loc() noexcept {
        static thread_local executors_local loc;
        return loc;
    }

    executor_global glob;

    struct mutex_unify_relock_access {
        static void* raw_ptr(const mutex_unify& m) noexcept {
            return reinterpret_cast<void*>(m.nmut);
        }

        static uint8_t raw_type(const mutex_unify& m) noexcept {
            return static_cast<uint8_t>(m.type);
        }

        static mutex_unify from_raw(void* ptr, uint8_t type) noexcept {
            mutex_unify m(nullptr);
            m.type = static_cast<mutex_unify::mutex_unify_type>(type);
            m.nmut = reinterpret_cast<fast_task::mutex*>(ptr);
            return m;
        }

        static mutex_unify from_task_object(task_object& obj) noexcept {
            mutex_unify m(nullptr);
            m.type = mutex_unify::mutex_unify_type::task_obj;
            m.nmut = reinterpret_cast<fast_task::mutex*>(&obj);
            return m;
        }

        static void unlink_wait(std::atomic<task_object::wait_item*>& head, task_object::wait_item* node) noexcept {
            auto* cur = head.load(std::memory_order_relaxed);
            task_object::wait_item* prev = nullptr;
            while (cur) {
                if (cur == node) {
                    if (prev)
                        prev->next = cur->next;
                    else
                        head.store(cur->next, std::memory_order_relaxed);
                    return;
                }
                prev = cur;
                cur = cur->next;
            }
        }

        static_assert(sizeof(task_object::sbo_buffer) == task::sbo_size, "task::sbo_size must match task_object::sbo_buffer");
    };

    std::chrono::nanoseconds next_quantum(task_priority priority, std::chrono::nanoseconds& current_available_quantum) {
        if (priority == task_priority::semi_realtime)
            return std::chrono::nanoseconds::min();

        current_available_quantum += priority_quantum_basic[(size_t)priority];
        if (current_available_quantum > priority_quantum_max[(size_t)priority])
            current_available_quantum = priority_quantum_max[(size_t)priority];
        return current_available_quantum > std::chrono::nanoseconds(0) ? current_available_quantum : std::chrono::nanoseconds(0);
    }

    std::chrono::nanoseconds peek_quantum(task_priority priority, std::chrono::nanoseconds current_available_quantum) {
        if (priority == task_priority::semi_realtime)
            return std::chrono::nanoseconds::min();

        current_available_quantum += priority_quantum_basic[(size_t)priority];
        if (current_available_quantum > priority_quantum_max[(size_t)priority])
            current_available_quantum = priority_quantum_max[(size_t)priority];
        return current_available_quantum > std::chrono::nanoseconds(0) ? current_available_quantum : std::chrono::nanoseconds(0);
    }

    void task_switch(task_priority priority, std::chrono::nanoseconds& current_available_quantum, std::chrono::nanoseconds elapsed) {
        if (priority == task_priority::semi_realtime)
            return;
        current_available_quantum -= elapsed;
    }

    std::chrono::nanoseconds init_quantum(task_priority priority) {
        return priority_quantum_basic[(size_t)priority];
    }

    bool can_be_scheduled_task_to_hot() {
        if (task::max_running_tasks)
            if (task::max_running_tasks <= glob.in_run_tasks.load(std::memory_order_relaxed))
                return false;
        return true;
    }

    void executors_local::reset() {
        task_alloc_cache.release();
        local_tasks.reset();
        ex_ptr = nullptr;
        curr_task.reset();
        transfer_state.pending.reset();
    }

    executor_global::executor_global() = default;

    executor_global::~executor_global() {}

#if PLATFORM_WINDOWS
    std::wstring s2ws(const std::string& str) {
        int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
        if (len == 0)
            return L"";

        std::vector<wchar_t> wstr(len);
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], len);
        return std::wstring(wstr.begin(), wstr.end() - 1);
    }

    std::string ws2s(const std::wstring& wstr) {
        const CHAR def[] = " ";
        BOOL used = true;
        int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, def, &used);
        if (len == 0)
            return "";

        std::vector<char> str(len);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, str.data(), len, def, &used);
        return std::string(str.begin(), str.end() - 1);
    }

    bool _set_name_thread_dbg(const std::string& name, unsigned long thread_id) {
        std::wstring wname = s2ws(name);
        HANDLE thread = OpenThread(THREAD_SET_LIMITED_INFORMATION, false, thread_id);
        if (!thread)
            return false;
        bool result = SUCCEEDED(SetThreadDescription(thread, wname.c_str()));
        CloseHandle(thread);
        return result;
    }

    bool _set_name_thread_dbg(const std::string& name) {
        std::wstring wname = s2ws(name);
        return SUCCEEDED(SetThreadDescription(GetCurrentThread(), wname.c_str()));
    }

    std::string _get_name_thread_dbg(unsigned long thread_id) {
        HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, thread_id);
        if (!thread)
            return "";
        WCHAR* res;
        if (SUCCEEDED(GetThreadDescription(thread, &res))) {
            std::string result = ws2s(res);
            LocalFree(res);
            CloseHandle(thread);
            return result;
        } else {
            CloseHandle(thread);
            return "";
        }
    }

    unsigned long _thread_id() {
        return GetCurrentThreadId();
    }

    bool is_debugger_attached() {
        return IsDebuggerPresent();
    }

#elif PLATFORM_LINUX
    bool _set_name_thread_dbg(const std::string& name) {
        if (name.size() > 15)
            return false;
        return pthread_setname_np(pthread_self(), name.c_str()) == 0;
    }

    bool _set_name_thread_dbg(const std::string& name, unsigned long id) {
        if (name.size() > 15)
            return false;
        return pthread_setname_np(id, name.c_str()) == 0;
    }

    std::string _get_name_thread_dbg(unsigned long thread_id) {
        char name[16];
        if (pthread_getname_np(pthread_t(thread_id), name, 16) != 0)
            return "";
        return name;
    }

    unsigned long _thread_id() {
        return pthread_self();
    }

    bool is_debugger_attached() {
        std::ifstream status_file("/proc/self/status");
        if (!status_file.is_open())
            return false;
        std::string line;
        while (std::getline(status_file, line))
            if (line.rfind("TracerPid:", 0) == 0)
                return std::stoi(line.substr(10)) != 0;
        return false;
    }
#endif
    bool task_object::get_time_end() const noexcept {
        return (state.load(std::memory_order_acquire) & (state_f::time_end)) != 0;
    }

    bool task_object::get_awaked() const noexcept {
        return (state.load(std::memory_order_acquire) & (state_f::awaked)) != 0;
    }

    bool task_object::get_auto_bind() const noexcept {
        return (state.load(std::memory_order_relaxed) & (state_f::auto_bind)) != 0;
    }

    bool task_object::get_is_restartable() const noexcept {
        return (state.load(std::memory_order_relaxed) & (state_f::is_restartable)) != 0;
    }

    bool task_object::get_is_on_scheduler() const noexcept {
        return (state.load(std::memory_order_relaxed) & (state_f::is_on_scheduler)) != 0;
    }

    bool task_object::get_is_sbo() const noexcept {
        return (state.load(std::memory_order_relaxed) & (state_f::is_sbo)) != 0;
    }

    bool task_object::get_cancellation_requested() const noexcept {
        return (state.load(std::memory_order_acquire) & (state_f::cancellation_requested)) != 0;
    }

    bool task_object::get_invalid_switch_caught() const noexcept {
        return (state.load(std::memory_order_relaxed) & (state_f::invalid_switch_caught)) != 0;
    }

    bool task_object::get_completed() const noexcept {
        return (state.load(std::memory_order_acquire) & (state_f::completed)) != 0;
    }

    template <fast_task::task_object::state_f::f flag>
    void set_flag(std::atomic<fast_task::task_object::state_f::f>& state, bool on) noexcept {
        task_object::state_f::f cur = state.load(std::memory_order_relaxed), next;
        do {
            next = on ? task_object::state_f::f(cur | (flag)) : task_object::state_f::f(cur & ~(flag));
        } while (!state.compare_exchange_weak(cur, next, std::memory_order_acq_rel, std::memory_order_relaxed));
    }

    void task_object::set_time_end(bool on) noexcept {
        set_flag<state_f::time_end>(state, on);
    }

    void task_object::set_awaked(bool on) noexcept {
        set_flag<state_f::awaked>(state, on);
    }

    void task_object::set_auto_bind(bool on) noexcept {
        set_flag<state_f::auto_bind>(state, on);
    }

    void task_object::set_is_restartable(bool on) noexcept {
        set_flag<state_f::is_restartable>(state, on);
    }

    void task_object::set_is_on_scheduler(bool on) noexcept {
        set_flag<state_f::is_on_scheduler>(state, on);
    }

    void task_object::set_is_sbo(bool on) noexcept {
        set_flag<state_f::is_sbo>(state, on);
    }

    void task_object::set_cancellation_requested(bool on) noexcept {
        set_flag<state_f::cancellation_requested>(state, on);
    }

    void task_object::set_invalid_switch_caught(bool on) noexcept {
        set_flag<state_f::invalid_switch_caught>(state, on);
    }

    void task_object::set_completed(bool on) noexcept {
        set_flag<state_f::completed>(state, on);
    }

    task_object::execution_mode task_object::get_execution_mode() const noexcept {
        return static_cast<task_object::execution_mode>(state.load(std::memory_order_relaxed) & 0x03); //the execution mode should not be modified mid run
    }

    void task_object::lock() noexcept {
        interrupt_unsafe_region::lock();
        state_f::f cur = state.load(std::memory_order_relaxed);
        for (;;) {
            cur = state_f::f(cur & ~state_f::spin_lock_locked);
            if (state.compare_exchange_weak(cur, state_f::f(cur | state_f::spin_lock_locked), std::memory_order_acquire, std::memory_order_relaxed))
                return;
#ifdef PLATFORM_WINDOWS
    #ifdef __IS_X86_OR_X64
            _mm_pause();
    #endif
#else
    #if (defined(__GNUC__) || defined(__clang__)) && defined(__IS_X86_OR_X64)
            __builtin_ia32_pause();
    #endif
#endif
        }
    }

    void task_object::unlock() noexcept {
        state_f::f cur = state.load(std::memory_order_relaxed), next;
        do {
            next = state_f::f(cur & ~state_f::spin_lock_locked);
        } while (!state.compare_exchange_weak(cur, next, std::memory_order_release, std::memory_order_relaxed));
        interrupt_unsafe_region::unlock();
    }

    void task_object::set_status(status_e s) noexcept {
        status.store(s, std::memory_order_release);
    }

    bool task_object::is_scheduled() const noexcept {
        return status.load(std::memory_order_acquire) != status_e::created;
    }

    bool task_object::is_created() const noexcept {
        return status.load(std::memory_order_acquire) == status_e::created;
    }

    bool task_object::is_running() const noexcept {
        return status.load(std::memory_order_acquire) == status_e::running;
    }

    bool task_object::is_suspended() const noexcept {
        return status.load(std::memory_order_acquire) == status_e::suspended;
    }

    bool task_object::is_ended() const noexcept {
        return status.load(std::memory_order_acquire) == status_e::ended;
    }

    void* task_object::user_data() const noexcept {
        if ((state.load(std::memory_order_acquire) & state_f::is_sbo) != 0)
            return const_cast<std::byte*>(sbo_buffer);
        return *reinterpret_cast<void* const*>(sbo_buffer);
    }

    void task_object::end_of_life_notify() {
        lock();
        status.store(task_object::status_e::ended, std::memory_order_release);
        task_object::wait_item* head = on_wait.exchange(nullptr, std::memory_order_acq_rel);
        unlock();
        if (!head)
            return;

        fast_task::shared_lock guard(glob.task_thread_safety);
        size_t to_wake = 0;
        while (head) {
            auto* next = head->next;
            bool heap_allocated = head->heap_allocated;
            if (head->waiter) {
                auto& wd = get_data(head->waiter);
                fast_task::lock_guard guard_loc(wd);
                if (wd.awake_check == head->awake_check && !wd.get_time_end()) {
                    wd.set_awaked(true);
                    fast_task::relock_guard guard_relock(guard);
                    transfer_task(std::move(head->waiter));
                    ++to_wake;
                }
            } else if (head->native_cv) {
                fast_task::lock_guard re_lock(*this);
                *head->native_check = true;
                head->native_cv->notify_all();
            }
            if (heap_allocated)
                delete head;
            head = next;
        }
        to_wake = std::min<size_t>(to_wake, glob.executors);
        for (size_t i = 0; i < to_wake; i++)
            glob.tasks_notifier.notify_one();
    }

    void task_object::wait() {
        mutex_unify self = mutex_unify_relock_access::from_task_object(*this);
        if (get_loc().is_task_thread) {
            fast_task::lock_guard guard(*this);
            if (is_ended()) {
                return;
            }
            wait_item node;
            node.waiter = get_loc().curr_task;
            node.awake_check = get_data(get_loc().curr_task).awake_check;
            node.next = on_wait.load(std::memory_order_relaxed);
            on_wait.store(&node, std::memory_order_relaxed);
            swapCtxRelock(self);
        } else {
            fast_task::condition_variable_any cd;
            bool done = false;
            fast_task::unique_lock<mutex_unify> g(self);
            if (is_ended())
                return;
            wait_item node;
            node.native_cv = &cd;
            node.native_check = &done;
            node.next = on_wait.load(std::memory_order_relaxed);
            on_wait.store(&node, std::memory_order_relaxed);
            while (!done) //-V654
                cd.wait(g);
        }
    }

    void task_object::wait_until(std::chrono::high_resolution_clock::time_point time_point) {
        mutex_unify self = mutex_unify_relock_access::from_task_object(*this);
        if (get_loc().is_task_thread) {
            fast_task::lock_guard guard(*this);
            if (is_ended()) {
                return;
            }
            wait_item node;
            node.waiter = get_loc().curr_task;
            node.awake_check = get_data(get_loc().curr_task).awake_check;
            node.next = on_wait.load(std::memory_order_relaxed);
            on_wait.store(&node, std::memory_order_relaxed);
            {
                fast_task::lock_guard guard(glob.task_timer_safety);
                makeTimeWait_unsafe(time_point);
                swapCtxRelock(self, glob.task_timer_safety);
            }
            bool timed = get_data(get_loc().curr_task).get_time_end();
            resetTimeWait();
            if (timed)
                mutex_unify_relock_access::unlink_wait(on_wait, &node);
        } else {
            fast_task::condition_variable_any cd;
            bool done = false;
            fast_task::unique_lock<mutex_unify> g(self);
            if (is_ended())
                return;
            wait_item node;
            node.native_cv = &cd;
            node.native_check = &done;
            node.next = on_wait.load(std::memory_order_relaxed);
            on_wait.store(&node, std::memory_order_relaxed);
            while (!done) { //-V654
                if (cd.wait_until(g, time_point) == cv_status::timeout) {
                    mutex_unify_relock_access::unlink_wait(on_wait, &node);
                    return;
                }
            }
        }
    }

    void task_object::cancel() {
        set_cancellation_requested(true);
    }

    bool task_object::enter_wait(const task& waiter, enter_state& st) {
        lock();
        if (is_ended()) {
            unlock();
            return true;
        }
        auto node = st.template use<wait_item>();
        node->waiter = waiter;
        node->awake_check = get_data(waiter).awake_check;
        node->next = on_wait.load(std::memory_order_relaxed);
        on_wait.store(node, std::memory_order_relaxed);
        unlock();
        return false;
    }

    bool task_object::enter_wait_until(const task& waiter, enter_state& st, std::chrono::high_resolution_clock::time_point time_point) {
        if (std::chrono::high_resolution_clock::now() >= time_point)
            return true;
        lock();
        if (is_ended()) {
            unlock();
            return true;
        }
        auto node = st.template use<wait_item>();
        node->waiter = waiter;
        node->awake_check = get_data(waiter).awake_check;
        node->next = on_wait.load(std::memory_order_relaxed);
        on_wait.store(node, std::memory_order_relaxed);
        unlock();
        fast_task::makeTimeWait_extern(waiter, time_point);
        return false;
    }

    bool task_object::enter_cancel(const task& waiter, enter_state& st) {
        cancel();
        return enter_wait(waiter, st);
    }

    mutex_unify task_object::get_relock_0() const noexcept {
        return mutex_unify_relock_access::from_raw(relock0, relock0_type);
    }

    mutex_unify task_object::get_relock_1() const noexcept {
        return mutex_unify_relock_access::from_raw(relock1, relock1_type);
    }

    void task_object::set_relock_0(mutex_unify mut) noexcept {
        relock0 = mutex_unify_relock_access::raw_ptr(mut);
        relock0_type = mutex_unify_relock_access::raw_type(mut);
    }

    void task_object::set_relock_1(mutex_unify mut) noexcept {
        relock1 = mutex_unify_relock_access::raw_ptr(mut);
        relock1_type = mutex_unify_relock_access::raw_type(mut);
    }

    global_task_allocator g_block_allocator;

    task_object* task_object::alloc() {
        auto obj = static_cast<task_object*>(get_loc().task_alloc_cache.allocate());

        obj->tls_data.store(nullptr, std::memory_order_relaxed);
        obj->on_wait.store(nullptr, std::memory_order_relaxed);
        obj->exdata.store(nullptr, std::memory_order_relaxed);
        obj->vtable = nullptr;
        obj->relock0 = nullptr;
        obj->relock1 = nullptr;
        obj->relock0_type = 0;
        obj->relock1_type = 0;
        obj->status.store(status_e::created, std::memory_order_relaxed);
        obj->state.store(static_cast<state_f::f>(0), std::memory_order_relaxed);
        obj->bind_to_worker_id = static_cast<uint16_t>(-1);
        obj->awake_check = 0;
        obj->tls_capacity = 0;
        obj->reserved0 = 0;
        obj->link_counter.store(1, std::memory_order_relaxed);
        obj->on_start_override = nullptr;
        obj->on_start_override_data = nullptr;
        FT_DEBUG_ONLY(register_object(obj));
        return obj;
    }

    task_object* task_object::use(task_object* obj) noexcept {
        if (obj) {
            uint32_t old_counter = obj->link_counter.fetch_add(1, std::memory_order_relaxed);
            if (old_counter == 0) {
                obj->link_counter.fetch_sub(1, std::memory_order_relaxed);
                return nullptr;
            }
        }
        return obj;
    }

    void task_object::free(task_object* obj) {
        if (obj->link_counter.fetch_sub(1, std::memory_order_acq_rel) == 1) {
            FT_DEBUG_ONLY(unregister_object(obj));
            if (!obj)
                return;

            const bool started = obj->is_scheduled();
            const bool ended = obj->is_ended();

            if (obj->vtable && obj->vtable->on_destruct)
                obj->vtable->on_destruct(obj->user_data());

            if (auto* ex = obj->exdata.load(std::memory_order_acquire)) {
                delete ex;
                obj->exdata.store(nullptr, std::memory_order_relaxed);
            }

            if (!ended && started) {
                --glob.executing_tasks;
                fast_task::shared_lock guard(glob.task_thread_safety);
                glob.no_tasks_execute_notifier.notify_all();
            }

#ifdef FT_ENABLE_ABORT_IF_NEVER_STARTED
            if (!started && !ended) {
                assert(false && "The task should always be started.");
                std::abort();
            }
#endif

            FT_DEBUG_ONLY(unregister_object(obj));
            if (obj->vtable && obj->vtable->heap_allocated)
                delete const_cast<task_vtable*>(obj->vtable);

            obj->status.store(task_object::status_e::released, std::memory_order_relaxed);
            get_loc().task_alloc_cache.deallocate(obj);
        }
    }

    mutex_unify task_object::get_self_unify() noexcept {
        return mutex_unify_relock_access::from_task_object(*this);
    }
}
