// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
// Optional C++20 module wrapper for the fast_task framework.
//
// This module is a thin facade over the classic header-based API. It does not
// reimplement anything: it includes the public headers inside the global module
// fragment and re-exports the public names through `export using` declarations.
// This lets consumers write:
//
//     import fast_task;
//
// instead of:
//
//     #include <fast_task.hpp>
//
// The module is only built when FAST_TASK_BUILD_MODULE is enabled.

module;

#include "fast_task.hpp"

export module fast_task;


export namespace fast_task {
    using ::fast_task::task;
    using ::fast_task::task_priority;

    using ::fast_task::mutex;
    using ::fast_task::recursive_mutex;
    using ::fast_task::rw_mutex;
    using ::fast_task::timed_mutex;
    using ::fast_task::condition_variable;
    using ::fast_task::condition_variable_any;
    using ::fast_task::semaphore;
    using ::fast_task::limiter;
    using ::fast_task::queue;
    using ::fast_task::deadline_timer;
    using ::fast_task::mutex_unify;
    using ::fast_task::multiply_mutex;

    using ::fast_task::future;
    using ::fast_task::future_ptr;

    using ::fast_task::read_lock;
    using ::fast_task::write_lock;
    using ::fast_task::protected_value;

    using ::fast_task::allocator;
    using ::fast_task::allocator_tag;

    using ::fast_task::interrupt_unsafe_region;

    using ::fast_task::base_coro_handle;
    using ::fast_task::enter_state;
    using ::fast_task::task_promise_base;

    using ::fast_task::task_auto_start_coro;
    using ::fast_task::task_coro;
    
    using ::fast_task::operator co_await;
}

export namespace fast_task::scheduler {
    using ::fast_task::scheduler::preemption_policy;

    using ::fast_task::scheduler::schedule;
    using ::fast_task::scheduler::schedule_until;
    using ::fast_task::scheduler::start;

    using ::fast_task::scheduler::create_bind_only_executor;
    using ::fast_task::scheduler::assign_bind_only_executor;
    using ::fast_task::scheduler::close_bind_only_executor;

    using ::fast_task::scheduler::create_executor;
    using ::fast_task::scheduler::total_executors;
    using ::fast_task::scheduler::reduce_executor;

    using ::fast_task::scheduler::become_task_executor;
    using ::fast_task::scheduler::await_no_tasks;
    using ::fast_task::scheduler::await_end_tasks;

    using ::fast_task::scheduler::explicit_start_timer;
    using ::fast_task::scheduler::shut_down;

    using ::fast_task::scheduler::current_context_task;
    using ::fast_task::scheduler::request_stw;

    using ::fast_task::scheduler::clean_up;
    using ::fast_task::scheduler::local_clean_up;
    using ::fast_task::scheduler::preemption_enabled;
}


export namespace fast_task::this_task {
    using ::fast_task::this_task::get_id;
    using ::fast_task::this_task::yield;
    using ::fast_task::this_task::sleep_until;
    using ::fast_task::this_task::sleep_for;
    using ::fast_task::this_task::check_cancellation;
    using ::fast_task::this_task::is_cancellation_requested;
    using ::fast_task::this_task::self_cancel;
    using ::fast_task::this_task::is_task;
    using ::fast_task::this_task::the_coroutine_ended;
    using ::fast_task::this_task::transfer_to;
    using ::fast_task::this_task::enter_sleep_until;
    using ::fast_task::this_task::enter_yield;
    using ::fast_task::this_task::async_yield;
    using ::fast_task::this_task::async_sleep_for;
    using ::fast_task::this_task::async_sleep_until;
}


export namespace fast_task::native {
    using ::fast_task::native::condition_variable;
    using ::fast_task::native::condition_variable_any;
    using ::fast_task::native::mutex;
    using ::fast_task::native::recursive_mutex;
    using ::fast_task::native::rw_mutex;
    using ::fast_task::native::timed_mutex;
    using ::fast_task::native::spin_lock;
    using ::fast_task::native::thread;
}

export namespace fast_task::file {
    using ::fast_task::file::open_mode;
    using ::fast_task::file::share_mode;
    using ::fast_task::file::pointer;
    using ::fast_task::file::pointer_offset;
    using ::fast_task::file::pointer_mode;
    using ::fast_task::file::on_open_action;
    using ::fast_task::file::file_flags;
    using ::fast_task::file::io_errors;
    using ::fast_task::file::file_handle;
    using ::fast_task::file::async_filebuf;
    using ::fast_task::file::async_iofstream;
    using ::fast_task::file::atomic_async_ofstream;
}

export namespace fast_task::net {
    using ::fast_task::net::tcp_configuration;
    using ::fast_task::net::tcp_error;
    using ::fast_task::net::shutdown_mode;
    using ::fast_task::net::address;
    using ::fast_task::net::tcp_socket;
    using ::fast_task::net::tcp_listener;
    using ::fast_task::net::udp_configuration;
    using ::fast_task::net::udp_socket;
    using ::fast_task::net::udp_peer;
}

export namespace fast_task::debug {
    using ::fast_task::debug::program_state_dump;
    using ::fast_task::debug::raw_stack_trace;
    using ::fast_task::debug::raw_tls_info;
    using ::fast_task::debug::raw_task_info;
    using ::fast_task::debug::raw_mutex_info;
    using ::fast_task::debug::raw_recursive_mutex_info;
    using ::fast_task::debug::raw_rw_mutex_info;
    using ::fast_task::debug::raw_condition_info;
    using ::fast_task::debug::raw_semaphore_info;
    using ::fast_task::debug::raw_limiter_info;
    using ::fast_task::debug::raw_queue_info;
    using ::fast_task::debug::raw_deadline_timer_info;
    using ::fast_task::debug::awake_item;
    using ::fast_task::debug::dump_program_state;
    using ::fast_task::debug::save_program_state_dump;
    using ::fast_task::debug::iterate_task_objects;
    using ::fast_task::debug::request_task_stack_trace;
    using ::fast_task::debug::request_task_init_stack_trace;
    using ::fast_task::debug::enable_init_stack_trace;
    using ::fast_task::debug::is_debug_enabled;
}
