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
    using ::fast_task::clock;
    using ::fast_task::deadline_after;
    using ::fast_task::duration;
    using ::fast_task::is_no_deadline;
    using ::fast_task::no_deadline;
    using ::fast_task::time_point;

    using ::fast_task::task;
    using ::fast_task::task_priority;
    using ::fast_task::task_vtable;

    using ::fast_task::adopt_lock;
    using ::fast_task::adopt_lock_t;
    using ::fast_task::cv_status;
    using ::fast_task::defer_lock;
    using ::fast_task::defer_lock_t;
    using ::fast_task::defer_unlock;
    using ::fast_task::defer_unlock_t;
    using ::fast_task::lock_guard;
    using ::fast_task::relock_guard;
    using ::fast_task::shared_lock;
    using ::fast_task::unique_lock;

    using ::fast_task::exception;
    using ::fast_task::file_closed;
    using ::fast_task::invalid_context;
    using ::fast_task::invalid_coroutine_context;
    using ::fast_task::invalid_coroutine_context_arguments;
    using ::fast_task::invalid_native_context;
    using ::fast_task::invalid_switch;
    using ::fast_task::no_assignable_workers;
    using ::fast_task::no_return_value;
    using ::fast_task::task_cancellation;

    using ::fast_task::mutex;
    using ::fast_task::recursive_mutex;
    using ::fast_task::rw_mutex;
    using ::fast_task::timed_mutex;
    using ::fast_task::condition_variable;
    using ::fast_task::condition_variable_any;
    using ::fast_task::semaphore;
    using ::fast_task::limiter;
    using ::fast_task::bounded_channel;
    using ::fast_task::unbounded_channel;
    using ::fast_task::spsc_channel;
    using ::fast_task::watch_channel;
    using ::fast_task::watch_receiver;
    using ::fast_task::oneshot;
    using ::fast_task::oneshot_sender;
    using ::fast_task::oneshot_receiver;
    using ::fast_task::make_oneshot;
    using ::fast_task::manual_reset_event;
    using ::fast_task::auto_reset_event;
    using ::fast_task::latch;
    using ::fast_task::barrier;
    using ::fast_task::once_flag;
    using ::fast_task::call_once;
    using ::fast_task::cancellation_source;
    using ::fast_task::cancellation_token;
    using ::fast_task::cancellation_callback;
    using ::fast_task::seqlock;
    using ::fast_task::ticker;
    using ::fast_task::missed_tick_policy;
    using ::fast_task::rate_limiter;
    using ::fast_task::parallel_for;
    using ::fast_task::parallel_reduce;
    using ::fast_task::task_group;
    using ::fast_task::async;
    using ::fast_task::when_all;
    using ::fast_task::when_any;
    using ::fast_task::with_timeout;
    using ::fast_task::queue;
    using ::fast_task::deadline_timer;
    using ::fast_task::mutex_unify;
    using ::fast_task::multiply_mutex;

    using ::fast_task::future;
    using ::fast_task::future_ptr;
    using ::fast_task::make_ready_future;

    using ::fast_task::read_lock;
    using ::fast_task::write_lock;
    using ::fast_task::protected_value;

    using ::fast_task::allocate;
    using ::fast_task::allocate_aligned;
    using ::fast_task::allocator;
    using ::fast_task::allocator_tag;
    using ::fast_task::at;
    using ::fast_task::free;
    using ::fast_task::free_aligned;

    using ::fast_task::interrupt_unsafe_region;

    using ::fast_task::base_coro_handle;
    using ::fast_task::enter_state;
    using ::fast_task::task_promise;
    using ::fast_task::task_promise_base;

    using ::fast_task::task_auto_start_coro;
    using ::fast_task::task_coro;
    using ::fast_task::task_generator;

    using ::fast_task::operator co_await;
    using ::fast_task::operator==;
    using ::fast_task::operator!=;
}

export namespace fast_task::future_tool {
    using ::fast_task::future_tool::accumulate;
    using ::fast_task::future_tool::combine_all;
    using ::fast_task::future_tool::for_each;
    using ::fast_task::future_tool::for_each_move;
    using ::fast_task::future_tool::for_each_wait;
    using ::fast_task::future_tool::process;
    using ::fast_task::future_tool::wait_all;
}

export namespace fast_task::coroutine {
    using ::fast_task::coroutine::async_for_each;
    using ::fast_task::coroutine::for_each;
    using ::fast_task::coroutine::wait_all;
    using ::fast_task::coroutine::wait_all_blocking;
}

export namespace fast_task::polyfill {
    using ::fast_task::polyfill::expected;
    using ::fast_task::polyfill::unexpected;
}

export namespace fast_task::scheduler {
    using ::fast_task::scheduler::idle_policy;
    using ::fast_task::scheduler::pool_affinity_mode;
    using ::fast_task::scheduler::preemption_policy;
    using ::fast_task::scheduler::queue_policy;
    using ::fast_task::scheduler::worker_balancer;

    using ::fast_task::scheduler::runtime_stats;
    using ::fast_task::scheduler::worker_affinity_options;
    using ::fast_task::scheduler::worker_context_options;
    using ::fast_task::scheduler::worker_hooks;
    using ::fast_task::scheduler::worker_pool_options;
    using ::fast_task::scheduler::worker_pool_stats;

    using ::fast_task::scheduler::worker_context;
    using ::fast_task::scheduler::worker_pool;

    using ::fast_task::scheduler::schedule;
    using ::fast_task::scheduler::schedule_until;
    using ::fast_task::scheduler::start;

    using ::fast_task::scheduler::become_task_executor;
    using ::fast_task::scheduler::await_no_tasks;
    using ::fast_task::scheduler::await_end_tasks;

    using ::fast_task::scheduler::explicit_start_timer;
    using ::fast_task::scheduler::shut_down;

    using ::fast_task::scheduler::current_context_task;
    using ::fast_task::scheduler::request_stw;

    using ::fast_task::scheduler::clean_up;
    using ::fast_task::scheduler::get_runtime_stats;
    using ::fast_task::scheduler::local_clean_up;
    using ::fast_task::scheduler::preemption_enabled;
}


export namespace fast_task::this_task {
    using ::fast_task::this_task::async_sleep_for;
    using ::fast_task::this_task::async_sleep_until;
    using ::fast_task::this_task::async_switch_to;
    using ::fast_task::this_task::async_yield;
    using ::fast_task::this_task::check_cancellation;
    using ::fast_task::this_task::current_pool;
    using ::fast_task::this_task::enter_sleep_until;
    using ::fast_task::this_task::enter_yield;
    using ::fast_task::this_task::get_id;
    using ::fast_task::this_task::is_cancellation_requested;
    using ::fast_task::this_task::is_task;
    using ::fast_task::this_task::self_cancel;
    using ::fast_task::this_task::set_pool;
    using ::fast_task::this_task::sleep_for;
    using ::fast_task::this_task::sleep_until;
    using ::fast_task::this_task::switch_to;
    using ::fast_task::this_task::the_coroutine_ended;
    using ::fast_task::this_task::transfer_to;
    using ::fast_task::this_task::yield;
}


export namespace fast_task::native {
    using ::fast_task::native::condition_variable;
    using ::fast_task::native::condition_variable_any;
    using ::fast_task::native::cpu_affinity;
    using ::fast_task::native::mutex;
    using ::fast_task::native::recursive_mutex;
    using ::fast_task::native::rw_mutex;
    using ::fast_task::native::timed_mutex;
    using ::fast_task::native::spin_lock;
    using ::fast_task::native::thread;
}

export namespace fast_task::native::this_thread {
    using ::fast_task::native::this_thread::get_affinity;
    using ::fast_task::native::this_thread::get_id;
    using ::fast_task::native::this_thread::set_affinity;
    using ::fast_task::native::this_thread::sleep_for;
    using ::fast_task::native::this_thread::sleep_until;
    using ::fast_task::native::this_thread::yield;
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
    using ::fast_task::file::io_operation;
    using ::fast_task::file::file_handle;
    using ::fast_task::file::async_filebuf;
    using ::fast_task::file::async_iofstream;
    using ::fast_task::file::atomic_async_ofstream;
}

export namespace fast_task::net {
    using ::fast_task::net::tcp_configuration;
    using ::fast_task::net::tcp_error;
    using ::fast_task::net::shutdown_mode;
    using ::fast_task::net::opaque_network_state;
    using ::fast_task::net::address;
    using ::fast_task::net::tcp_socket;
    using ::fast_task::net::tcp_listener;
    using ::fast_task::net::udp_configuration;
    using ::fast_task::net::udp_socket;
    using ::fast_task::net::udp_peer;
    using ::fast_task::net::init_networking;
    using ::fast_task::net::deinit_networking;
    using ::fast_task::net::ipv6_supported;
}

export namespace fast_task::debug {
    using ::fast_task::debug::array;
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
