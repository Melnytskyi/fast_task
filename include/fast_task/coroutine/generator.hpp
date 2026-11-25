#ifndef FAST_TASK_INCLUDE_COROUTINE_GENERATOR
#define FAST_TASK_INCLUDE_COROUTINE_GENERATOR
#include "../native/spin_lock.hpp"
#include "../shared.hpp"
#include "../task/scheduler.hpp"
#include "../task/task.hpp"
#include "promise.hpp"
#include <concepts>
#include <optional>
#include <queue>
#include <type_traits>

namespace fast_task {
    //chanel type as coroutine, usage:
    //while (auto opt_val = co_await async_gen.next()) {
    //    auto val = *opt_val;
    //}
    template <class T>
    class [[nodiscard]] task_generator {
        struct gen_state {
            fast_task::native::spin_lock lock;
            std::queue<T> values;
            bool is_finished = false;
            std::exception_ptr ex;
            fast_task::task consumer_signal;
            fast_task::task producer_signal;
        };

        std::shared_ptr<gen_state> state;
        fast_task::task task_handle;

    public:
        struct promise_type : public fast_task::task_promise_base {
            std::shared_ptr<gen_state> state = std::make_shared<gen_state>();

            task_generator get_return_object() {
                auto h_promise = std::coroutine_handle<promise_type>::from_promise(*this);
                std::coroutine_handle<> h_frame = h_promise;

                static task_vtable vt = {
                    nullptr,
                    nullptr,
                    [](void* handle_addr) {
                        auto h = std::coroutine_handle<promise_type>::from_address(handle_addr);
                        auto& p = h.promise();
                        struct task_object_guard {
                            task_promise_base& promise;

                            ~task_object_guard() noexcept {
                                promise.task_object.reset();
                            }
                        };
                        p.task_object = scheduler::current_context_task();
                        task_object_guard guard{p};
                        h.resume();
                    },
                    nullptr,
                    [](void* handle_addr) {
                        std::coroutine_handle<>::from_address(handle_addr).destroy();
                    },
                    false
                };

                task t(
                    h_frame.address(),
                    &vt,
                    true,
                    true
                );
                task_object = t;
                return task_generator{state, std::move(t)};
            }

            auto initial_suspend() noexcept {
                struct auto_start_awaiter {
                    promise_type& promise;

                    bool await_ready() noexcept {
                        return false;
                    }

                    void await_suspend(std::coroutine_handle<>) {
                        task t = std::move(promise.task_object);
                        if (t)
                            scheduler::start(std::move(t));
                    }

                    void await_resume() noexcept {}
                };

                return auto_start_awaiter{*this};
            }

            auto yield_value(T val) {
                struct yield_awaiter {
                    enter_state wait_state;
                    std::shared_ptr<gen_state> state;
                    T val;

                    bool await_ready() noexcept {
                        return false;
                    }

                    bool await_suspend(std::coroutine_handle<promise_type> h) {
                        fast_task::task consumer_sig;
                        fast_task::task producer_sig;
                        {
                            fast_task::lock_guard guard(state->lock);
                            state->values.push(std::move(val));

                            if (state->consumer_signal) {
                                consumer_sig = std::move(state->consumer_signal);
                                state->consumer_signal.reset();
                            }

                            if (state->values.size() > 40) {
                                if (!state->producer_signal)
                                    state->producer_signal = fast_task::task::callback_dummy(nullptr, nullptr, nullptr, nullptr, nullptr);
                                producer_sig = state->producer_signal;
                            }
                        }
                        if (consumer_sig)
                            consumer_sig.end_dummy([](void*) {});
                        if (producer_sig)
                            return !producer_sig.enter_wait(h.promise().task_object, wait_state);
                        return false;
                    }

                    void await_resume() {}
                };

                return yield_awaiter{{}, state, std::move(val)};
            }

            void return_void() noexcept {
                fast_task::task consumer_sig;
                {
                    fast_task::lock_guard guard(state->lock);
                    state->is_finished = true;
                    if (state->consumer_signal) {
                        consumer_sig = std::move(state->consumer_signal);
                        state->consumer_signal.reset();
                    }
                }
                if (consumer_sig)
                    consumer_sig.end_dummy([](void*) {});
            }

            void unhandled_exception() noexcept {
                fast_task::task consumer_sig;
                {
                    fast_task::lock_guard guard(state->lock);
                    state->ex = std::current_exception();
                    state->is_finished = true;
                    if (state->consumer_signal) {
                        consumer_sig = std::move(state->consumer_signal);
                        state->consumer_signal.reset();
                    }
                }
                if (consumer_sig)
                    consumer_sig.end_dummy([](void*) {});
            }
        };

        task_generator(std::shared_ptr<gen_state> s, task t) : state(std::move(s)), task_handle(std::move(t)) {}

        ~task_generator() {
            if (task_handle) {
                task_handle.notify_cancel();
                if (state) {
                    fast_task::task producer_sig;
                    {
                        fast_task::lock_guard guard(state->lock);
                        if (state->producer_signal) {
                            producer_sig = std::move(state->producer_signal);
                            state->producer_signal.reset();
                        }
                    }
                    if (producer_sig)
                        producer_sig.end_dummy([](void*) {});
                }
            }
        }

        task_generator(task_generator&&) noexcept = default;
        task_generator& operator=(task_generator&&) noexcept = default;

        task_generator(const task_generator&) = delete;
        task_generator& operator=(const task_generator&) = delete;

        auto next() {
            struct next_awaiter {
                enter_state wait_state;
                std::shared_ptr<gen_state> state;

                bool await_ready() {
                    fast_task::lock_guard guard(state->lock);
                    return !state->values.empty() || state->is_finished;
                }

                template <class Promise>
                bool await_suspend(std::coroutine_handle<Promise> h) {
                    fast_task::task signal;
                    {
                        fast_task::lock_guard guard(state->lock);
                        if (!state->values.empty() || state->is_finished)
                            return false;
                        if (!state->consumer_signal)
                            state->consumer_signal = fast_task::task::callback_dummy(nullptr, nullptr, nullptr, nullptr, nullptr);
                        signal = state->consumer_signal;
                    }
                    if constexpr (std::derived_from<Promise, task_promise_base>) {
                        return !signal.enter_wait(h.promise().task_object, wait_state);
                    } else {
                        static task_vtable vt = {
                            nullptr,
                            nullptr,
                            [](void* handle_addr) {
                                std::coroutine_handle<>::from_address(handle_addr).resume();
                            },
                            nullptr,
                            nullptr,
                            false
                        };
                        auto bridge_task = fast_task::task(
                            h.address(),
                            &vt,
                            false,
                            true
                        );
                        if (signal.is_ended())
                            return false;
                        signal.callback(bridge_task);
                        return true;
                    }
                }

                std::optional<T> await_resume() {
                    fast_task::task producer_sig;
                    std::optional<T> res;
                    {
                        fast_task::lock_guard guard(state->lock);
                        if (!state->values.empty()) {
                            res.emplace(std::move(state->values.front()));
                            state->values.pop();
                            if (state->producer_signal) {
                                producer_sig = std::move(state->producer_signal);
                                state->producer_signal.reset();
                            }
                        } else if (state->ex) {
                            auto ex = std::move(state->ex);
                            state->ex = nullptr;
                            std::rethrow_exception(ex);
                        }
                    }
                    if (producer_sig)
                        producer_sig.end_dummy([](void*) {});
                    return res;
                }
            };

            return next_awaiter{{}, state};
        }
    };
}
#endif /* FAST_TASK_INCLUDE_COROUTINE_GENERATOR */
