#ifndef INCLUDE_COROUTINE_GENERATOR
#define INCLUDE_COROUTINE_GENERATOR
#include "../shared.hpp"
#include "../task/scheduler.hpp"
#include "../task/task.hpp"
#include "promise.hpp"
#include <concepts>
#include <queue>

namespace fast_task {
    //chanel type as coroutine, usage:
    //while (auto opt_val = co_await async_gen.next()) {
    //    auto val = *opt_val;
    //}
    template <class T>
    class [[nodiscard]] task_generator {
        struct shared_state {
            fast_task::spin_lock lock;
            std::queue<T> values;
            bool is_finished = false;
            std::exception_ptr ex;
            std::shared_ptr<fast_task::task> suspended_consumer;
            std::shared_ptr<fast_task::task> suspended_producer;
        };

        std::shared_ptr<shared_state> state;
        std::shared_ptr<fast_task::task> task_handle;

    public:
        struct promise_type : public fast_task::task_promise_base {
            std::shared_ptr<shared_state> state = std::make_shared<shared_state>();

            task_generator get_return_object() {
                auto h_promise = std::coroutine_handle<promise_type>::from_promise(*this);

                std::coroutine_handle<> h_frame = h_promise;

                auto on_start = [](void* handle_addr) {
                    std::coroutine_handle<>::from_address(handle_addr).resume();
                };

                auto on_destruct = [](void* handle_addr) {
                    std::coroutine_handle<>::from_address(handle_addr).destroy();
                };

                task_object = std::make_shared<task>(
                    h_frame.address(),
                    on_start,
                    [](void* handle_addr) {},
                    [](void* handle_addr) {},
                    on_destruct,
                    true,
                    true
                );
                return task_generator{state, task_object};
            }

            auto yield_value(T val) {
                struct yield_awaiter {
                    std::shared_ptr<shared_state> state;
                    T val;

                    bool await_ready() {
                        return false;
                    }

                    bool await_suspend(std::coroutine_handle<promise_type> h) {
                        fast_task::lock_guard guard(state->lock);
                        state->values.push(std::move(val));

                        if (state->suspended_consumer) {
                            fast_task::scheduler::start(state->suspended_consumer);
                            state->suspended_consumer.reset();
                        }

                        if (state->values.size() > 40) {
                            state->suspended_producer = h.promise().task_object;
                            return true;
                        } else
                            return false;
                    }

                    void await_resume() {}
                };

                return yield_awaiter{state, std::move(val)};
            }

            void return_void() noexcept {
                fast_task::lock_guard guard(state->lock);
                state->is_finished = true;
                if (state->suspended_consumer) {
                    fast_task::scheduler::start(state->suspended_consumer);
                }
            }

            void unhandled_exception() {
                fast_task::lock_guard guard(state->lock);
                state->ex = std::current_exception();
                if (state->suspended_consumer) {
                    fast_task::scheduler::start(state->suspended_consumer);
                }
            }
        };

        task_generator(std::shared_ptr<shared_state> s, std::shared_ptr<task> t) : state(std::move(s)), task_handle(std::move(t)) {
            scheduler::start(task_handle);
        }

        task_generator(task_generator&&) noexcept = default;
        task_generator& operator=(task_generator&&) noexcept = default;

        task_generator(const task_generator&) = delete;
        task_generator& operator=(const task_generator&) = delete;

        auto next() {
            struct next_awaiter {
                std::shared_ptr<shared_state> state;

                bool await_ready() {
                    fast_task::lock_guard guard(state->lock);
                    return !state->values.empty() || state->is_finished;
                }

                template <class Promise>
                bool await_suspend(std::coroutine_handle<Promise> h) {
                    fast_task::lock_guard guard(state->lock);
                    if (!state->values.empty() || state->is_finished)
                        return false;
                    if constexpr (std::derived_from<Promise, task_promise_base>) {
                        state->suspended_consumer = h.promise().task_object;
                        return true;
                    } else {
                        auto on_start_resume = [](void* handle_addr) {
                            std::coroutine_handle<>::from_address(handle_addr).resume();
                        };
                        auto on_nop = [](void*) {};
                        auto bridge_task = std::make_shared<fast_task::task>(
                            h.address(),
                            on_start_resume,
                            on_nop,
                            on_nop,
                            on_nop,
                            false,
                            true
                        );
                        state->suspended_consumer = bridge_task;
                        return true;
                    }
                }

                std::optional<T> await_resume() {
                    fast_task::lock_guard guard(state->lock);
                    if (state->ex)
                        std::rethrow_exception(state->ex);
                    if (state->values.empty() && state->is_finished)
                        return std::nullopt;

                    T val = std::move(state->values.front());
                    state->values.pop();
                    if(state->suspended_producer) {
                        fast_task::scheduler::start(state->suspended_producer);
                        state->suspended_producer.reset();
                    }

                    return val;
                }
            };

            return next_awaiter{state};
        }
    };
}
#endif /* INCLUDE_COROUTINE_GENERATOR */
