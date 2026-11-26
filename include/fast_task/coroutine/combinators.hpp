// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_COROUTINE_COMBINATORS
#define FAST_TASK_INCLUDE_COROUTINE_COMBINATORS

#include "../clock.hpp"
#include "../task/event.hpp"
#include "../task/future.hpp"
#include "../task/scheduler.hpp"
#include "core.hpp"
#include <atomic>
#include <cstddef>
#include <exception>
#include <memory>
#include <optional>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>

namespace fast_task {
    namespace detail {
        template <class T>
        struct combinator_result {
            using type = T;
        };

        template <>
        struct combinator_result<void> {
            using type = std::monostate;
        };

        template <class T>
        struct combinator_value;

        template <class T>
        struct combinator_value<task_coro<T>> {
            using raw_type = T;
            using type = typename combinator_result<T>::type;

            static task get_task(const task_coro<T>& c) {
                return c.get_task();
            }

            static void ensure_started(const task_coro<T>& c) {
                auto t = c.get_task();
                if (t && !t.is_ended())
                    scheduler::start(t);
            }
        };

        template <class T>
        struct combinator_value<task_auto_start_coro<T>> : combinator_value<task_coro<T>> {
            static void ensure_started(const task_auto_start_coro<T>&) noexcept {}
        };

        template <class T>
        struct combinator_value<future_ptr<T>> {
            using raw_type = T;
            using type = typename combinator_result<T>::type;

            static task get_task(const future_ptr<T>& f) {
                return f->get_task();
            }

            static void ensure_started(const future_ptr<T>&) noexcept {}
        };

        template <class Item>
        using combinator_result_t = typename combinator_value<std::decay_t<Item>>::type;

        template <class Item>
        using combinator_raw_t = typename combinator_value<std::decay_t<Item>>::raw_type;

        template <size_t I, class Tuple, class ResultTuple>
        task_coro<void> await_one_for_all(Tuple& items, ResultTuple& out, std::exception_ptr& first_ex) {
            using Item = std::decay_t<std::tuple_element_t<I, Tuple>>;
            try {
                if constexpr (std::is_void_v<combinator_raw_t<Item>>) {
                    co_await std::get<I>(items);
                    std::get<I>(out) = std::monostate{};
                } else {
                    std::get<I>(out) = co_await std::get<I>(items);
                }
            } catch (...) {
                if (!first_ex)
                    first_ex = std::current_exception();
            }
            co_return;
        }

        template <size_t I, class Tuple, class Variant>
        task_coro<void> handle_one_for_any(
            Tuple& items,
            size_t win,
            std::optional<Variant>& result,
            std::exception_ptr& win_ex
        ) {
            using Item = std::decay_t<std::tuple_element_t<I, Tuple>>;
            if (I == win) {
                try {
                    if constexpr (std::is_void_v<combinator_raw_t<Item>>) {
                        co_await std::get<I>(items);
                        result.emplace(std::in_place_index<I>, std::monostate{});
                    } else {
                        result.emplace(std::in_place_index<I>, co_await std::get<I>(items));
                    }
                } catch (...) {
                    win_ex = std::current_exception();
                }
            } else {
                try {
                    if constexpr (std::is_void_v<combinator_raw_t<Item>>)
                        co_await std::get<I>(items);
                    else
                        (void)co_await std::get<I>(items);
                } catch (...) {
                }
            }
            co_return;
        }
    }

    // Heterogeneous when_all for task_coro<T>, task_auto_start_coro<T>, and future_ptr<T>.
    // Launches all items concurrently, awaits every item to completion, and returns
    // std::tuple<Results...> (using std::monostate for void items).
    // Rethrows the first exception after all items have finished.
    template <class... Items>
        requires (sizeof...(Items) > 0)
    [[nodiscard]] auto when_all(Items&&... items)
        -> task_coro<std::tuple<detail::combinator_result_t<Items>...>> {
        using Tuple = std::tuple<std::decay_t<Items>...>;
        using ResultTuple = std::tuple<detail::combinator_result_t<Items>...>;

        return []<size_t... Is>(Tuple tup, std::index_sequence<Is...>) -> task_coro<ResultTuple> {
            (detail::combinator_value<std::tuple_element_t<Is, Tuple>>::ensure_started(std::get<Is>(tup)), ...);

            ResultTuple results{};
            std::exception_ptr first_ex;
            ((co_await detail::await_one_for_all<Is>(tup, results, first_ex)), ...);

            if (first_ex)
                std::rethrow_exception(first_ex);
            co_return results;
        }(std::make_tuple(std::forward<Items>(items)...), std::index_sequence_for<Items...>{});
    }

    // Heterogeneous when_any for task_coro<T>, task_auto_start_coro<T>, and future_ptr<T>.
    // Races all items concurrently, cancels losers on first completion, waits for losers
    // safely via a shared completion state, and returns {winner_index, std::variant<...>}.
    template <class... Items>
        requires (sizeof...(Items) > 0)
    [[nodiscard]] auto when_any(Items&&... items)
        -> task_coro<std::pair<size_t, std::variant<detail::combinator_result_t<Items>...>>> {
        using Tuple = std::tuple<std::decay_t<Items>...>;
        using Variant = std::variant<detail::combinator_result_t<Items>...>;
        using Return = std::pair<size_t, Variant>;

        struct race_state {
            std::atomic<size_t> winner{SIZE_MAX};
            manual_reset_event ready;
        };

        return []<size_t... Is>(Tuple tup, std::index_sequence<Is...>) -> task_coro<Return> {
            auto st = std::make_shared<race_state>();

            auto arm_one = [&]<size_t I>() {
                auto& elem = std::get<I>(tup);
                task t = detail::combinator_value<std::tuple_element_t<I, Tuple>>::get_task(elem);
                if (t.is_ended()) {
                    size_t expected = SIZE_MAX;
                    if (st->winner.compare_exchange_strong(expected, I, std::memory_order_acq_rel))
                        st->ready.set();
                } else {
                    task cb = task::create([st] {
                        size_t expected = SIZE_MAX;
                        if (st->winner.compare_exchange_strong(expected, I, std::memory_order_acq_rel))
                            st->ready.set();
                    });
                    t.callback(cb);
                    detail::combinator_value<std::tuple_element_t<I, Tuple>>::ensure_started(elem);
                }
            };
            (arm_one.template operator()<Is>(), ...);

            co_await st->ready.async_wait();
            const size_t win = st->winner.load(std::memory_order_acquire);

            auto cancel_one = [&]<size_t I>() {
                if (I != win) {
                    auto& elem = std::get<I>(tup);
                    task t = detail::combinator_value<std::tuple_element_t<I, Tuple>>::get_task(elem);
                    if (t && !t.is_ended())
                        t.notify_cancel();
                }
            };
            (cancel_one.template operator()<Is>(), ...);

            std::optional<Variant> result;
            std::exception_ptr win_ex;
            ((co_await detail::handle_one_for_any<Is>(tup, win, result, win_ex)), ...);

            if (win_ex)
                std::rethrow_exception(win_ex);
            co_return Return{win, std::move(*result)};
        }(std::make_tuple(std::forward<Items>(items)...), std::index_sequence_for<Items...>{});
    }

    // Bounds a task_coro<T> by a timeout.
    // Returns std::optional<T> (std::nullopt on timeout) or bool (false on timeout) for void.
    template <class T, class Rep, class Period>
    [[nodiscard]] auto with_timeout(task_coro<T> coro, const std::chrono::duration<Rep, Period>& duration)
        -> task_coro<std::conditional_t<std::is_void_v<T>, bool, std::optional<T>>> {
        using Ret = std::conditional_t<std::is_void_v<T>, bool, std::optional<T>>;
        const auto deadline = fast_task::deadline_after(duration);

        auto wrapper = [](task_coro<T> c, fast_task::time_point dl) -> task_coro<Ret> {
            auto done = std::make_shared<manual_reset_event>();
            task child = c.get_task();
            if (!child.is_ended()) {
                task cb = task::create([done] { done->set(); });
                child.callback(cb);
                child.set_timeout(dl);
                scheduler::start(child);
            } else {
                done->set();
            }

            bool finished_in_time = co_await done->async_wait_until(dl);
            if (!finished_in_time) {
                child.notify_cancel();
                try {
                    if constexpr (std::is_void_v<T>)
                        co_await c;
                    else
                        (void)co_await c;
                } catch (...) {
                }
                if constexpr (std::is_void_v<T>)
                    co_return false;
                else
                    co_return std::nullopt;
            }

            try {
                if constexpr (std::is_void_v<T>) {
                    co_await c;
                    co_return true;
                } else {
                    co_return co_await c;
                }
            } catch (const task_cancellation&) {
                if constexpr (std::is_void_v<T>)
                    co_return false;
                else
                    co_return std::nullopt;
            }
        }(std::move(coro), deadline);
        return wrapper;
    }
}

#endif /* FAST_TASK_INCLUDE_COROUTINE_COMBINATORS */
