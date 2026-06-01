#ifndef INCLUDE_POLYFILL_EXPECTED
#define INCLUDE_POLYFILL_EXPECTED
#include <stdexcept>
#include <utility>
#include <variant>

namespace fast_task::polyfill {
    template <class E>
    class unexpected {
        E val;

    public:
        constexpr explicit unexpected(E e) : val(std::move(e)) {}

        constexpr const E& error() const& noexcept {
            return val;
        }

        constexpr E& error() & noexcept {
            return val;
        }

        constexpr E&& error() && noexcept {
            return std::move(val);
        }
    };

    template <class T, class E>
    class expected {
        std::variant<T, unexpected<E>> m_var;

    public:
        constexpr expected()
            requires std::is_default_constructible_v<T>
            : m_var(std::in_place_type<T>) {}

        template <class U>
            requires std::is_constructible_v<T, U&&>
        constexpr expected(U&& v)
            : m_var(std::in_place_type<T>, std::forward<U>(v)) {}

        constexpr expected(const unexpected<E>& unexp) : m_var(unexp) {}

        constexpr expected(unexpected<E>&& unexp) : m_var(std::move(unexp)) {}

        constexpr bool has_value() const noexcept {
            return std::holds_alternative<T>(m_var);
        }

        constexpr explicit operator bool() const noexcept {
            return has_value();
        }

        constexpr T& operator*() & noexcept {
            return std::get<T>(m_var);
        }

        constexpr const T& operator*() const& noexcept {
            return std::get<T>(m_var);
        }

        constexpr T* operator->() & noexcept {
            return &std::get<T>(m_var);
        }

        constexpr const T* operator->() const& noexcept {
            return &std::get<T>(m_var);
        }

        constexpr T&& operator*() && noexcept {
            return std::get<T>(std::move(m_var));
        }

        constexpr E& error() & noexcept {
            return std::get<unexpected<E>>(m_var).error();
        }

        constexpr const E& error() const& noexcept {
            return std::get<unexpected<E>>(m_var).error();
        }

        constexpr E&& error() && noexcept {
            return std::get<unexpected<E>>(std::move(m_var)).error();
        }
    };

    template <class E>
    class expected<void, E> {
        std::variant<std::monostate, unexpected<E>> m_var;

    public:
        constexpr expected() noexcept : m_var(std::monostate{}) {}

        constexpr expected(const unexpected<E>& unexp) : m_var(unexp) {}

        constexpr expected(unexpected<E>&& unexp) : m_var(std::move(unexp)) {}

        constexpr bool has_value() const noexcept {
            return std::holds_alternative<std::monostate>(m_var);
        }

        constexpr explicit operator bool() const noexcept {
            return has_value();
        }

        constexpr E& error() & noexcept {
            return std::get<unexpected<E>>(m_var).error();
        }

        constexpr const E& error() const& noexcept {
            return std::get<unexpected<E>>(m_var).error();
        }

        constexpr E&& error() && noexcept {
            return std::get<unexpected<E>>(std::move(m_var)).error();
        }
    };

} // namespace fast_task::polyfill

#endif /* INCLUDE_POLYFILL_EXPECTED */
