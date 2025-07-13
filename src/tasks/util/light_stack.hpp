// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#pragma once
#ifndef FAST_TASK_LIGHT_STACK
    #define FAST_TASK_LIGHT_STACK

    #include <boost/context/fiber.hpp>
    #include <boost/context/stack_context.hpp>
    #include <boost/context/stack_traits.hpp>

namespace fast_task {
    struct light_stack {
        typedef boost::context::stack_traits traits_type;
        typedef boost::context::stack_context stack_context;

        light_stack(std::size_t size = traits_type::default_size()) BOOST_NOEXCEPT_OR_NOTHROW;
        stack_context allocate();
        void deallocate(stack_context& sctx);

        static bool flush_used_stacks;
        static size_t max_buffer_size;

    private:
        std::size_t size;
    };
}


#endif
