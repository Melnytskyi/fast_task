// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_EXCEPTIONS
#define FAST_TASK_INCLUDE_EXCEPTIONS
#include "shared.hpp"

namespace fast_task {
    struct FT_API exception {
        virtual const char* what() = 0;
    };

    //this exception should never be thrown
    struct FT_API invalid_switch final : public exception {
        inline const char* what() override {
            return "Caught task that switched context but not scheduled or finalized self. This could happen if the scheduler functions been called directly or the synchronization primitives is broken.";
        }
    };

    struct FT_API invalid_context final : public exception {
        inline const char* what() override {
            return "Native thread called task only function while being not in task context.";
        }
    };

    struct FT_API invalid_native_context final : public exception {
        inline const char* what() override {
            return "Task called native thread only function.";
        }
    };

    struct FT_API no_assignable_workers final : public exception {
        inline const char* what() override {
            return "Tried to assign task to binded workers, but there no worker that allows implicit start.";
        }
    };

    struct FT_API file_closed final : public exception {
        inline const char* what() override {
            return "Tried to use functions on closed file.";
        }
    };


    //this exception should never be catched
    class FT_API task_cancellation {
        bool in_landing = false;
        friend void forceCancelCancellation(const task_cancellation& cancel_token);

    public:
        task_cancellation();
        ~task_cancellation();
        bool _in_landing();
    };
}

#endif /* FAST_TASK_INCLUDE_EXCEPTIONS */
