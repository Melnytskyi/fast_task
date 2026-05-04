#ifndef INCLUDE_TASK_THIS_TASK
#define INCLUDE_TASK_THIS_TASK
#include "fwd.hpp"

namespace fast_task {
    namespace this_task {
        size_t FT_API get_id() noexcept;
        void FT_API yield();
        void FT_API sleep_until(std::chrono::high_resolution_clock::time_point time_point);

        template <class Dur_resolution, class Dur_type>
        void sleep_for(std::chrono::duration<Dur_resolution, Dur_type> duration) {
            sleep_until(std::chrono::high_resolution_clock::now() + duration);
        }

    void FT_API check_cancellation();
    bool FT_API is_cancellation_requested() noexcept;
    void FT_API self_cancel();
    bool FT_API is_task() noexcept;
    void FT_API the_coroutine_ended(const std::shared_ptr<task>&) noexcept;
    bool FT_API transfer_to(const std::shared_ptr<task>& target);


    bool FT_API enter_sleep_until(std::chrono::high_resolution_clock::time_point time_point);
    bool FT_API enter_yield();
}
#endif /* INCLUDE_TASK_THIS_TASK */
