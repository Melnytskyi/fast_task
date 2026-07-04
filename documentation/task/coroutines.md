`void this_task::the_coroutine_ended(const task&) noexcept;`
> Should be called by the coroutine when it finishes its execution. It will modify the task flags so the scheduler would call required condition variables and callbacks, update the scheduler's state.
>
> It removes the flag is_restartable from the task and marks it completed.
>
> Automatically called by the scheduler when the task canceled.

`bool this_task::transfer_to(const task& target);`
> Directly transfers the scheduler's current executing task to target after completion
>
> Both current task(c) and target(t) must:
>   - (c, t)have the same worker binding
>   - (t) The target could be scheduled (is_restartable = true or started = false)
>   - (c) the scheduler is executing on_start callback(no exception)
>   - (c) no pending transfers
>   - (c) still haven't reached the limit of cooperative transfers without returning to the scheduler (if such a limit is set)
>
> Returns true  -> transfer accepted, and now waiting for the return from on_start.
>
> Returns false -> conditions not met, caller must fall back to normal `scheduler::start(target)`.