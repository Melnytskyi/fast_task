// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <debug.hpp>
#include <files.hpp>

#include <atomic>
#include <barrier>
#include <format>
#include <iostream>
#include <mutex>
#include <optional>
#include <task.hpp>
#include <tasks/_internal.hpp>
#include <unordered_map>
#include <vector>

#ifdef FT_DEBUG_API_ENABLED
    #include <cpptrace/cpptrace.hpp>

namespace fast_task::debug {
    raw_stack_trace make_trace(size_t ignore_frames) {
        auto trace = cpptrace::generate_raw_trace(1 + ignore_frames);
        raw_stack_trace res{
            .entries = array<raw_stack_trace::entry>{trace.frames.size()}
        };
        size_t i = 0;
        for (auto& it : trace)
            res.entries[i++].entry_ptr = (void*)it;
        return res;
    }

    struct debug_registry;

    struct debug_data {
        uintptr_t virtual_id;
        std::optional<raw_stack_trace> init_trace;

        uintptr_t created_by_id;
        bool created_by_is_native;

        debug_data(debug_registry& reg);
    };

    struct debug_registry {
        std::unordered_map<task_mutex*, debug_data> mutex_instances;
        std::unordered_map<task_recursive_mutex*, debug_data> rec_mutex_instances;
        std::unordered_map<task_rw_mutex*, debug_data> rw_mutex_instances;
        std::unordered_map<task_condition_variable*, debug_data> cv_instances;
        std::unordered_map<task*, debug_data> task_instances;
        std::unordered_map<task_semaphore*, debug_data> sem_instances;
        std::unordered_map<task_limiter*, debug_data> limiter_instances;
        std::unordered_map<task_query*, debug_data> query_instances;
        std::unordered_map<deadline_timer*, debug_data> dtimer_instances;

        uintptr_t task_id_counter{0};
        bool _init_stack_trace;
    };

    protected_value<debug_registry, rw_mutex>& dbg_registry(){
        static protected_value<debug_registry, rw_mutex> d;
        return d;
    }

    debug_data::debug_data(debug_registry& reg) : virtual_id(reg.task_id_counter++) {
        if (reg._init_stack_trace)
            init_trace = make_trace(1);
        created_by_is_native = !loc.is_task_thread;
        if (loc.is_task_thread)
            created_by_id = reg.task_instances.at(loc.curr_task.get()).virtual_id;
        else
            created_by_id = _thread_id();
    }

    void enable_init_stack_trace(bool enable) {
        dbg_registry().set([enable](auto& reg) { reg._init_stack_trace = enable; });
    }

    // Forward declarations for internal functions

    raw_stack_trace capture_stack_trace(boost::context::continuation& cont) {
        if (!cont)
            return {};
        raw_stack_trace res;
        cont = std::move(cont.resume_with([&](boost::context::continuation&& c) {
            res = make_trace(1);
            return c.resume();
        }));
        return res;
    }

    struct _debug_collect {
        static void collect_mut_inst(program_state_dump& dump, debug_registry& reg) {
            size_t i = 0;
            dump.mutexes = array<raw_mutex_info>(reg.mutex_instances.size());
            for (auto&& [mutd, ddata] : reg.mutex_instances) {
                auto& [id, trace, created_by_id, created_by_is_native] = ddata;
                raw_mutex_info& info = dump.mutexes[i++];
                info.mutex_id = id;
                if (size_t(mutd->values.current_task) & native_thread_flag) {
                    info.owner_is_native = true;
                    info.owner_id = size_t(mutd->values.current_task) ^ native_thread_flag;
                } else {
                    info.owner_id = mutd->values.current_task ? reg.task_instances.at(mutd->values.current_task).virtual_id : FT_DEBUG_OPTIONAL;
                    info.owner_is_native = false;
                }
                size_t coll = 0;
                info.waiting_tasks_ids = array<awake_item>(mutd->values.resume_task.size());
                for (auto& it : mutd->values.resume_task) {
                    info.waiting_tasks_ids[coll++] = {
                        .id = it.task ? reg.task_instances.at(it.task.get()).virtual_id : FT_DEBUG_OPTIONAL,
                        .awake_check = it.awake_check,
                        .native_awake = (bool)it.native_check
                    };
                }
                info.created_by_id = created_by_id;
                info.created_by_is_native = created_by_is_native;
                if (trace)
                    info.init_call_stack = new raw_stack_trace(*trace);
            }
        }

        static void collect_rec_mut_inst(program_state_dump& dump, debug_registry& reg) {
            size_t i = 0;
            dump.rec_mutexes = array<raw_recursive_mutex_info>(reg.rec_mutex_instances.size());
            for (auto&& [mutd, ddata] : reg.rec_mutex_instances) {
                auto& [id, trace, created_by_id, created_by_is_native] = ddata;
                raw_recursive_mutex_info& info = dump.rec_mutexes[i++];
                info.mutex_id = id;
                info.internal_mutex_id = reg.mutex_instances.at(&mutd->mutex).virtual_id;
                info.recursion_count = mutd->recursive_count;
                info.created_by_id = created_by_id;
                info.created_by_is_native = created_by_is_native;
                if (trace)
                    info.init_call_stack = new raw_stack_trace(*trace);
            }
        }

        static void collect_rw_mut_inst(program_state_dump& dump, debug_registry& reg) {
            size_t i = 0;
            dump.rw_mutexes = array<raw_rw_mutex_info>(reg.rw_mutex_instances.size());
            for (auto&& [mutd, ddata] : reg.rw_mutex_instances) {
                auto& [id, trace, created_by_id, created_by_is_native] = ddata;
                raw_rw_mutex_info& info = dump.rw_mutexes[i++];
                info.mutex_id = id;
                if (size_t(mutd->values.current_writer_task) & native_thread_flag) {
                    info.writer_is_native = true;
                    info.writer_id = size_t(mutd->values.current_writer_task) ^ native_thread_flag;
                } else {
                    info.writer_id = mutd->values.current_writer_task ? reg.task_instances.at(mutd->values.current_writer_task).virtual_id : FT_DEBUG_OPTIONAL;
                    info.writer_is_native = false;
                }

                size_t coll = 0;
                info.reader_tasks_ids = array<uintptr_t>(mutd->values.readers.size());
                for (auto& it : mutd->values.readers)
                    info.reader_tasks_ids[coll++] = reg.task_instances.at(it).virtual_id;

                coll = 0;
                info.wait_tasks_ids = array<awake_item>(mutd->values.resume_task.size());
                for (auto& it : mutd->values.resume_task) {
                    info.wait_tasks_ids[coll++] = {
                        .id = it.task ? reg.task_instances.at(it.task.get()).virtual_id : FT_DEBUG_OPTIONAL,
                        .awake_check = it.awake_check,
                        .native_awake = (bool)it.native_check
                    };
                }
                info.created_by_id = created_by_id;
                info.created_by_is_native = created_by_is_native;
                if (trace)
                    info.init_call_stack = new raw_stack_trace(*trace);
            }
        }

        static void collect_task_inst(program_state_dump& dump, debug_registry& reg) {
            size_t i = 0;
            dump.tasks = array<raw_task_info>(reg.task_instances.size());
            for (auto&& [task_ptr, ddata] : reg.task_instances) {
                auto& [id, trace, created_by_id, created_by_is_native] = ddata;
                auto& task_data = get_data(task_ptr);
                raw_task_info& info = dump.tasks[i++];


                info.task_id = id;
                info.internal_condition_id = reg.cv_instances.at(&task_data.result_notify).virtual_id;

                if (task_data.exdata)
                    if (get_execution_data(task_ptr).context)
                        info.call_stack = capture_stack_trace(get_execution_data(task_ptr).context);
                info.counter_interrupt = task_ptr->get_counter_interrupt();
                info.counter_context_switch = task_ptr->get_counter_context_switch();
                info.priority = task_ptr->get_priority();
                info.awake_check = task_data.awake_check;
                info.bind_to_worker_id = task_data.completed;
                info.time_end_flag = task_data.time_end_flag;
                info.started = task_data.started;
                info.awaked = task_data.awaked;
                info.end_of_life = task_data.end_of_life;
                info.make_cancel = task_data.make_cancel;
                info.auto_bind_worker = task_data.auto_bind_worker;
                info.invalid_switch_caught = task_data.invalid_switch_caught;
                info.completed = task_data.completed;
                info.timeout_timestamp = task_data.timeout;
                info.created_by_id = created_by_id;
                info.created_by_is_native = created_by_is_native;
                if (trace)
                    info.init_call_stack = new raw_stack_trace(*trace);
            }
        }

        static void collect_cv_inst(program_state_dump& dump, debug_registry& reg) {
            size_t i = 0;
            dump.condition_variables = array<raw_condition_info>(reg.cv_instances.size());
            for (auto&& [mutd, ddata] : reg.cv_instances) {
                auto& [id, trace, created_by_id, created_by_is_native] = ddata;
                raw_condition_info& info = dump.condition_variables[i++];
                info.condition_id = id;
                size_t coll = 0;
                info.waiting_tasks_ids = array<awake_item>(mutd->values.resume_task.size());
                for (auto& it : mutd->values.resume_task) {
                    info.waiting_tasks_ids[coll++] = {
                        .id = it.task ? reg.task_instances.at(it.task.get()).virtual_id : FT_DEBUG_OPTIONAL,
                        .awake_check = it.awake_check,
                        .native_awake = (bool)it.native_check
                    };
                }
                info.created_by_id = created_by_id;
                info.created_by_is_native = created_by_is_native;
                if (trace)
                    info.init_call_stack = new raw_stack_trace(*trace);
            }
        }

        static void collect_sem_inst(program_state_dump& dump, debug_registry& reg) {
            size_t i = 0;
            dump.semaphores = array<raw_semaphore_info>(reg.sem_instances.size());
            for (auto&& [mutd, ddata] : reg.sem_instances) {
                auto& [id, trace, created_by_id, created_by_is_native] = ddata;
                raw_semaphore_info& info = dump.semaphores[i++];
                info.semaphore_id = id;
                info.allow_threshold = mutd->values.allow_threshold;
                info.max_threshold = mutd->values.max_threshold;
                size_t coll = 0;
                info.waiting_tasks_ids = array<awake_item>(mutd->values.resume_task.size());
                for (auto& it : mutd->values.resume_task) {
                    info.waiting_tasks_ids[coll++] = {
                        .id = it.task ? reg.task_instances.at(it.task.get()).virtual_id : FT_DEBUG_OPTIONAL,
                        .awake_check = it.awake_check,
                        .native_awake = false
                    };
                }
                info.created_by_id = created_by_id;
                info.created_by_is_native = created_by_is_native;
                if (trace)
                    info.init_call_stack = new raw_stack_trace(*trace);
            }
        }

        static void collect_limiter_inst(program_state_dump& dump, debug_registry& reg) {
            size_t i = 0;
            dump.limiters = array<raw_limiter_info>(reg.limiter_instances.size());
            for (auto&& [mutd, ddata] : reg.limiter_instances) {
                auto& [id, trace, created_by_id, created_by_is_native] = ddata;
                raw_limiter_info& info = dump.limiters[i++];
                info.limiter_id = id;
                info.allow_threshold = mutd->values.allow_threshold;
                info.max_threshold = mutd->values.max_threshold;
                info.locked = mutd->values.locked;
                size_t coll = 0;
                info.waiting_tasks_ids = array<awake_item>(mutd->values.resume_task.size());
                for (auto& it : mutd->values.resume_task) {
                    info.waiting_tasks_ids[coll++] = {
                        .id = it.task ? reg.task_instances.at(it.task.get()).virtual_id : FT_DEBUG_OPTIONAL,
                        .awake_check = it.awake_check,
                        .native_awake = false
                    };
                }
                info.created_by_id = created_by_id;
                info.created_by_is_native = created_by_is_native;
                if (trace)
                    info.init_call_stack = new raw_stack_trace(*trace);
            }
        }

        static void collect_query_inst(program_state_dump& dump, debug_registry& reg) {
            size_t i = 0;
            dump.queries = array<raw_query_info>(reg.query_instances.size());
            for (auto&& [mutd, ddata] : reg.query_instances) {
                auto& [id, trace, created_by_id, created_by_is_native] = ddata;
                raw_query_info& info = dump.queries[i++];
                info.query_id = id;
                info.internal_condition_id = reg.cv_instances.at(&mutd->handle->end_of_query).virtual_id;
                info.current_in_run = mutd->handle->now_at_execution;
                info.max_on_execution = mutd->handle->at_execution_max;
                info.enabled = mutd->handle->is_running;
                size_t coll = 0;
                info.waiting_tasks_ids = array<uintptr_t>(mutd->handle->tasks.size());
                for (auto& it : mutd->handle->tasks)
                    info.waiting_tasks_ids[coll++] = reg.task_instances.at(it.get()).virtual_id;
                info.created_by_id = created_by_id;
                info.created_by_is_native = created_by_is_native;
                if (trace)
                    info.init_call_stack = new raw_stack_trace(*trace);
            }
        }

        static void collect_dtimer_inst(program_state_dump& dump, debug_registry& reg) {
            size_t i = 0;
            dump.deadlines = array<raw_deadline_timer_info>(reg.dtimer_instances.size());
            for (auto&& [mutd, ddata] : reg.dtimer_instances) {
                auto& [id, trace, created_by_id, created_by_is_native] = ddata;
                raw_deadline_timer_info& info = dump.deadlines[i++];
                info.timer_id = id;
                info.shutdown = mutd->hh->shutdown;
                info.internal_mutex_id = reg.mutex_instances.at(&mutd->hh->no_race).virtual_id;
                info.timestamp = mutd->hh->time_point.time_since_epoch().count();
                size_t coll = 0;
                info.canceled_tasks = array<uintptr_t>(mutd->hh->canceled_tasks.size());
                for (auto& it : mutd->hh->canceled_tasks)
                    info.canceled_tasks[coll++] = reg.task_instances.at((task*)it).virtual_id;

                info.scheduled_tasks = array<uintptr_t>(mutd->hh->scheduled_tasks.size());
                for (auto& it : mutd->hh->scheduled_tasks)
                    info.scheduled_tasks[coll++] = reg.task_instances.at(it).virtual_id;

                info.created_by_id = created_by_id;
                info.created_by_is_native = created_by_is_native;
                if (trace)
                    info.init_call_stack = new raw_stack_trace(*trace);
            }
        }

        static void collect(program_state_dump& dump, debug_registry& reg) {
            collect_mut_inst(dump, reg);
            collect_rec_mut_inst(dump, reg);
            collect_rw_mut_inst(dump, reg);
            collect_task_inst(dump, reg);
            collect_cv_inst(dump, reg);
            collect_sem_inst(dump, reg);
            collect_limiter_inst(dump, reg);
            collect_query_inst(dump, reg);
            collect_dtimer_inst(dump, reg);
        }
    };

    program_state_dump dump_program_state() {
        program_state_dump dump;
        dump.start_timestamp = std::chrono::system_clock::now().time_since_epoch().count();
        scheduler::request_stw([&dump]() {
            dbg_registry().set([&dump](auto& reg) {
                _debug_collect::collect(dump, reg);
            });
        });
        dump.end_timestamp = std::chrono::system_clock::now().time_since_epoch().count();
        return dump;
    }

    std::optional<raw_stack_trace> request_task_stack_trace(const std::shared_ptr<task>& task) {
        if (task) {
            std::optional<raw_stack_trace> res;
            scheduler::request_stw([&]() {
                if (get_data(task).exdata)
                    if (get_execution_data(task).context)
                        res = capture_stack_trace(get_execution_data(task).context);
            });
            return res;
        } else
            return std::nullopt;
    }

    std::optional<raw_stack_trace> request_task_init_stack_trace(const std::shared_ptr<task>& task) {
        if (task)
            return dbg_registry().get([&task](auto& reg) -> std::optional<raw_stack_trace> {
                if (auto it = reg.task_instances.find(task.get()); it != reg.task_instances.end())
                    return it->second.init_trace;
                else
                    return std::nullopt;
            });
        else
            return std::nullopt;
    }

    raw_stack_trace::entry::lazy_resolve& resolve(raw_stack_trace::entry& en) {
        if (en.dat)
            return *en.dat;
        cpptrace::raw_trace trace;
        trace.frames = {(cpptrace::frame_ptr)en.entry_ptr};
        auto frame = trace.resolve().frames.front();
        en.dat = new raw_stack_trace::entry::lazy_resolve{
            .symbol = frame.symbol,
            .file = frame.filename,
            .line = frame.line.value() == UINT32_MAX ? int64_t(-1) : frame.line.value(),
            .column = frame.column.value() == UINT32_MAX ? int64_t(-1) : frame.column.value(),
            .is_inline = frame.is_inline
        };
        return *en.dat;
    }

    std::string raw_stack_trace::entry::symbol() {
        return resolve(*this).symbol;
    }

    std::string raw_stack_trace::entry::file() {
        return resolve(*this).file;
    }

    int64_t raw_stack_trace::entry::line() {
        return resolve(*this).line;
    }

    int64_t raw_stack_trace::entry::column() {
        return resolve(*this).column;
    }

    bool raw_stack_trace::entry::is_inline() {
        return resolve(*this).is_inline;
    }

    bool is_debug_enabled() {
        return true;
    }
}

namespace fast_task {
    void register_object(task_mutex* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.mutex_instances.emplace(val, reg);
        });
    }

    void register_object(task_recursive_mutex* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.rec_mutex_instances.emplace(val, reg);
        });
    }

    void register_object(task_rw_mutex* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.rw_mutex_instances.emplace(val, reg);
        });
    }

    void register_object(task_condition_variable* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.cv_instances.emplace(val, reg);
        });
    }

    void register_object(task* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.task_instances.emplace(val, reg);
        });
    }

    void register_object(task_semaphore* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.sem_instances.emplace(val, reg);
        });
    }

    void register_object(task_limiter* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.limiter_instances.emplace(val, reg);
        });
    }

    void register_object(task_query* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.query_instances.emplace(val, reg);
        });
    }

    void register_object(deadline_timer* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.dtimer_instances.emplace(val, reg);
        });
    }

    void unregister_object(task_mutex* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.mutex_instances.erase(val);
        });
    }

    void unregister_object(task_recursive_mutex* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.rec_mutex_instances.erase(val);
        });
    }

    void unregister_object(task_rw_mutex* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.rw_mutex_instances.erase(val);
        });
    }

    void unregister_object(task_condition_variable* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.cv_instances.erase(val);
        });
    }

    void unregister_object(task* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.task_instances.erase(val);
        });
    }

    void unregister_object(task_semaphore* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.sem_instances.erase(val);
        });
    }

    void unregister_object(task_limiter* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.limiter_instances.erase(val);
        });
    }

    void unregister_object(task_query* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.query_instances.erase(val);
        });
    }

    void unregister_object(deadline_timer* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.dtimer_instances.erase(val);
        });
    }
}
#else
namespace fast_task::debug {
    program_state_dump FT_API dump_program_state() {
        return {};
    }

    void enable_init_stack_trace(bool enable) {}

    std::string raw_stack_trace::entry::symbol() {
        return "";
    }

    std::string raw_stack_trace::entry::file() {
        return "";
    }

    int64_t raw_stack_trace::entry::line() {
        return -1;
    }

    int64_t raw_stack_trace::entry::column() {
        return -1;
    }

    bool raw_stack_trace::entry::is_inline() {
        return false;
    }

    std::optional<raw_stack_trace> request_task_stack_trace(const std::shared_ptr<task>&) {
        return nullptr;
    }

    std::optional<raw_stack_trace> request_task_init_stack_trace(const std::shared_ptr<task>&) {
        return nullptr;
    }

    bool is_debug_enabled() {
        return false;
    }
} // namespace fast_task::debug
#endif // FT_DEBUG_API_ENABLED
namespace fast_task::debug {
    raw_stack_trace::entry::~entry() {
        if (dat)
            delete dat;
        dat = nullptr;
    }

    raw_task_info::raw_task_info() {}

    raw_task_info::~raw_task_info() {
        if (init_call_stack)
            delete init_call_stack;
    }

    raw_mutex_info::raw_mutex_info() {}

    raw_mutex_info::~raw_mutex_info() {
        if (init_call_stack)
            delete init_call_stack;
    }

    raw_recursive_mutex_info::raw_recursive_mutex_info() {}

    raw_recursive_mutex_info::~raw_recursive_mutex_info() {
        if (init_call_stack)
            delete init_call_stack;
    }

    raw_rw_mutex_info::raw_rw_mutex_info() {}

    raw_rw_mutex_info::~raw_rw_mutex_info() {
        if (init_call_stack)
            delete init_call_stack;
    }

    raw_condition_info::raw_condition_info() {}

    raw_condition_info::~raw_condition_info() {
        if (init_call_stack)
            delete init_call_stack;
    }

    raw_semaphore_info::raw_semaphore_info() {}

    raw_semaphore_info::~raw_semaphore_info() {
        if (init_call_stack)
            delete init_call_stack;
    }

    raw_limiter_info::raw_limiter_info() {}

    raw_limiter_info::~raw_limiter_info() {
        if (init_call_stack)
            delete init_call_stack;
    }

    raw_query_info::raw_query_info() {}

    raw_query_info::~raw_query_info() {
        if (init_call_stack)
            delete init_call_stack;
    }

    raw_deadline_timer_info::raw_deadline_timer_info() {}

    raw_deadline_timer_info::~raw_deadline_timer_info() {
        if (init_call_stack)
            delete init_call_stack;
    }

    void FT_API dump_stack_(files::async_iofstream& ii, raw_stack_trace& trace, size_t t_count) {
        std::string space(t_count, '\t');
        ii << space << "Trace: " << std::endl;
        space += '\t';
        for (auto& it : trace.entries)
            ii << space << it.symbol() << ':' << it.line() << '.' << it.column() << (it.is_inline() ? " (inline)" : "") << std::endl;
    }

    void FT_API dump_await_(files::async_iofstream& ii, array<awake_item>& items, size_t t_count) {
        std::string space(t_count, '\t');
        ii << space << "Await items: " << std::endl;
        space += '\t';
        for (auto& it : items)
            if (it.native_awake)
                ii << space << "native thread" << std::endl;
            else
                ii << space << "id-" << it.id << ", awake_check-" << it.awake_check << std::endl;
    }

    void FT_API dump_task_ids_(files::async_iofstream& ii, array<uintptr_t>& items, size_t t_count) {
        std::string space(t_count + 1, '\t');
        for (auto& id : items)
            ii << space << id << std::endl;
    }

    void FT_API save_program_state_dump(const char* path) {
        auto dump = dump_program_state();
        files::async_iofstream ii(path, std::ios_base::trunc | std::ios_base::out);

        ii << "Program dump: " << std::endl;
        ii << "\tStart: " << std::chrono::system_clock::time_point(std::chrono::system_clock::duration(dump.start_timestamp)) << std::endl;
        ii << "\tEnd: " << std::chrono::system_clock::time_point(std::chrono::system_clock::duration(dump.end_timestamp)) << std::endl;
        for (auto& it : dump.condition_variables) {
            ii << "\tCondition variable: " << it.condition_id << std::endl;
            ii << "\t\tCreated by: " << it.created_by_id << (it.created_by_is_native ? " thread" : " task") << std::endl;
            if (it.init_call_stack)
                dump_stack_(ii, *it.init_call_stack, 2);
            dump_await_(ii, it.waiting_tasks_ids, 2);
        }
        for (auto& it : dump.deadlines) {
            ii << "\tDeadline: " << it.timer_id << std::endl;
            ii << "\t\tCreated by: " << it.created_by_id << (it.created_by_is_native ? " thread" : " task") << std::endl;
            if (it.init_call_stack)
                dump_stack_(ii, *it.init_call_stack, 2);
            ii << "\t\tScheduled tasks: " << std::endl;
            dump_task_ids_(ii, it.scheduled_tasks, 2);
            ii << "\t\tCanceled tasks: " << std::endl;
            dump_task_ids_(ii, it.canceled_tasks, 2);
            ii << "\t\tInternal mutex: " << it.internal_mutex_id << std::endl;
            ii << "\t\tShutdown: " << it.shutdown << std::endl;
            ii << "\t\tTimeout: " << std::chrono::system_clock::time_point(std::chrono::system_clock::duration(it.timestamp)) << std::endl;
        }
        for (auto& it : dump.limiters) {
            ii << "\tLimiter: " << it.limiter_id << std::endl;
            ii << "\t\tCreated by: " << it.created_by_id << (it.created_by_is_native ? " thread" : " task") << std::endl;
            if (it.init_call_stack)
                dump_stack_(ii, *it.init_call_stack, 2);
            dump_await_(ii, it.waiting_tasks_ids, 2);
            ii << "\t\tAllow threshold: " << it.allow_threshold << std::endl;
            ii << "\t\tMax threshold: " << it.max_threshold << std::endl;
            ii << "\t\tIs locked: " << it.locked << std::endl;
        }
        for (auto& it : dump.mutexes) {
            ii << "\tMutex: " << it.mutex_id << std::endl;
            ii << "\t\tCreated by: " << it.created_by_id << (it.created_by_is_native ? " thread" : " task") << std::endl;
            if (it.init_call_stack)
                dump_stack_(ii, *it.init_call_stack, 2);
            dump_await_(ii, it.waiting_tasks_ids, 2);
            ii << "\t\tOwner: " << (it.owner_id != FT_DEBUG_OPTIONAL ? std::to_string(it.owner_id) : "none");
            if (it.owner_id != FT_DEBUG_OPTIONAL)
                ii << (it.owner_is_native ? " thread" : " task") << std::endl;
        }
        for (auto& it : dump.queries) {
            ii << "\tQuery " << it.query_id << std::endl;
            ii << "\t\tCreated by: " << it.created_by_id << (it.created_by_is_native ? " thread" : " task") << std::endl;
            if (it.init_call_stack)
                dump_stack_(ii, *it.init_call_stack, 2);
            ii << "\t\tInternal condition variable: " << it.internal_condition_id << std::endl;
            ii << "\t\tMax on execution: " << it.max_on_execution << std::endl;
            ii << "\t\tCurrent in run: " << it.current_in_run << std::endl;
            ii << "\t\tIs enabled: " << it.enabled << std::endl;
            ii << "\t\tWaiting tasks: " << std::endl;
            dump_task_ids_(ii, it.waiting_tasks_ids, 2);
        }
        for (auto& it : dump.rec_mutexes) {
            ii << "\tRecursive mutex: " << it.mutex_id << std::endl;
            ii << "\t\tCreated by: " << it.created_by_id << (it.created_by_is_native ? " thread" : " task") << std::endl;
            if (it.init_call_stack)
                dump_stack_(ii, *it.init_call_stack, 2);
            ii << "\t\tInternal mutex: " << it.internal_mutex_id << std::endl;
            ii << "\t\tRecursion count: " << it.recursion_count << std::endl;
        }
        for (auto& it : dump.rw_mutexes) {
            ii << "\tRW Mutex: " << it.mutex_id << std::endl;
            ii << "\t\tCreated by: " << it.created_by_id << (it.created_by_is_native ? " thread" : " task") << std::endl;
            if (it.init_call_stack)
                dump_stack_(ii, *it.init_call_stack, 2);
            ii << "\t\tWriter: " << (it.writer_id != FT_DEBUG_OPTIONAL ? std::to_string(it.writer_id) : "none");
            if (it.writer_id != FT_DEBUG_OPTIONAL)
                ii << (it.writer_is_native ? " thread" : " task") << std::endl;
            ii << "\t\tReader tasks: " << std::endl;
            dump_task_ids_(ii, it.reader_tasks_ids, 2);
            dump_await_(ii, it.wait_tasks_ids, 2);
        }
        for (auto& it : dump.semaphores) {
            ii << "\tSemaphore: " << it.semaphore_id << std::endl;
            ii << "\t\tCreated by: " << it.created_by_id << (it.created_by_is_native ? " thread" : " task") << std::endl;
            if (it.init_call_stack)
                dump_stack_(ii, *it.init_call_stack, 2);
            dump_await_(ii, it.waiting_tasks_ids, 2);
            ii << "\t\tAllow threshold: " << it.allow_threshold << std::endl;
            ii << "\t\tMax threshold: " << it.max_threshold << std::endl;
        }
        auto hi_current = std::chrono::high_resolution_clock::now();
        for (auto& it : dump.tasks) {
            ii << "\tTask: " << it.task_id << std::endl;
            ii << "\t\tCreated by: " << it.created_by_id << (it.created_by_is_native ? " thread" : " task") << std::endl;
            if (it.init_call_stack)
                dump_stack_(ii, *it.init_call_stack, 2);

            ii << "\t\tCall stack" << std::endl;
            dump_stack_(ii, it.call_stack, 2);
            switch (it.priority) {
            case task_priority::background:
                ii << "\t\tPriority: background" << std::endl;
                break;
            case task_priority::low:
                ii << "\t\tPriority: low" << std::endl;
                break;
            case task_priority::lower:
                ii << "\t\tPriority: lower" << std::endl;
                break;
            case task_priority::normal:
                ii << "\t\tPriority: normal" << std::endl;
                break;
            case task_priority::higher:
                ii << "\t\tPriority: higher" << std::endl;
                break;
            case task_priority::high:
                ii << "\t\tPriority: high" << std::endl;
                break;
            case task_priority::semi_realtime:
                ii << "\t\tPriority: semi realtime" << std::endl;
                break;
            default:
                ii << "\t\tPriority: ???" << std::endl;
                break;
            }

            ii << "\t\tCounter interrupt: " << it.counter_interrupt << std::endl;
            ii << "\t\tCounter constext switch: " << it.counter_context_switch << std::endl;
            ii << "\t\tAwake check: " << it.awake_check << std::endl;
            ii << "\t\tBinded to worker id: " << it.bind_to_worker_id << std::endl;
            ii << "\t\tTime end flag: " << it.time_end_flag << std::endl;
            ii << "\t\tIs started: " << it.started << std::endl;
            ii << "\t\tAwaked: " << it.awaked << std::endl;
            ii << "\t\tEnd of life: " << it.end_of_life << std::endl;
            ii << "\t\tRequested cancel: " << it.make_cancel << std::endl;
            ii << "\t\tAuto bind enabled: " << it.auto_bind_worker << std::endl;
            ii << "\t\tInvalid switch caught: " << it.invalid_switch_caught << std::endl;
            ii << "\t\tIs completed: " << it.completed << std::endl;
            if (it.timeout_timestamp != std::chrono::high_resolution_clock::time_point::min().time_since_epoch().count())
                ii << "\t\tTimeouts in: " << std::chrono::hh_mm_ss{std::chrono::high_resolution_clock::time_point(std::chrono::high_resolution_clock::duration(it.timeout_timestamp)) - hi_current} << '\n';
        }
    }
}