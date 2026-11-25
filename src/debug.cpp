// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <fast_task/debug.hpp>
#include <fast_task/file.hpp>
#include <fast_task/internal/futex.hpp>
#include <fast_task/native/mutex.hpp>

#include <atomic>
#include <barrier>
#include <fast_task/task.hpp>
#include <format>
#include <iostream>
#include <mutex>
#include <optional>
#include <tasks/_internal.hpp>
#include <unordered_map>
#include <vector>

namespace fast_task::debug {
    namespace {
        std::mutex& stack_entry_resolve_mutex() {
            static std::mutex mtx;
            return mtx;
        }
    }
}

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

        debug_data();
        debug_data(debug_registry& reg);
    };

    struct debug_registry {
        std::unordered_map<mutex*, debug_data> mutex_instances;
        std::unordered_map<recursive_mutex*, debug_data> rec_mutex_instances;
        std::unordered_map<rw_mutex*, debug_data> rw_mutex_instances;
        std::unordered_map<condition_variable*, debug_data> cv_instances;
        std::unordered_map<size_t, debug_data> task_instances;
        std::unordered_map<semaphore*, debug_data> sem_instances;
        std::unordered_map<limiter*, debug_data> limiter_instances;
        std::unordered_map<queue*, debug_data> queue_instances;
        std::unordered_map<deadline_timer*, debug_data> dtimer_instances;

        uintptr_t task_id_counter{0};
        bool _init_stack_trace = false;
    };

    protected_value<debug_registry, native::rw_mutex>& dbg_registry() {
        static protected_value<debug_registry, native::rw_mutex> d;
        return d;
    }

    debug_data::debug_data(debug_registry& reg) : virtual_id(reg.task_id_counter++) {
        if (reg._init_stack_trace)
            init_trace = make_trace(1);
        auto* loc = get_loc();
        created_by_is_native = !loc || !loc->is_task_thread;
        if (loc && loc->is_task_thread) {
            auto it = reg.task_instances.find(loc->curr_task.get_id());
            created_by_id = it != reg.task_instances.end() ? it->second.virtual_id : FT_DEBUG_OPTIONAL;
        } else
            created_by_id = _thread_id();
    }

    debug_data::debug_data() : virtual_id(0), init_trace(std::nullopt), created_by_id(0), created_by_is_native(false) {}

    void enable_init_stack_trace(bool enable) {
        dbg_registry().set([enable](auto& reg) { reg._init_stack_trace = enable; });
    }

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
        static uintptr_t lookup_task_id(const debug_registry& reg, size_t raw_id) {
            if (!raw_id)
                return FT_DEBUG_OPTIONAL;
            auto it = reg.task_instances.find(raw_id);
            return it != reg.task_instances.end() ? it->second.virtual_id : FT_DEBUG_OPTIONAL;
        }

        static array<awake_item> collect_futex_waiters(void* address, const debug_registry& reg) {
            struct waiter_collect_ctx {
                std::vector<awake_item> items;
                const debug_registry* reg;
            } ctx{{}, &reg};

            futex::iterate_waiters(
                address,
                [](void*, void* data, const futex::waiter_info& waiter) {
                    auto* c = reinterpret_cast<waiter_collect_ctx*>(data);
                    awake_item item{};
                    item.awake_check = 0;
                    if (waiter.is_native) {
                        item.native_awake = true;
                        item.id = waiter.task_id ^ native_thread_flag;
                    } else {
                        item.native_awake = false;
                        item.id = lookup_task_id(*c->reg, waiter.task_id);
                    }
                    c->items.push_back(item);
                },
                &ctx
            );

            array<awake_item> result(ctx.items.size());
            for (size_t idx = 0; idx < ctx.items.size(); ++idx)
                result[idx] = ctx.items[idx];
            return result;
        }

        static void collect_mut_inst(program_state_dump& dump, debug_registry& reg) {
            size_t i = 0;
            dump.mutexes = array<raw_mutex_info>(reg.mutex_instances.size());
            for (auto&& [mutd, ddata] : reg.mutex_instances) {
                auto& [id, trace, created_by_id, created_by_is_native] = ddata;
                raw_mutex_info& info = dump.mutexes[i++];
                info.mutex_id = id;
                size_t raw_owner = mutd->state.load(std::memory_order_relaxed) & ~native_thread_data;
                if (raw_owner & native_thread_flag) {
                    info.owner_is_native = true;
                    info.owner_id = raw_owner ^ native_thread_flag;
                } else {
                    info.owner_id = lookup_task_id(reg, raw_owner);
                    info.owner_is_native = false;
                }
                info.waiting_tasks_ids = collect_futex_waiters(&mutd->state, reg);
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
                auto mit = reg.mutex_instances.find(&mutd->mut);
                info.internal_mutex_id = mit != reg.mutex_instances.end() ? mit->second.virtual_id : FT_DEBUG_OPTIONAL;
                info.recursion_count = mutd->recursive_count.load(std::memory_order_relaxed);
                info.created_by_id = created_by_id;
                info.created_by_is_native = created_by_is_native;
                if (trace)
                    info.init_call_stack = new raw_stack_trace(*trace);
            }
        }

        struct rw_waiter_collect {
            std::vector<awake_item> items;
            std::vector<uint8_t> keys;
            const debug_registry* reg;
        };

        static void collect_rw_waiter(void*, void* data, const futex::waiter_info& waiter) {
            auto* coll = reinterpret_cast<rw_waiter_collect*>(data);
            awake_item item{};
            item.awake_check = 0;
            if (waiter.is_native) {
                item.native_awake = true;
                item.id = waiter.task_id ^ native_thread_flag;
            } else {
                item.native_awake = false;
                item.id = lookup_task_id(*coll->reg, waiter.task_id);
            }
            coll->items.push_back(item);
            coll->keys.push_back(waiter.key.data);
        }

        static void collect_rw_mut_inst(program_state_dump& dump, debug_registry& reg) {
            size_t i = 0;
            dump.rw_mutexes = array<raw_rw_mutex_info>(reg.rw_mutex_instances.size());
            for (auto&& [mutd, ddata] : reg.rw_mutex_instances) {
                auto& [id, trace, created_by_id, created_by_is_native] = ddata;
                raw_rw_mutex_info& info = dump.rw_mutexes[i++];
                info.mutex_id = id;

                size_t writer = mutd->debug_writer_owner();
                if (writer & native_thread_flag) {
                    info.writer_is_native = true;
                    info.writer_id = writer ^ native_thread_flag;
                } else {
                    info.writer_id = lookup_task_id(reg, writer);
                    info.writer_is_native = false;
                }

                info.reader_tasks_ids = array<uintptr_t>(mutd->debug_reader_count());

                rw_waiter_collect coll{{}, {}, &reg};
                futex::iterate_waiters(&mutd->values.state, collect_rw_waiter, &coll);
                info.wait_tasks_ids = array<awake_item>(coll.items.size());
                info.wait_tasks_keys = array<uint8_t>(coll.keys.size());
                for (size_t idx = 0; idx < coll.items.size(); ++idx) {
                    info.wait_tasks_ids[idx] = coll.items[idx];
                    info.wait_tasks_keys[idx] = coll.keys[idx];
                }
                info.created_by_id = created_by_id;
                info.created_by_is_native = created_by_is_native;
                if (trace)
                    info.init_call_stack = new raw_stack_trace(*trace);
            }
        }

        static void collect_task_inst(program_state_dump& dump_z, debug_registry& reg_z) {
            struct lambda_data_t {
                std::vector<raw_task_info> tasks;
                debug_registry& reg;
            } lambda_data{{}, reg_z};

            fast_task::glob.allocators.gba.iterate_all(
                [](fast_task::task_object* task_data, void* d) {
                    if (task_data->is_released())
                        return;

                    auto& data = *reinterpret_cast<lambda_data_t*>(d);
                    auto& reg = data.reg;

                    data.tasks.emplace_back();
                    raw_task_info& info = data.tasks.back();

                    auto reg_it = reg.task_instances.find(task_data->get_id());
                    if (reg_it != reg.task_instances.end()) {
                        auto& [id, trace, created_by_id, created_by_is_native] = reg_it->second;
                        info.task_id = id;
                        info.created_by_id = created_by_id;
                        info.created_by_is_native = created_by_is_native;
                        if (trace)
                            info.init_call_stack = new raw_stack_trace(*trace);
                    } else {
                        info.task_id = FT_DEBUG_OPTIONAL;
                        info.created_by_id = FT_DEBUG_OPTIONAL;
                        info.created_by_is_native = false;
                    }

                    switch (task_data->status.load(std::memory_order_relaxed)) {
                    case task_object::status_e::created:
                        info.status = raw_task_info::status_e::created;
                        break;
                    case task_object::status_e::scheduled:
                        info.status = raw_task_info::status_e::scheduled;
                        break;
                    case task_object::status_e::running:
                        info.status = raw_task_info::status_e::running;
                        break;
                    case task_object::status_e::suspending:
                        info.status = raw_task_info::status_e::suspending;
                        break;
                    case task_object::status_e::suspended:
                        info.status = raw_task_info::status_e::suspended;
                        break;
                    case task_object::status_e::ended:
                        info.status = raw_task_info::status_e::ended;
                        break;
                    default:
                        info.status = raw_task_info::status_e::ended;
                    }

                    info.is_restartable = task_data->get_is_restartable();
                    info.is_on_scheduler = task_data->get_is_on_scheduler();
                    info.time_end = task_data->get_time_end();
                    info.awaked = task_data->get_awaked();
                    info.pool_assigned = task_data->get_pool_assigned();
                    info.is_sbo = task_data->get_is_sbo();
                    info.spin_lock_locked = (task_data->state.load(std::memory_order_relaxed) & (task_object::state_f::spin_lock_locked)) != 0;
                    info.cancellation_requested = task_data->get_cancellation_requested();
                    info.invalid_switch_caught = task_data->get_invalid_switch_caught();
                    info.completed = task_data->get_completed();
                    info.stored_exception = false;

                    auto* ex = task_data->exdata.load(std::memory_order_acquire);
    #if defined(FT_EXCEPTION_POLICY_PRESERVE)
                    if (ex)
                        info.stored_exception = static_cast<bool>(ex->switch_preserve);
    #endif
                    info.counter = task_data->link_counter.load(std::memory_order_relaxed);
                    info.tls_info = nullptr;
                    info.waiting_tasks_ids = collect_futex_waiters(task_data, reg);

                    info.awake_check = task_data->awake_check;
                    info.pool_slot = task_data->pool_index;
                    if (ex) {
                        info.timeout_timestamp = ex->timeout;
                        if (ex->context)
                            info.call_stack = capture_stack_trace(ex->context);
    #ifdef FT_ENABLE_PREEMPTIVE_SCHEDULER
                        info.counter_interrupt = ex->interrupt_count;
                        info.current_available_quantum_ns = static_cast<uint64_t>(ex->current_available_quantum.count());
                        info.priority = ex->priority;
                        info.interrupt_data = ex->interrupt_data;
    #else
                        info.counter_interrupt = 0;
                        info.current_available_quantum_ns = 0;
                        info.priority = task_data->get_priority();
                        info.interrupt_data = 0;
    #endif
                        info.counter_context_switch = ex->context_switch_count;
                    } else {
                        info.timeout_timestamp = fast_task::no_deadline.time_since_epoch().count();
                        info.counter_interrupt = 0;
                        info.counter_context_switch = 0;
                        info.current_available_quantum_ns = 0;
                        info.priority = task_data->get_priority();
                        info.interrupt_data = 0;
                    }

                    info.on_start_override = task_data->on_start_override;
                    info.vtable = task_data->vtable;
                },
                &lambda_data
            );

            dump_z.tasks = array<raw_task_info>(lambda_data.tasks.size());
            for (size_t idx = 0; idx < lambda_data.tasks.size(); ++idx)
                dump_z.tasks[idx] = std::move(lambda_data.tasks[idx]);
        }

        static void collect_cv_inst(program_state_dump& dump, debug_registry& reg) {
            size_t i = 0;
            dump.condition_variables = array<raw_condition_info>(reg.cv_instances.size());
            for (auto&& [mutd, ddata] : reg.cv_instances) {
                auto& [id, trace, created_by_id, created_by_is_native] = ddata;
                raw_condition_info& info = dump.condition_variables[i++];
                info.condition_id = id;
                info.waiting_tasks_ids = collect_futex_waiters(&mutd->address, reg);
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
                info.allow_threshold = mutd->values.state.load(std::memory_order_relaxed) & ~native_thread_data;
                info.max_threshold = mutd->values.max_threshold.load(std::memory_order_relaxed);
                info.waiting_tasks_ids = collect_futex_waiters(&mutd->values.state, reg);
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
                size_t available = mutd->values.state.load(std::memory_order_relaxed) & ~native_thread_data;
                info.allow_threshold = available;
                info.max_threshold = mutd->values.max_threshold.load(std::memory_order_relaxed);
                info.locked = (available == 0);
                info.waiting_tasks_ids = collect_futex_waiters(&mutd->values.state, reg);
                info.created_by_id = created_by_id;
                info.created_by_is_native = created_by_is_native;
                if (trace)
                    info.init_call_stack = new raw_stack_trace(*trace);
            }
        }

        static void collect_queue_inst(program_state_dump& dump, debug_registry& reg) {
            size_t i = 0;
            dump.queries = array<raw_queue_info>(reg.queue_instances.size());
            for (auto&& [mutd, ddata] : reg.queue_instances) {
                (void)mutd;
                auto& [id, trace, created_by_id, created_by_is_native] = ddata;
                raw_queue_info& info = dump.queries[i++];
                info.queue_id = id;
                info.internal_condition_id = FT_DEBUG_OPTIONAL;
                info.current_in_run = 0;
                info.max_on_execution = 0;
                info.enabled = false;
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
                info.shutdown = (mutd->hh == nullptr);
                info.internal_mutex_id = FT_DEBUG_OPTIONAL;
                info.timestamp = std::chrono::system_clock::time_point::max().time_since_epoch().count();
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
            collect_queue_inst(dump, reg);
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

    std::optional<raw_stack_trace> request_task_stack_trace(const task& task) {
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

    std::optional<raw_stack_trace> request_task_init_stack_trace(const task& task) {
        if (task)
            return dbg_registry().get([&task](auto& reg) -> std::optional<raw_stack_trace> {
                if (auto it = reg.task_instances.find(task.get_id()); it != reg.task_instances.end())
                    return it->second.init_trace;
                else
                    return std::nullopt;
            });
        else
            return std::nullopt;
    }

    raw_stack_trace::entry::lazy_resolve& resolve(raw_stack_trace::entry& en) {
        {
            std::lock_guard<std::mutex> lock(stack_entry_resolve_mutex());
            if (en.dat)
                return *en.dat;
        }
        cpptrace::raw_trace trace;
        trace.frames = {(cpptrace::frame_ptr)en.entry_ptr};
        auto resolved = trace.resolve();
        auto* created = new raw_stack_trace::entry::lazy_resolve{};
        if (!resolved.frames.empty()) {
            const auto& frame = resolved.frames.front();
            created->symbol = frame.symbol;
            created->file = frame.filename;
            created->line = (!frame.line.has_value() || frame.line.value() == UINT32_MAX) ? int64_t(-1) : static_cast<int64_t>(frame.line.value());
            created->column = (!frame.column.has_value() || frame.column.value() == UINT32_MAX) ? int64_t(-1) : static_cast<int64_t>(frame.column.value());
            created->is_inline = frame.is_inline;
        }
        std::lock_guard<std::mutex> lock(stack_entry_resolve_mutex());
        if (en.dat) {
            delete created;
            return *en.dat;
        }
        en.dat = created;
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
    void register_object(mutex* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.mutex_instances.emplace(val, reg);
        });
    }

    void register_object(recursive_mutex* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.rec_mutex_instances.emplace(val, reg);
        });
    }

    void register_object(rw_mutex* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.rw_mutex_instances.emplace(val, reg);
        });
    }

    void register_object(condition_variable* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.cv_instances.emplace(val, reg);
        });
    }

    void register_object(task_object* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.task_instances.emplace(val->get_id(), reg);
        });
    }

    void register_object(semaphore* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.sem_instances.emplace(val, reg);
        });
    }

    void register_object(limiter* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.limiter_instances.emplace(val, reg);
        });
    }

    void register_object(queue* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.queue_instances.emplace(val, reg);
        });
    }

    void register_object(deadline_timer* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.dtimer_instances.emplace(val, reg);
        });
    }

    void unregister_object(mutex* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.mutex_instances.erase(val);
        });
    }

    void unregister_object(recursive_mutex* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.rec_mutex_instances.erase(val);
        });
    }

    void unregister_object(rw_mutex* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.rw_mutex_instances.erase(val);
        });
    }

    void unregister_object(condition_variable* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.cv_instances.erase(val);
        });
    }

    void unregister_object(task_object* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.task_instances.erase(val->get_id());
        });
    }

    void unregister_object(semaphore* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.sem_instances.erase(val);
        });
    }

    void unregister_object(limiter* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.limiter_instances.erase(val);
        });
    }

    void unregister_object(queue* val) {
        debug::dbg_registry().set([val](auto& reg) {
            reg.queue_instances.erase(val);
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

    void enable_init_stack_trace(bool) {}

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

    std::optional<raw_stack_trace> request_task_stack_trace(const task&) {
        return std::nullopt;
    }

    std::optional<raw_stack_trace> request_task_init_stack_trace(const task&) {
        return std::nullopt;
    }

    bool is_debug_enabled() {
        return false;
    }
} // namespace fast_task::debug
#endif // FT_DEBUG_API_ENABLED
namespace fast_task::debug {
    namespace {
        raw_stack_trace* clone_stack_trace(const raw_stack_trace* src) {
            return src ? new raw_stack_trace(*src) : nullptr;
        }
    }

    raw_stack_trace::entry::entry(const entry& other) : entry_ptr(other.entry_ptr), dat(nullptr) {
        std::lock_guard<std::mutex> lock(stack_entry_resolve_mutex());
        if (other.dat)
            dat = new lazy_resolve(*other.dat);
    }

    raw_stack_trace::entry::entry(entry&& other) noexcept : entry_ptr(other.entry_ptr), dat(other.dat) {
        other.entry_ptr = nullptr;
        other.dat = nullptr;
    }

    raw_stack_trace::entry& raw_stack_trace::entry::operator=(const entry& other) {
        if (this != &other) {
            entry tmp(other);
            *this = std::move(tmp);
        }
        return *this;
    }

    raw_stack_trace::entry& raw_stack_trace::entry::operator=(entry&& other) noexcept {
        if (this != &other) {
            delete dat;
            entry_ptr = other.entry_ptr;
            dat = other.dat;
            other.entry_ptr = nullptr;
            other.dat = nullptr;
        }
        return *this;
    }

    raw_stack_trace::entry::~entry() {
        delete dat;
        dat = nullptr;
    }

    raw_task_info::raw_task_info() = default;

    raw_task_info::raw_task_info(const raw_task_info& other)
        : task_id(other.task_id),
          status(other.status),
          is_restartable(other.is_restartable),
          is_on_scheduler(other.is_on_scheduler),
          time_end(other.time_end),
          awaked(other.awaked),
          pool_assigned(other.pool_assigned),
          is_sbo(other.is_sbo),
          spin_lock_locked(other.spin_lock_locked),
          cancellation_requested(other.cancellation_requested),
          invalid_switch_caught(other.invalid_switch_caught),
          completed(other.completed),
          stored_exception(other.stored_exception),
          counter(other.counter),
          waiting_tasks_ids(other.waiting_tasks_ids),
          tls_info(other.tls_info),
          timeout_timestamp(other.timeout_timestamp),
          call_stack(other.call_stack),
          counter_interrupt(other.counter_interrupt),
          counter_context_switch(other.counter_context_switch),
          priority(other.priority),
          awake_check(other.awake_check),
          pool_slot(other.pool_slot),
          created_by_id(other.created_by_id),
          created_by_is_native(other.created_by_is_native),
          current_available_quantum_ns(other.current_available_quantum_ns),
          interrupt_data(other.interrupt_data),
          on_start_override(other.on_start_override),
          vtable(other.vtable),
          init_call_stack(clone_stack_trace(other.init_call_stack)) {}

    raw_task_info::raw_task_info(raw_task_info&& other) noexcept
        : task_id(other.task_id),
          status(other.status),
          is_restartable(other.is_restartable),
          is_on_scheduler(other.is_on_scheduler),
          time_end(other.time_end),
          awaked(other.awaked),
          pool_assigned(other.pool_assigned),
          is_sbo(other.is_sbo),
          spin_lock_locked(other.spin_lock_locked),
          cancellation_requested(other.cancellation_requested),
          invalid_switch_caught(other.invalid_switch_caught),
          completed(other.completed),
          stored_exception(other.stored_exception),
          counter(other.counter),
          waiting_tasks_ids(std::move(other.waiting_tasks_ids)),
          tls_info(other.tls_info),
          timeout_timestamp(other.timeout_timestamp),
          call_stack(std::move(other.call_stack)),
          counter_interrupt(other.counter_interrupt),
          counter_context_switch(other.counter_context_switch),
          priority(other.priority),
          awake_check(other.awake_check),
          pool_slot(other.pool_slot),
          created_by_id(other.created_by_id),
          created_by_is_native(other.created_by_is_native),
          current_available_quantum_ns(other.current_available_quantum_ns),
          interrupt_data(other.interrupt_data),
          on_start_override(other.on_start_override),
          vtable(other.vtable),
          init_call_stack(other.init_call_stack) {
        other.init_call_stack = nullptr;
    }

    raw_task_info& raw_task_info::operator=(const raw_task_info& other) {
        if (this != &other) {
            raw_task_info tmp(other);
            *this = std::move(tmp);
        }
        return *this;
    }

    raw_task_info& raw_task_info::operator=(raw_task_info&& other) noexcept {
        if (this != &other) {
            delete init_call_stack;
            task_id = other.task_id;
            status = other.status;
            is_restartable = other.is_restartable;
            is_on_scheduler = other.is_on_scheduler;
            time_end = other.time_end;
            awaked = other.awaked;
            pool_assigned = other.pool_assigned;
            is_sbo = other.is_sbo;
            spin_lock_locked = other.spin_lock_locked;
            cancellation_requested = other.cancellation_requested;
            invalid_switch_caught = other.invalid_switch_caught;
            completed = other.completed;
            stored_exception = other.stored_exception;
            counter = other.counter;
            waiting_tasks_ids = std::move(other.waiting_tasks_ids);
            tls_info = other.tls_info;
            timeout_timestamp = other.timeout_timestamp;
            call_stack = std::move(other.call_stack);
            counter_interrupt = other.counter_interrupt;
            counter_context_switch = other.counter_context_switch;
            priority = other.priority;
            awake_check = other.awake_check;
            pool_slot = other.pool_slot;
            created_by_id = other.created_by_id;
            created_by_is_native = other.created_by_is_native;
            current_available_quantum_ns = other.current_available_quantum_ns;
            interrupt_data = other.interrupt_data;
            on_start_override = other.on_start_override;
            vtable = other.vtable;
            init_call_stack = other.init_call_stack;
            other.init_call_stack = nullptr;
        }
        return *this;
    }

    raw_task_info::~raw_task_info() {
        delete init_call_stack;
        init_call_stack = nullptr;
    }

    raw_mutex_info::raw_mutex_info() = default;

    raw_mutex_info::raw_mutex_info(const raw_mutex_info& other)
        : mutex_id(other.mutex_id),
          owner_id(other.owner_id),
          owner_is_native(other.owner_is_native),
          waiting_tasks_ids(other.waiting_tasks_ids),
          init_call_stack(clone_stack_trace(other.init_call_stack)),
          created_by_id(other.created_by_id),
          created_by_is_native(other.created_by_is_native) {}

    raw_mutex_info::raw_mutex_info(raw_mutex_info&& other) noexcept
        : mutex_id(other.mutex_id),
          owner_id(other.owner_id),
          owner_is_native(other.owner_is_native),
          waiting_tasks_ids(std::move(other.waiting_tasks_ids)),
          init_call_stack(other.init_call_stack),
          created_by_id(other.created_by_id),
          created_by_is_native(other.created_by_is_native) {
        other.init_call_stack = nullptr;
    }

    raw_mutex_info& raw_mutex_info::operator=(const raw_mutex_info& other) {
        if (this != &other) {
            raw_mutex_info tmp(other);
            *this = std::move(tmp);
        }
        return *this;
    }

    raw_mutex_info& raw_mutex_info::operator=(raw_mutex_info&& other) noexcept {
        if (this != &other) {
            delete init_call_stack;
            mutex_id = other.mutex_id;
            owner_id = other.owner_id;
            owner_is_native = other.owner_is_native;
            waiting_tasks_ids = std::move(other.waiting_tasks_ids);
            init_call_stack = other.init_call_stack;
            created_by_id = other.created_by_id;
            created_by_is_native = other.created_by_is_native;
            other.init_call_stack = nullptr;
        }
        return *this;
    }

    raw_mutex_info::~raw_mutex_info() {
        delete init_call_stack;
        init_call_stack = nullptr;
    }

    raw_recursive_mutex_info::raw_recursive_mutex_info() = default;

    raw_recursive_mutex_info::raw_recursive_mutex_info(const raw_recursive_mutex_info& other)
        : mutex_id(other.mutex_id),
          internal_mutex_id(other.internal_mutex_id),
          recursion_count(other.recursion_count),
          init_call_stack(clone_stack_trace(other.init_call_stack)),
          created_by_id(other.created_by_id),
          created_by_is_native(other.created_by_is_native) {}

    raw_recursive_mutex_info::raw_recursive_mutex_info(raw_recursive_mutex_info&& other) noexcept
        : mutex_id(other.mutex_id),
          internal_mutex_id(other.internal_mutex_id),
          recursion_count(other.recursion_count),
          init_call_stack(other.init_call_stack),
          created_by_id(other.created_by_id),
          created_by_is_native(other.created_by_is_native) {
        other.init_call_stack = nullptr;
    }

    raw_recursive_mutex_info& raw_recursive_mutex_info::operator=(const raw_recursive_mutex_info& other) {
        if (this != &other) {
            raw_recursive_mutex_info tmp(other);
            *this = std::move(tmp);
        }
        return *this;
    }

    raw_recursive_mutex_info& raw_recursive_mutex_info::operator=(raw_recursive_mutex_info&& other) noexcept {
        if (this != &other) {
            delete init_call_stack;
            mutex_id = other.mutex_id;
            internal_mutex_id = other.internal_mutex_id;
            recursion_count = other.recursion_count;
            init_call_stack = other.init_call_stack;
            created_by_id = other.created_by_id;
            created_by_is_native = other.created_by_is_native;
            other.init_call_stack = nullptr;
        }
        return *this;
    }

    raw_recursive_mutex_info::~raw_recursive_mutex_info() {
        delete init_call_stack;
        init_call_stack = nullptr;
    }

    raw_rw_mutex_info::raw_rw_mutex_info() = default;

    raw_rw_mutex_info::raw_rw_mutex_info(const raw_rw_mutex_info& other)
        : mutex_id(other.mutex_id),
          writer_id(other.writer_id),
          writer_is_native(other.writer_is_native),
          reader_tasks_ids(other.reader_tasks_ids),
          wait_tasks_ids(other.wait_tasks_ids),
          wait_tasks_keys(other.wait_tasks_keys),
          init_call_stack(clone_stack_trace(other.init_call_stack)),
          created_by_id(other.created_by_id),
          created_by_is_native(other.created_by_is_native) {}

    raw_rw_mutex_info::raw_rw_mutex_info(raw_rw_mutex_info&& other) noexcept
        : mutex_id(other.mutex_id),
          writer_id(other.writer_id),
          writer_is_native(other.writer_is_native),
          reader_tasks_ids(std::move(other.reader_tasks_ids)),
          wait_tasks_ids(std::move(other.wait_tasks_ids)),
          wait_tasks_keys(std::move(other.wait_tasks_keys)),
          init_call_stack(other.init_call_stack),
          created_by_id(other.created_by_id),
          created_by_is_native(other.created_by_is_native) {
        other.init_call_stack = nullptr;
    }

    raw_rw_mutex_info& raw_rw_mutex_info::operator=(const raw_rw_mutex_info& other) {
        if (this != &other) {
            raw_rw_mutex_info tmp(other);
            *this = std::move(tmp);
        }
        return *this;
    }

    raw_rw_mutex_info& raw_rw_mutex_info::operator=(raw_rw_mutex_info&& other) noexcept {
        if (this != &other) {
            delete init_call_stack;
            mutex_id = other.mutex_id;
            writer_id = other.writer_id;
            writer_is_native = other.writer_is_native;
            reader_tasks_ids = std::move(other.reader_tasks_ids);
            wait_tasks_ids = std::move(other.wait_tasks_ids);
            wait_tasks_keys = std::move(other.wait_tasks_keys);
            init_call_stack = other.init_call_stack;
            created_by_id = other.created_by_id;
            created_by_is_native = other.created_by_is_native;
            other.init_call_stack = nullptr;
        }
        return *this;
    }

    raw_rw_mutex_info::~raw_rw_mutex_info() {
        delete init_call_stack;
        init_call_stack = nullptr;
    }

    raw_condition_info::raw_condition_info() = default;

    raw_condition_info::raw_condition_info(const raw_condition_info& other)
        : condition_id(other.condition_id),
          waiting_tasks_ids(other.waiting_tasks_ids),
          init_call_stack(clone_stack_trace(other.init_call_stack)),
          created_by_id(other.created_by_id),
          created_by_is_native(other.created_by_is_native) {}

    raw_condition_info::raw_condition_info(raw_condition_info&& other) noexcept
        : condition_id(other.condition_id),
          waiting_tasks_ids(std::move(other.waiting_tasks_ids)),
          init_call_stack(other.init_call_stack),
          created_by_id(other.created_by_id),
          created_by_is_native(other.created_by_is_native) {
        other.init_call_stack = nullptr;
    }

    raw_condition_info& raw_condition_info::operator=(const raw_condition_info& other) {
        if (this != &other) {
            raw_condition_info tmp(other);
            *this = std::move(tmp);
        }
        return *this;
    }

    raw_condition_info& raw_condition_info::operator=(raw_condition_info&& other) noexcept {
        if (this != &other) {
            delete init_call_stack;
            condition_id = other.condition_id;
            waiting_tasks_ids = std::move(other.waiting_tasks_ids);
            init_call_stack = other.init_call_stack;
            created_by_id = other.created_by_id;
            created_by_is_native = other.created_by_is_native;
            other.init_call_stack = nullptr;
        }
        return *this;
    }

    raw_condition_info::~raw_condition_info() {
        delete init_call_stack;
        init_call_stack = nullptr;
    }

    raw_semaphore_info::raw_semaphore_info() = default;

    raw_semaphore_info::raw_semaphore_info(const raw_semaphore_info& other)
        : semaphore_id(other.semaphore_id),
          waiting_tasks_ids(other.waiting_tasks_ids),
          allow_threshold(other.allow_threshold),
          max_threshold(other.max_threshold),
          init_call_stack(clone_stack_trace(other.init_call_stack)),
          created_by_id(other.created_by_id),
          created_by_is_native(other.created_by_is_native) {}

    raw_semaphore_info::raw_semaphore_info(raw_semaphore_info&& other) noexcept
        : semaphore_id(other.semaphore_id),
          waiting_tasks_ids(std::move(other.waiting_tasks_ids)),
          allow_threshold(other.allow_threshold),
          max_threshold(other.max_threshold),
          init_call_stack(other.init_call_stack),
          created_by_id(other.created_by_id),
          created_by_is_native(other.created_by_is_native) {
        other.init_call_stack = nullptr;
    }

    raw_semaphore_info& raw_semaphore_info::operator=(const raw_semaphore_info& other) {
        if (this != &other) {
            raw_semaphore_info tmp(other);
            *this = std::move(tmp);
        }
        return *this;
    }

    raw_semaphore_info& raw_semaphore_info::operator=(raw_semaphore_info&& other) noexcept {
        if (this != &other) {
            delete init_call_stack;
            semaphore_id = other.semaphore_id;
            waiting_tasks_ids = std::move(other.waiting_tasks_ids);
            allow_threshold = other.allow_threshold;
            max_threshold = other.max_threshold;
            init_call_stack = other.init_call_stack;
            created_by_id = other.created_by_id;
            created_by_is_native = other.created_by_is_native;
            other.init_call_stack = nullptr;
        }
        return *this;
    }

    raw_semaphore_info::~raw_semaphore_info() {
        delete init_call_stack;
        init_call_stack = nullptr;
    }

    raw_limiter_info::raw_limiter_info() = default;

    raw_limiter_info::raw_limiter_info(const raw_limiter_info& other)
        : limiter_id(other.limiter_id),
          waiting_tasks_ids(other.waiting_tasks_ids),
          allow_threshold(other.allow_threshold),
          max_threshold(other.max_threshold),
          locked(other.locked),
          init_call_stack(clone_stack_trace(other.init_call_stack)),
          created_by_id(other.created_by_id),
          created_by_is_native(other.created_by_is_native) {}

    raw_limiter_info::raw_limiter_info(raw_limiter_info&& other) noexcept
        : limiter_id(other.limiter_id),
          waiting_tasks_ids(std::move(other.waiting_tasks_ids)),
          allow_threshold(other.allow_threshold),
          max_threshold(other.max_threshold),
          locked(other.locked),
          init_call_stack(other.init_call_stack),
          created_by_id(other.created_by_id),
          created_by_is_native(other.created_by_is_native) {
        other.init_call_stack = nullptr;
    }

    raw_limiter_info& raw_limiter_info::operator=(const raw_limiter_info& other) {
        if (this != &other) {
            raw_limiter_info tmp(other);
            *this = std::move(tmp);
        }
        return *this;
    }

    raw_limiter_info& raw_limiter_info::operator=(raw_limiter_info&& other) noexcept {
        if (this != &other) {
            delete init_call_stack;
            limiter_id = other.limiter_id;
            waiting_tasks_ids = std::move(other.waiting_tasks_ids);
            allow_threshold = other.allow_threshold;
            max_threshold = other.max_threshold;
            locked = other.locked;
            init_call_stack = other.init_call_stack;
            created_by_id = other.created_by_id;
            created_by_is_native = other.created_by_is_native;
            other.init_call_stack = nullptr;
        }
        return *this;
    }

    raw_limiter_info::~raw_limiter_info() {
        delete init_call_stack;
        init_call_stack = nullptr;
    }

    raw_queue_info::raw_queue_info() = default;

    raw_queue_info::raw_queue_info(const raw_queue_info& other)
        : queue_id(other.queue_id),
          internal_condition_id(other.internal_condition_id),
          waiting_tasks_ids(other.waiting_tasks_ids),
          current_in_run(other.current_in_run),
          max_on_execution(other.max_on_execution),
          enabled(other.enabled),
          init_call_stack(clone_stack_trace(other.init_call_stack)),
          created_by_id(other.created_by_id),
          created_by_is_native(other.created_by_is_native) {}

    raw_queue_info::raw_queue_info(raw_queue_info&& other) noexcept
        : queue_id(other.queue_id),
          internal_condition_id(other.internal_condition_id),
          waiting_tasks_ids(std::move(other.waiting_tasks_ids)),
          current_in_run(other.current_in_run),
          max_on_execution(other.max_on_execution),
          enabled(other.enabled),
          init_call_stack(other.init_call_stack),
          created_by_id(other.created_by_id),
          created_by_is_native(other.created_by_is_native) {
        other.init_call_stack = nullptr;
    }

    raw_queue_info& raw_queue_info::operator=(const raw_queue_info& other) {
        if (this != &other) {
            raw_queue_info tmp(other);
            *this = std::move(tmp);
        }
        return *this;
    }

    raw_queue_info& raw_queue_info::operator=(raw_queue_info&& other) noexcept {
        if (this != &other) {
            delete init_call_stack;
            queue_id = other.queue_id;
            internal_condition_id = other.internal_condition_id;
            waiting_tasks_ids = std::move(other.waiting_tasks_ids);
            current_in_run = other.current_in_run;
            max_on_execution = other.max_on_execution;
            enabled = other.enabled;
            init_call_stack = other.init_call_stack;
            created_by_id = other.created_by_id;
            created_by_is_native = other.created_by_is_native;
            other.init_call_stack = nullptr;
        }
        return *this;
    }

    raw_queue_info::~raw_queue_info() {
        delete init_call_stack;
        init_call_stack = nullptr;
    }

    raw_deadline_timer_info::raw_deadline_timer_info() = default;

    raw_deadline_timer_info::raw_deadline_timer_info(const raw_deadline_timer_info& other)
        : timer_id(other.timer_id),
          internal_mutex_id(other.internal_mutex_id),
          timestamp(other.timestamp),
          canceled_tasks(other.canceled_tasks),
          scheduled_tasks(other.scheduled_tasks),
          shutdown(other.shutdown),
          init_call_stack(clone_stack_trace(other.init_call_stack)),
          created_by_id(other.created_by_id),
          created_by_is_native(other.created_by_is_native) {}

    raw_deadline_timer_info::raw_deadline_timer_info(raw_deadline_timer_info&& other) noexcept
        : timer_id(other.timer_id),
          internal_mutex_id(other.internal_mutex_id),
          timestamp(other.timestamp),
          canceled_tasks(std::move(other.canceled_tasks)),
          scheduled_tasks(std::move(other.scheduled_tasks)),
          shutdown(other.shutdown),
          init_call_stack(other.init_call_stack),
          created_by_id(other.created_by_id),
          created_by_is_native(other.created_by_is_native) {
        other.init_call_stack = nullptr;
    }

    raw_deadline_timer_info& raw_deadline_timer_info::operator=(const raw_deadline_timer_info& other) {
        if (this != &other) {
            raw_deadline_timer_info tmp(other);
            *this = std::move(tmp);
        }
        return *this;
    }

    raw_deadline_timer_info& raw_deadline_timer_info::operator=(raw_deadline_timer_info&& other) noexcept {
        if (this != &other) {
            delete init_call_stack;
            timer_id = other.timer_id;
            internal_mutex_id = other.internal_mutex_id;
            timestamp = other.timestamp;
            canceled_tasks = std::move(other.canceled_tasks);
            scheduled_tasks = std::move(other.scheduled_tasks);
            shutdown = other.shutdown;
            init_call_stack = other.init_call_stack;
            created_by_id = other.created_by_id;
            created_by_is_native = other.created_by_is_native;
            other.init_call_stack = nullptr;
        }
        return *this;
    }

    raw_deadline_timer_info::~raw_deadline_timer_info() {
        delete init_call_stack;
        init_call_stack = nullptr;
    }

    void FT_API dump_stack_(file::async_iofstream& ii, raw_stack_trace& trace, size_t t_count) {
        std::string space(t_count, '\t');
        ii << space << "Trace: " << std::endl;
        space += '\t';
        for (auto& it : trace.entries)
            ii << space << it.symbol() << ':' << it.line() << '.' << it.column() << (it.is_inline() ? " (inline)" : "") << std::endl;
    }

    void FT_API dump_await_(file::async_iofstream& ii, array<awake_item>& items, size_t t_count) {
        std::string space(t_count, '\t');
        ii << space << "Await items: " << std::endl;
        space += '\t';
        for (auto& it : items)
            if (it.native_awake)
                ii << space << "native thread" << std::endl;
            else
                ii << space << "id-" << it.id << ", awake_check-" << it.awake_check << std::endl;
    }

    void FT_API dump_rw_await_(file::async_iofstream& ii, array<awake_item>& items, array<uint8_t>& keys, size_t t_count) {
        std::string space(t_count, '\t');
        ii << space << "Await items: " << std::endl;
        space += '\t';
        auto key_it = keys.begin();
        auto key_end = keys.end();
        for (auto& it : items) {
            const char* role = (key_it != key_end && *key_it == 1) ? "reader" : "writer";
            if (key_it != key_end)
                ++key_it;
            if (it.native_awake)
                ii << space << role << " (native thread)" << std::endl;
            else
                ii << space << role << ", id-" << it.id << ", awake_check-" << it.awake_check << std::endl;
        }
    }

    void FT_API dump_task_ids_(file::async_iofstream& ii, array<uintptr_t>& items, size_t t_count) {
        std::string space(t_count + 1, '\t');
        for (auto& id : items)
            ii << space << id << std::endl;
    }

    void FT_API save_program_state_dump(const char* path) {
        auto dump = dump_program_state();
        file::async_iofstream ii(path, std::ios_base::trunc | std::ios_base::out);

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
            ii << "\t\tOwner: " << (it.owner_id != FT_DEBUG_OPTIONAL ? std::to_string(it.owner_id) : "none") << std::endl;
            if (it.owner_id != FT_DEBUG_OPTIONAL)
                ii << (it.owner_is_native ? " thread" : " task") << std::endl;
        }
        for (auto& it : dump.queries) {
            ii << "\tQueue " << it.queue_id << std::endl;
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
            dump_rw_await_(ii, it.wait_tasks_ids, it.wait_tasks_keys, 2);
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
        auto hi_current = fast_task::clock::now();
        for (auto& it : dump.tasks) {
            ii << "\tTask: " << it.task_id << std::endl;
            ii << "\t\tCreated by: " << it.created_by_id << (it.created_by_is_native ? " thread" : " task") << std::endl;
            if (it.init_call_stack)
                dump_stack_(ii, *it.init_call_stack, 2);

            ii << "\t\tCall stack" << std::endl;
            dump_stack_(ii, it.call_stack, 2);
            switch (it.status) {
            case raw_task_info::status_e::created:
                ii << "\t\tStatus: created" << std::endl;
                break;
            case raw_task_info::status_e::scheduled:
                ii << "\t\tStatus: scheduled" << std::endl;
                break;
            case raw_task_info::status_e::running:
                ii << "\t\tStatus: running" << std::endl;
                break;
            case raw_task_info::status_e::suspending:
                ii << "\t\tStatus: suspending" << std::endl;
                break;
            case raw_task_info::status_e::suspended:
                ii << "\t\tStatus: suspended" << std::endl;
                break;
            case raw_task_info::status_e::ended:
                ii << "\t\tStatus: ended" << std::endl;
                break;
            default:
                ii << "\t\tStatus: ???" << std::endl;
                break;
            }
            ii << "\t\tFLAGS:" << std::endl;
            ii << "\t\t\tRestartable: " << it.is_restartable << std::endl;
            ii << "\t\t\tUse scheduler stack: " << it.is_on_scheduler << std::endl;
            ii << "\t\t\tTime end Flag: " << it.time_end << std::endl;
            ii << "\t\t\tAwaked: " << it.awaked << std::endl;
            ii << "\t\t\tPool assigned: " << it.pool_assigned << std::endl;
            ii << "\t\t\tUsed SBO: " << it.is_sbo << std::endl;
            ii << "\t\t\tTask locked: " << it.spin_lock_locked << std::endl;
            ii << "\t\t\tCancel requested: " << it.cancellation_requested << std::endl;
            ii << "\t\t\tInvalid switch caught: " << it.invalid_switch_caught << std::endl;
            ii << "\t\t\tIs completed: " << it.completed << std::endl;
            ii << "\t\t\tException is stored: " << it.stored_exception << std::endl;
            dump_await_(ii, it.waiting_tasks_ids, 2);

            ii << "\t\tCounted: " << it.counter << std::endl;
            ii << "\t\tTLS: unsupported" << std::endl;
            ii << "\t\tUsage counter: " << it.counter << std::endl;

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
            ii << "\t\tPool slot: " << static_cast<unsigned>(it.pool_slot) << std::endl;
            ii << "\t\tPreempt available quantum ns: " << it.current_available_quantum_ns << std::endl;
            ii << "\t\tInterrupt data: " << it.interrupt_data << std::endl;
            ii << "\t\tStart overriden: " << (it.on_start_override ? "true" : "false") << std::endl;
            //TODO SHOW VTABLE

            // time_point::min() is "no deadline" and time_point::max() is
            // "deadline far in the future"; both would print nonsense through
            // hh_mm_ss, so they are skipped instead of being formatted.
            if (it.timeout_timestamp != fast_task::no_deadline.time_since_epoch().count() &&
                it.timeout_timestamp != fast_task::time_point::max().time_since_epoch().count())
                ii << "\t\tTimeouts in: " << std::chrono::hh_mm_ss{fast_task::time_point(fast_task::clock::duration(it.timeout_timestamp)) - hi_current} << '\n';
        }
    }

    void FT_API iterate_task_objects(void (*callback)(const task_object&, void* data), void* data) {
        if (!callback)
            return;
        scheduler::request_stw([callback, data]() {
            struct iterate_task_objects_data {
                void (*callback)(const task_object&, void* data);
                void* data;
            } d;
            d.callback = callback;
            d.data = data;

            glob.allocators.gba.iterate_all(
                [](fast_task::task_object* obj, void* d) {
                    auto dat = reinterpret_cast<iterate_task_objects_data*>(d);
                    if (!obj->is_released())
                        dat->callback(*obj, dat->data);
                },
                &d
            );
        });
    }
}
#if PLATFORM_LINUX
__attribute__((used, retain))
#endif
std::vector<fast_task::task_object*> FT_API collect_task_objects() {
    std::vector<fast_task::task_object*> collect;
    fast_task::glob.allocators.gba.iterate_all(
        [](fast_task::task_object* obj, void* d) {
            auto dat = reinterpret_cast<std::vector<fast_task::task_object*>*>(d);
            if (!obj->is_released() && !obj->is_ended())
                dat->push_back(obj);
        },
        &collect
    );
    return collect;
}
