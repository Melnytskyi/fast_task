// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)


#ifndef _WIN64
    #include <dirent.h>
    #include <errno.h>
    #include <ext/stdio_filebuf.h>
    #include <fcntl.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <sys/inotify.h>
    #include <sys/stat.h>
    #include <sys/types.h>
    #include <unistd.h>


    #include <filesystem>

    #include <file.hpp>
    #include <task.hpp>
    #include <task/future.hpp>
    #include <tasks/util/native_workers_singleton.hpp>
    #include <variant>
    #include <vector>

namespace fast_task::files {
    class File_;

    struct completion_struct {
        File_* handle = nullptr;
        uint32_t completed_bytes = 0;
        char* data = nullptr;
        io_errors error = io_errors::no_error;
    };

    void io_error_to_exception(io_errors error) {
        switch (error) {
        case io_errors::eof:
            throw std::runtime_error("FileException EOF");
        case io_errors::no_enough_memory:
            throw std::runtime_error("FileException No enough memory");
        case io_errors::invalid_user_buffer:
            throw std::runtime_error("FileException Invalid user buffer");
        case io_errors::no_enough_quota:
            throw std::runtime_error("FileException No enough quota");
        case io_errors::operation_canceled:
            throw std::runtime_error("FileException Operation canceled");
        case io_errors::unknown_error:
        default:
            throw std::runtime_error("FileException Unknown error");
        }
    }

    class File_ : public util::native_worker_handle {
        task_condition_variable awaiters;
        task_mutex mutex;
        int handle;
        char* buffer = nullptr;
        bool fullifed = false;

        File_(util::native_worker_manager* manager, int handle, const char* buffer, uint32_t buffer_size, uint64_t offset)
            : util::native_worker_handle(manager), handle(handle), buffer_size(buffer_size), offset(offset), is_read(false), required_full(true), buffer_alloc(false) {
            this->buffer = new char[buffer_size];
            memcpy(this->buffer, buffer, buffer_size);
        }

        File_(util::native_worker_manager* manager, int handle, uint32_t buffer_size, uint64_t offset, bool required_full = true)
            : util::native_worker_handle(manager), handle(handle), buffer_size(buffer_size), offset(offset), is_read(true), required_full(required_full), buffer_alloc(false) {
            this->buffer = new char[buffer_size];
        }

        File_(bool buffer_alloc, util::native_worker_manager* manager, int handle, char* buffer, uint32_t buffer_size, uint64_t offset)
            : util::native_worker_handle(manager), handle(handle), buffer_size(buffer_size), offset(offset), is_read(false), required_full(true), buffer_alloc(buffer_alloc) {
            if (buffer_alloc) {
                this->buffer = new char[buffer_size];
                memcpy(this->buffer, buffer, buffer_size);
            } else
                this->buffer = buffer;
        }

        File_(util::native_worker_manager* manager, int handle, char* buffer, uint32_t buffer_size, uint64_t offset, bool required_full)
            : util::native_worker_handle(manager), handle(handle), buffer_size(buffer_size), offset(offset), is_read(true), required_full(required_full), buffer_alloc(false) {
            this->buffer = buffer;
        }

    public:
        std::shared_ptr<task> awaiter;
        uint32_t fullifed_bytes = 0;
        const uint32_t buffer_size;
        const uint64_t offset;
        const bool is_read;
        const bool required_full;
        const bool buffer_alloc;

        static File_* command_write(util::native_worker_manager* manager, int handle, char* buffer, uint32_t buffer_size, uint64_t offset) {
            return new File_(true, manager, handle, buffer, buffer_size, offset);
        }

        static File_* command_write_inline(util::native_worker_manager* manager, int handle, char* buffer, uint32_t buffer_size, uint64_t offset) {
            return new File_(false, manager, handle, buffer, buffer_size, offset);
        }

        static File_* command_read(util::native_worker_manager* manager, int handle, uint32_t buffer_size, uint64_t offset, bool required_full = true) {
            return new File_(manager, handle, buffer_size, offset, required_full);
        }

        static File_* command_read_inline(util::native_worker_manager* manager, int handle, char* buffer, uint32_t buffer_size, uint64_t offset, bool required_full = true) {
            return new File_(manager, handle, buffer, buffer_size, offset, required_full);
        }

        ~File_() {
            if (buffer && buffer_alloc)
                delete[] buffer;
        }

        void cancel() {
            if (buffer && awaiter ? !get_data(awaiter).end_of_life : true) {
                if (util::native_workers_singleton::await_cancel_fd_all(handle)) {
                    mutex_unify unify(mutex);
                    fast_task::unique_lock<mutex_unify> lock(unify);
                    fullifed = true;
                    if (awaiter) {
                        if (is_read && !required_full)
                            awaiter->end_dummy([&](auto) {});
                        else
                            awaiter->end_dummy([&](auto data) { ((completion_struct*)data)->error = io_errors::operation_canceled; });
                    }
                    awaiters.notify_all();
                }
            }
        }

        void await() {
            mutex_unify unify(mutex);
            fast_task::unique_lock<mutex_unify> lock(unify);
            while (!fullifed)
                awaiters.wait(lock);
        }

        void now_fullifed() {
            mutex_unify unify(mutex);
            fast_task::unique_lock<mutex_unify> lock(unify);
            fullifed = true;
            if (awaiter) {
                if (is_read)
                    awaiter->end_dummy([&](auto data) { auto tt = (completion_struct*)data; tt->completed_bytes = fullifed_bytes; tt->data = buffer; });
                else
                    awaiter->end_dummy([&](auto data) { auto tt = (completion_struct*)data; tt->completed_bytes = fullifed_bytes; });
            }
            awaiters.notify_all();
            awaiter = nullptr;
        }

        void exception(io_errors e) {
            mutex_unify unify(mutex);
            fast_task::unique_lock<mutex_unify> lock(unify);
            fullifed = true;
            if (awaiter) {
                if (fullifed_bytes) {
                    if (is_read)
                        awaiter->end_dummy([&](auto data) { auto tt = (completion_struct*)data; tt->completed_bytes = fullifed_bytes; tt->data = buffer; tt->error = e; });
                    else
                        awaiter->end_dummy([&](auto data) { auto tt = (completion_struct*)data; tt->completed_bytes = fullifed_bytes; tt->error = e; });
                } else
                    awaiter->end_dummy([&](auto data) { auto tt = (completion_struct*)data; tt->error = e; });
            }
            awaiters.notify_all();
            awaiter = nullptr;
        }

        void readed(uint32_t len) {
            if (is_read) {
                fullifed_bytes += len;
                if (buffer_size > fullifed_bytes) {
                    uint64_t new_offset = offset + fullifed_bytes;
                    util::native_workers_singleton::post_read(this, handle, buffer + fullifed_bytes, buffer_size - fullifed_bytes, new_offset);
                } else
                    now_fullifed();
            }
        }

        void written(uint32_t len) {
            if (!is_read) {
                fullifed_bytes += len;
                if (buffer_size > fullifed_bytes) {
                    uint64_t new_offset = offset + fullifed_bytes;
                    util::native_workers_singleton::post_write(this, handle, buffer + fullifed_bytes, buffer_size - fullifed_bytes, new_offset);
                }
            } else
                now_fullifed();
        }

        void operation_fullifed(uint32_t len) {
            if (buffer_size <= fullifed_bytes + len) {
                fullifed_bytes += len;
                now_fullifed();
                return;
            }
            if (is_read)
                readed(len);
            else
                written(len);
        }

        void ststd() {
            if (is_read)
                util::native_workers_singleton::post_read(this, handle, buffer, buffer_size, offset);
            else
                util::native_workers_singleton::post_write(this, handle, buffer, buffer_size, offset);
        }

        bool error_filter(int error) {
            switch (error) {
            case 0: { //EOF
                if (is_read && !required_full) {
                    now_fullifed();
                    return false;
                } else {
                    exception(io_errors::eof);
                    return true;
                }
            }
            case ENOMEM:
                exception(io_errors::no_enough_memory);
                return true;
            case ENOBUFS:
                exception(io_errors::invalid_user_buffer);
                return true;
            case EDQUOT:
                exception(io_errors::no_enough_quota);
                return true;
            case ECANCELED:
            case EINTR:
                return false;
            case ESPIPE:
                exception(io_errors::eof);
                return true;
            default:
                exception(io_errors::unknown_error);
                return true;
            }
        }
    };

    void file_overlapped_on_await(void* it) {
        ((completion_struct*)it)->handle->await();
    }

    void file_overlapped_on_cancel(void* it) {
        ((completion_struct*)it)->handle->cancel();
    }

    void file_overlapped_on_destruct(void* it) {
        if (((completion_struct*)it)->handle->awaiter)
            ((completion_struct*)it)->handle->cancel();
        delete ((completion_struct*)it)->handle;
        delete ((completion_struct*)it);
    }

    std::pair<completion_struct*, std::shared_ptr<task>> create_dummy_handle(File_* file) {
        auto res = new completion_struct(file);
        return {res, task::callback_dummy(res, file_overlapped_on_await, file_overlapped_on_cancel, file_overlapped_on_destruct)};
    }

    namespace user_flags {
        enum _ : uint16_t {
            FILE_FLAG_DELETE_ON_CLOSE = 1,
            FILE_FLAG_NO_BUFFERING = 2
        };
    } // namespace name

    class file_manager : public util::native_worker_manager {
        int _handle = -1;
        uint64_t write_pointer = 0;
        uint64_t read_pointer = 0;
        pointer_mode _pointer_mode;
        friend class File_;


        uint16_t uflags = 0;

        int64_t _file_size() {
            int64_t size = 0;
            struct stat st;
            if (fstat(_handle, &st) == 0)
                size = st.st_size;
            return size;
        }

    public:
        std::optional<task_mutex> mimic_non_async;

        static std::variant<file_manager*, std::string> open(const std::filesystem::path& path, open_mode open, on_open_action action, [[maybe_unused]] share_mode share, file_flags flags, pointer_mode _pointer_mode) {
            std::unique_ptr<file_manager> ptr;
            ptr.reset(new file_manager{});
            ptr->_pointer_mode = _pointer_mode;
            int mode = O_NONBLOCK;

            //if(share.read)
            //    wshare_mode |= FILE_SHARE_READ;
            //if(share.write)
            //    wshare_mode |= FILE_SHARE_WRITE;
            //if(share._delete)
            //    wshare_mode |= FILE_SHARE_DELETE;

            //int wflags = 0;
            if (flags.delete_on_close)
                ptr->uflags |= user_flags::FILE_FLAG_DELETE_ON_CLOSE;
            if (flags.no_buffering)
                mode |= O_DIRECT;
            //if(flags.posix_semantics)
            //    wflags |= FILE_FLAG_POSIX_SEMANTICS;
            //if(flags.random_access)
            //    wflags |= FILE_FLAG_RANDOM_ACCESS;
            //if(flags.sequential_scan)
            //    wflags |= FILE_FLAG_SEQUENTIAL_SCAN;
            //if(flags.write_through)
            //    wflags |= FILE_FLAG_WRITE_THROUGH;


            switch (open) {
            case open_mode::read:
                mode |= O_RDONLY;
                break;
            case open_mode::write:
                mode |= O_WRONLY;
                break;
            case open_mode::append:
                mode |= O_WRONLY;
                mode |= O_APPEND;
                break;
            case open_mode::read_write:
                mode |= O_RDWR;
                break;
            default:
                return "Invalid open mode, excepted read, write, read_write or append, but got " + std::to_string((int)open);
            }
            switch (action) {
            case on_open_action::open:
                mode |= O_CREAT;
                break;
            case on_open_action::always_new:
                mode |= O_CREAT;
                mode |= O_TRUNC;
                break;
            case on_open_action::create_new:
                mode |= O_CREAT | O_EXCL;
                break;
            case on_open_action::open_exists:
                if (!std::filesystem::exists(path))
                    return "FileException, File not found";
                break;
            case on_open_action::truncate_exists:
                if (!std::filesystem::exists(path))
                    return "FileException, File not found";
                mode |= O_TRUNC;
                break;
            default:
                return "Invalid open action, excepted open, always_new, create_new, open_exists or truncate_exists, but got " + std::to_string((int)open);
            }
            ptr->_handle = open64(path.c_str(), mode, 0644);
            if (ptr->_handle == -1) {
                switch (errno) {
                case ENOENT:
                    return "FileException, File not found";
                case EACCES:
                case EPERM:
                    return "FileException, Access denied";
                case EEXIST:
                    return "FileException, File exists";
                case EISDIR:
                    return "FileException, File invalid";
                case EFBIG:
                    return "FileException, File too large";
                case E2BIG:
                case EINVAL:
                    return "FileException, Invalid parameter";
                //case ERROR_SHARING_VIOLATION:
                //    throw std::runtime_error("FileException, Sharing violation");
                default:
                    return "FileException, Unknown error";
                }
            }
            if (flags.at_end)
                ptr->seek_pos(0, pointer_offset::end);
            return ptr.release();
        }

        ~file_manager() {
            if (_handle != -1)
                close(_handle);
        }

        future_ptr<std::vector<uint8_t>> fut_read(uint32_t size, bool require_all) {
            File_* file = File_::command_read(this, _handle, size, read_pointer, require_all);
            switch (_pointer_mode) {
            case pointer_mode::separated:
                read_pointer += size;
                break;
            case pointer_mode::combined:
                write_pointer = read_pointer = read_pointer + size;
                break;
            }
            auto [data, task_] = create_dummy_handle(file);
            try {
                file->awaiter = task_;
                file->ststd();
            } catch (...) {
                file->awaiter = nullptr;
                throw;
            }
            return future<std::vector<uint8_t>>::start([file, data, task_]() -> std::vector<uint8_t> {
                task::await_task(task_);
                file->awaiter = nullptr;
                if (data->error != io_errors::no_error && data->error != io_errors::eof) {
                    io_error_to_exception(data->error);
                    throw std::runtime_error("Unreachable");
                } else
                    return std::vector<uint8_t>((uint8_t*)data->data, (uint8_t*)data->data + data->completed_bytes);
            });
        }

        future_ptr<std::vector<uint8_t>> fut_read_at(uint64_t offset, uint32_t size, bool require_all) {
            File_* file = File_::command_read(this, _handle, size, offset, require_all);
            auto [data, task_] = create_dummy_handle(file);
            try {
                file->awaiter = task_;
                file->ststd();
            } catch (...) {
                file->awaiter = nullptr;
                throw;
            }
            return future<std::vector<uint8_t>>::start([file, data, task_]() -> std::vector<uint8_t> {
                task::await_task(task_);
                file->awaiter = nullptr;
                if (data->error != io_errors::no_error && data->error != io_errors::eof) {
                    io_error_to_exception(data->error);
                    throw std::runtime_error("Unreachable");
                } else
                    return std::vector<uint8_t>((uint8_t*)data->data, (uint8_t*)data->data + data->completed_bytes);
            });
        }

        std::shared_ptr<task> fmake_read(uint32_t size, bool require_all) {
            File_* file = File_::command_read(this, _handle, size, read_pointer, require_all);
            switch (_pointer_mode) {
            case pointer_mode::separated:
                read_pointer += size;
                break;
            case pointer_mode::combined:
                write_pointer = read_pointer = read_pointer + size;
                break;
            }
            auto [data, task_] = create_dummy_handle(file);
            try {
                file->awaiter = task_;
                file->ststd();
            } catch (...) {
                file->awaiter = nullptr;
                throw;
            }
            return task_;
        }

        std::shared_ptr<task> fmake_read_at(uint64_t offset, uint32_t size, bool require_all) {
            File_* file = File_::command_read(this, _handle, size, offset, require_all);
            auto [data, task_] = create_dummy_handle(file);
            try {
                file->awaiter = task_;
                file->ststd();
            } catch (...) {
                file->awaiter = nullptr;
                throw;
            }
            return task_;
        }

        uint32_t read(uint8_t* data_, uint32_t size, bool require_all) {
            File_* file = File_::command_read_inline(this, _handle, (char*)data_, size, read_pointer, require_all);
            switch (_pointer_mode) {
            case pointer_mode::separated:
                read_pointer += size;
                break;
            case pointer_mode::combined:
                write_pointer = read_pointer = read_pointer + size;
                break;
            }
            auto [data, task_] = create_dummy_handle(file);
            try {
                file->awaiter = task_;
                file->ststd();
            } catch (...) {
                file->awaiter = nullptr;
                throw;
            }
            task::await_task(task_);
            file->awaiter = nullptr;
            if (data->error != io_errors::no_error && data->error != io_errors::eof) {
                io_error_to_exception(data->error);
                throw std::runtime_error("Unreachable");
            } else
                return data->completed_bytes;
        }

        uint32_t read_at(uint64_t offset, uint8_t* data_, uint32_t size, bool require_all) {
            File_* file = File_::command_read_inline(this, _handle, (char*)data_, size, offset, require_all);
            auto [data, task_] = create_dummy_handle(file);
            try {
                file->awaiter = task_;
                file->ststd();
            } catch (...) {
                file->awaiter = nullptr;
                throw;
            }
            task::await_task(task_);
            file->awaiter = nullptr;
            if (data->error != io_errors::no_error && data->error != io_errors::eof) {
                io_error_to_exception(data->error);
                throw std::runtime_error("Unreachable");
            } else
                return data->completed_bytes;
        }

        future_ptr<void> fut_write(const uint8_t* data_, uint32_t size) {
            File_* file = File_::command_write(this, _handle, (char*)data_, size, write_pointer);
            switch (_pointer_mode) {
            case pointer_mode::separated:
                write_pointer += size;
                break;
            case pointer_mode::combined:
                write_pointer = read_pointer = write_pointer + size;
                break;
            }
            auto [data, task_] = create_dummy_handle(file);
            try {
                file->awaiter = task_;
                file->ststd();
            } catch (...) {
                file->awaiter = nullptr;
                throw;
            }
            return future<void>::start([file, data, task_]() {
                task::await_task(task_);
                file->awaiter = nullptr;
                if (data->error != io_errors::no_error) {
                    io_error_to_exception(data->error);
                    throw std::runtime_error("Unreachable");
                }
            });
        }

        future_ptr<void> fut_write_at(uint64_t offset, const uint8_t* data_, uint32_t size) {
            File_* file = File_::command_write(this, _handle, (char*)data_, size, offset);
            auto [data, task_] = create_dummy_handle(file);
            try {
                file->awaiter = task_;
                file->ststd();
            } catch (...) {
                file->awaiter = nullptr;
                throw;
            }
            return future<void>::start([file, data, task_]() {
                task::await_task(task_);
                file->awaiter = nullptr;
                if (data->error != io_errors::no_error) {
                    io_error_to_exception(data->error);
                    throw std::runtime_error("Unreachable");
                }
            });
        }

        std::shared_ptr<task> fmake_write(const uint8_t* data_, uint32_t size) {
            File_* file = File_::command_write(this, _handle, (char*)data_, size, write_pointer);
            switch (_pointer_mode) {
            case pointer_mode::separated:
                write_pointer += size;
                break;
            case pointer_mode::combined:
                write_pointer = read_pointer = write_pointer + size;
                break;
            }
            auto [data, task_] = create_dummy_handle(file);
            try {
                file->awaiter = task_;
                file->ststd();
            } catch (...) {
                file->awaiter = nullptr;
                throw;
            }
            return task_;
        }

        std::shared_ptr<task> fmake_write_at(uint64_t offset, const uint8_t* data_, uint32_t size) {
            File_* file = File_::command_write(this, _handle, (char*)data_, size, offset);
            auto [data, task_] = create_dummy_handle(file);
            try {
                file->awaiter = task_;
                file->ststd();
            } catch (...) {
                file->awaiter = nullptr;
                throw;
            }
            return task_;
        }

        void write_inline(const uint8_t* data_, uint32_t size) {
            File_* file = File_::command_write_inline(this, _handle, (char*)data_, size, write_pointer);
            switch (_pointer_mode) {
            case pointer_mode::separated:
                write_pointer += size;
                break;
            case pointer_mode::combined:
                write_pointer = read_pointer = write_pointer + size;
                break;
            }
            auto [data, task_] = create_dummy_handle(file);
            try {
                file->awaiter = task_;
                file->ststd();
            } catch (...) {
                file->awaiter = nullptr;
                throw;
            }
            task::await_task(task_);
            file->awaiter = nullptr;
            if (data->error != io_errors::no_error) {
                io_error_to_exception(data->error);
                throw std::runtime_error("Unreachable");
            }
        }

        void write_inline_at(uint64_t offset, const uint8_t* data_, uint32_t size) {
            File_* file = File_::command_write_inline(this, _handle, (char*)data_, size, offset);
            auto [data, task_] = create_dummy_handle(file);
            try {
                file->awaiter = task_;
                file->ststd();
            } catch (...) {
                file->awaiter = nullptr;
                throw;
            }
            task::await_task(task_);
            file->awaiter = nullptr;
            if (data->error != io_errors::no_error) {
                io_error_to_exception(data->error);
                throw std::runtime_error("Unreachable");
            }
        }

        future_ptr<void> fut_append(const uint8_t* data_, uint32_t size) {
            File_* file = File_::command_write(this, _handle, (char*)data_, size, (uint64_t)-1);
            auto [data, task_] = create_dummy_handle(file);
            try {
                file->awaiter = task_;
                file->ststd();
            } catch (...) {
                file->awaiter = nullptr;
                throw;
            }
            return future<void>::start([file, data, task_]() {
                task::await_task(task_);
                file->awaiter = nullptr;
                if (data->error != io_errors::no_error) {
                    io_error_to_exception(data->error);
                    throw std::runtime_error("Unreachable");
                }
            });
        }

        std::shared_ptr<task> fmake_append(const uint8_t* data_, uint32_t size) {
            File_* file = File_::command_write(this, _handle, (char*)data_, size, (uint64_t)-1);
            auto [data, task_] = create_dummy_handle(file);
            try {
                file->awaiter = task_;
                file->ststd();
            } catch (...) {
                file->awaiter = nullptr;
                throw;
            }
            return task_;
        }

        void append_inline(const uint8_t* data_, uint32_t size) {
            File_* file = File_::command_write_inline(this, _handle, (char*)data_, size, (uint64_t)-1);
            auto [data, task_] = create_dummy_handle(file);
            try {
                file->awaiter = task_;
                file->ststd();
            } catch (...) {
                file->awaiter = nullptr;
                throw;
            }
            task::await_task(task_);
            file->awaiter = nullptr;
            if (data->error != io_errors::no_error) {
                io_error_to_exception(data->error);
                throw std::runtime_error("Unreachable");
            }
        }

        bool seek_pos(int64_t offset, pointer_offset pointer_offset, pointer pointer) {
            switch (pointer_offset) {
            case pointer_offset::begin:
                switch (_pointer_mode) {
                case pointer_mode::separated:
                    switch (pointer) {
                    case pointer::read:
                        read_pointer = static_cast<uint64_t>(offset);
                        break;
                    case pointer::write:
                        write_pointer = static_cast<uint64_t>(offset);
                        break;
                    }
                    break;
                case pointer_mode::combined:
                    read_pointer = write_pointer = static_cast<uint64_t>(offset);
                    break;
                }
                break;
            case pointer_offset::current:
                switch (_pointer_mode) {
                case pointer_mode::separated:
                    switch (pointer) {
                    case pointer::read:
                        read_pointer += offset;
                        break;
                    case pointer::write:
                        write_pointer += offset;
                        break;
                    }
                    break;
                case pointer_mode::combined:
                    read_pointer = write_pointer += offset;
                    break;
                }
                break;
            case pointer_offset::end: {
                auto size = _file_size();
                if (size != -1) {
                    switch (_pointer_mode) {
                    case pointer_mode::separated:
                        switch (pointer) {
                        case pointer::read:
                            read_pointer = static_cast<uint64_t>(size + offset);
                            break;
                        case pointer::write:
                            write_pointer = static_cast<uint64_t>(size + offset);
                            break;
                        }
                        break;
                    case pointer_mode::combined:
                        read_pointer = write_pointer = static_cast<uint64_t>(size + offset);
                        break;
                    }
                } else
                    return false;
                break;
            }
            default:
                break;
            }
            return true;
        }

        bool seek_pos(int64_t offset, pointer_offset pointer_offset) {
            switch (pointer_offset) {
            case pointer_offset::begin:
                read_pointer = write_pointer = static_cast<uint64_t>(offset);
                break;
            case pointer_offset::current:
                read_pointer = write_pointer += offset;
                break;
            case pointer_offset::end: {
                auto size = _file_size();
                if (size != -1)
                    read_pointer = write_pointer = static_cast<uint64_t>(size + offset);
                else
                    return false;
                break;
            }
            default:
                break;
            }
            return true;
        }

        int64_t tell_pos(pointer pointer) {
            switch (pointer) {
            case pointer::read:
                return static_cast<int64_t>(read_pointer);
            case pointer::write:
                return static_cast<int64_t>(write_pointer);
            default:
                return 0;
            }
        }

        bool flush() {
            return (bool)fsync(_handle) == 0; //TODO replace with post_fsync
        }

        int64_t file_size() {
            auto res = _file_size();
            if (res == -1)
                return 0;
            else
                return res;
        }

        void handle(class util::native_worker_handle* overlapped, int32_t res, uint32_t flags) override {
            auto file = (File_*)overlapped;
            if (res <= 0)
                file->error_filter(-res);
            else
                file->operation_fullifed(res);
        }

        std::string get_path() const {
            struct stat st;
            if (fstat(_handle, &st) == 0) {
                if (st.st_nlink == 0)
                    return "";
            }
            char path[PATH_MAX];
            ssize_t len = readlink(("/proc/self/fd/" + std::to_string(_handle)).c_str(), path, PATH_MAX);
            if (len == -1)
                return "";
            else
                return std::string(path, len);
        }

        int get_handle() const {
            return _handle;
        }
    };

    int file_handle::internal_get_handle() const noexcept {
        return handle->get_handle();
    }
}

namespace fast_task::file {
    bool io_operation<std::vector<uint8_t>>::is_done() const noexcept {
        return slot_ && slot_->is_ended();
    }

    std::optional<io_errors> io_operation<std::vector<uint8_t>>::get_error() {
        if (!slot_ || !slot_->is_ended())
            return std::nullopt;
        std::optional<io_errors> res;
        slot_->access_dummy([&](void* e_data) {
            auto data = (completion_struct*)e_data;
            if (data->error != io_errors::no_error)
                res = data->error;
        });
        return res;
    }

    std::optional<std::vector<uint8_t>> io_operation<std::vector<uint8_t>>::try_get() {
        if (!slot_ || !slot_->is_ended())
            return std::nullopt;
        std::optional<std::vector<uint8_t>> res;
        slot_->access_dummy([&](void* e_data) {
            auto data = (completion_struct*)e_data;

            if (data->error == io_errors::no_error || data->error == io_errors::eof)
                res = {data->data, data->data + data->completed_bytes};
        });
        return res;
    }

    std::vector<uint8_t> io_operation<std::vector<uint8_t>>::get() {
        if (!slot_ || !slot_->is_ended())
            throw std::runtime_error("The operations is not complete");
        std::optional<std::vector<uint8_t>> res;
        slot_->access_dummy([&](void* e_data) {
            auto data = (completion_struct*)e_data;

            if (data->error == io_errors::no_error || data->error == io_errors::eof)
                res = {data->data, data->data + data->completed_bytes};
            else
                io_error_to_exception(data->error);
        });
        return res.value_or(std::vector<uint8_t>{});
    }

    bool io_operation<std::vector<uint8_t>>::enter_wait(const std::shared_ptr<task>& t) {
        if (slot_)
            return slot_->enter_wait(t);
        else
            return true;
    }

    bool io_operation<std::vector<uint8_t>>::enter_wait_until(const std::shared_ptr<task>& t, std::chrono::high_resolution_clock::time_point tp) {
        if (slot_)
            return slot_->enter_wait_until(t, tp);
        else
            return true;
    }

    bool io_operation<void>::is_done() const noexcept {
        return !slot_ || slot_->is_ended();
    }

    std::optional<io_errors> io_operation<void>::get_error() {
        if (!slot_)
            return io_errors::unknown_error;
        if (!slot_->is_ended())
            return std::nullopt;
        std::optional<io_errors> res;
        slot_->access_dummy([&](void* e_data) {
            auto data = (completion_struct*)e_data;
            if (data->error != io_errors::no_error)
                res = data->error;
        });
        return res;
    }

    bool io_operation<void>::try_get() {
        return slot_ && slot_->is_ended();
    }

    void io_operation<void>::get() {
        if (!slot_ || !slot_->is_ended())
            throw std::runtime_error("The operations is not complete");
        slot_->access_dummy([&](void* e_data) {
            auto data = (completion_struct*)e_data;

            if (data->error != io_errors::no_error && data->error != io_errors::eof)
                io_error_to_exception(data->error);
        });
    }

    bool io_operation<void>::enter_wait(const std::shared_ptr<task>& t) {
        return slot_->enter_wait(t);
    }

    bool io_operation<void>::enter_wait_until(const std::shared_ptr<task>& t, std::chrono::high_resolution_clock::time_point tp) {
        return slot_->enter_wait_until(t, tp);
    }

    bool io_operation<void>::enter_cancel(const std::shared_ptr<task>& t) {
        return slot_->enter_cancel(t);
    }

    file_handle file_handle::open(const std::filesystem::path& path, open_mode open, on_open_action action, file_flags flags, share_mode share, pointer_mode pointer_mode) {
        file_handle res;
        res.handle = nullptr;
        if (flags.use_lock) {
            flags.no_buffering = true;
            flags.write_through = true;
        }
        std::visit(
            [&res, &flags]<class T>(T&& value) {
                if constexpr (std::is_same_v<file_manager*, T>) {
                    res.handle = value;
                    if (flags.use_lock)
                        res.handle->mimic_non_async.emplace();
                }
            },
            file_manager::open(path, open, action, share, flags, pointer_mode)
        );
        return res;
    }

    file_handle file_handle::open_throws(const std::filesystem::path& path, open_mode open, on_open_action action, file_flags flags, share_mode share, pointer_mode pointer_mode) {
        file_handle res;
        res.handle = nullptr;
        if (flags.use_lock) {
            flags.no_buffering = true;
            flags.write_through = true;
        }
        std::visit(
            [&res, &flags]<class T>(T&& value) {
                if constexpr (std::is_same_v<file_manager*, T>) {
                    res.handle = value;
                    if (flags.use_lock)
                        res.handle->mimic_non_async.emplace();
                } else
                    throw std::runtime_error(std::move(value));
            },
            file_manager::open(path, open, action, share, flags, pointer_mode)
        );
        return res;
    }

    file_handle::file_handle() {
        handle = nullptr;
    }

    file_handle::file_handle(file_handle&& other) {
        handle = other.handle;
        other.handle = nullptr;
    }

    file_handle& file_handle::operator=(file_handle&& other) {
        if (this == &other)
            return *this;
        if (handle)
            delete handle;
        handle = other.handle;
        other.handle = nullptr;
        return *this;
    }

    file_handle::~file_handle() {
        if (handle)
            delete handle;
    }

    bool file_handle::is_open() const {
        return handle;
    }

    void file_handle::close() {
        if (handle)
            delete handle;
        handle = nullptr;
    }

    uint32_t file_handle::read(uint8_t* data, uint32_t size) {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*handle->mimic_non_async);
            return handle->read(data, size, false);
        } else
            return handle->read(data, size, false);
    }

    uint32_t file_handle::read_at(uint64_t offset, uint8_t* data, uint32_t size) {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*handle->mimic_non_async);
            return handle->read_at(offset, data, size, false);
        } else
            return handle->read_at(offset, data, size, false);
    }

    uint32_t file_handle::read_fixed(uint8_t* data, uint32_t size) {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*handle->mimic_non_async);
            return handle->read(data, size, true);
        } else
            return handle->read(data, size, true);
    }

    uint32_t file_handle::read_fixed_at(uint64_t offset, uint8_t* data, uint32_t size) {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*handle->mimic_non_async);
            return handle->read_at(offset, data, size, true);
        } else
            return handle->read_at(offset, data, size, true);
    }

    void file_handle::write(const uint8_t* data, uint32_t size) {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*handle->mimic_non_async);
            handle->write_inline(data, size);
        } else
            handle->write_inline(data, size);
    }

    void file_handle::write_at(uint64_t offset, const uint8_t* data, uint32_t size) {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*handle->mimic_non_async);
            handle->write_inline_at(offset, data, size);
        } else
            handle->write_inline_at(offset, data, size);
    }

    void file_handle::append(const uint8_t* data, uint32_t size) {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*handle->mimic_non_async);
            handle->append_inline(data, size);
        } else
            handle->append_inline(data, size);
    }

    bool file_handle::seek_pos(int64_t offset, pointer_offset pointer_offset, pointer pointer) {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*handle->mimic_non_async);
            return handle->seek_pos(offset, pointer_offset, pointer);
        } else
            return handle->seek_pos(offset, pointer_offset, pointer);
    }

    bool file_handle::seek_pos(int64_t offset, pointer_offset pointer_offset) {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*handle->mimic_non_async);
            return handle->seek_pos(offset, pointer_offset);
        } else
            return handle->seek_pos(offset, pointer_offset);
    }

    int64_t file_handle::tell_pos(pointer pointer) {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*handle->mimic_non_async);
            return handle->tell_pos(pointer);
        } else
            return handle->tell_pos(pointer);
    }

    bool file_handle::flush() {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*handle->mimic_non_async);
            return handle->flush();
        } else
            return handle->flush();
    }

    int64_t file_handle::size() {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*handle->mimic_non_async);
            return handle->file_size();
        } else
            return handle->file_size();
    }

    std::string file_handle::get_path() const {
        if (!handle)
            throw file_closed();
        return handle->get_path();
    }

    future_ptr<std::vector<uint8_t>> file_handle::fut_read(uint32_t size) {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*handle->mimic_non_async);
            auto res = handle->fut_read(size, false);
            res->wait();
            return res;
        } else
            return handle->fut_read(size, false);
    }

    future_ptr<std::vector<uint8_t>> file_handle::fut_read_at(uint64_t offset, uint32_t size) {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*handle->mimic_non_async);
            auto res = handle->fut_read_at(offset, size, false);
            res->wait();
            return res;
        } else
            return handle->fut_read_at(offset, size, false);
    }

    future_ptr<std::vector<uint8_t>> file_handle::fut_read_fixed(uint32_t size) {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*handle->mimic_non_async);
            auto res = handle->fut_read(size, true);
            res->wait();
            return res;
        } else
            return handle->fut_read(size, true);
    }

    future_ptr<std::vector<uint8_t>> file_handle::fut_read_fixed_at(uint64_t offset, uint32_t size) {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*handle->mimic_non_async);
            auto res = handle->fut_read_at(offset, size, true);
            res->wait();
            return res;
        } else
            return handle->fut_read_at(offset, size, true);
    }

    future_ptr<void> file_handle::fut_write(const uint8_t* data, uint32_t size) {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*handle->mimic_non_async);
            auto res = handle->fut_write(data, size);
            res->wait();
            return res;
        } else
            return handle->fut_write(data, size);
    }

    future_ptr<void> file_handle::fut_write_at(uint64_t offset, const uint8_t* data, uint32_t size) {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*handle->mimic_non_async);
            auto res = handle->fut_write_at(offset, data, size);
            res->wait();
            return res;
        } else
            return handle->fut_write_at(offset, data, size);
    }

    future_ptr<void> file_handle::fut_append(const uint8_t* data, uint32_t size) {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*handle->mimic_non_async);
            auto res = handle->fut_append(data, size);
            res->wait();
            return res;
        } else
            return handle->fut_append(data, size);
    }

    io_operation<std::vector<uint8_t>> file_handle::make_read(uint32_t size) {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value())
            throw std::runtime_error("Non-async mode not supported for make_read");
        return io_operation<std::vector<uint8_t>>(handle->fmake_read(size, false));
    }

    io_operation<std::vector<uint8_t>> file_handle::make_read_at(uint64_t offset, uint32_t size) {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value())
            throw std::runtime_error("Non-async mode not supported for make_read_at");
        return io_operation<std::vector<uint8_t>>(handle->fmake_read_at(offset, size, false));
    }

    io_operation<std::vector<uint8_t>> file_handle::make_read_fixed(uint32_t size) {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value())
            throw std::runtime_error("Non-async mode not supported for make_read_fixed");
        return io_operation<std::vector<uint8_t>>(handle->fmake_read(size, true));
    }

    io_operation<std::vector<uint8_t>> file_handle::make_read_fixed_at(uint64_t offset, uint32_t size) {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value())
            throw std::runtime_error("Non-async mode not supported for make_read_fixed_at");
        return io_operation<std::vector<uint8_t>>(handle->fmake_read_at(offset, size, true));
    }

    io_operation<void> file_handle::make_write(const uint8_t* data, uint32_t size) {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value())
            throw std::runtime_error("Non-async mode not supported for make_write");
        return io_operation<void>(handle->fmake_write(data, size));
    }

    io_operation<void> file_handle::make_write_at(uint64_t offset, const uint8_t* data, uint32_t size) {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value())
            throw std::runtime_error("Non-async mode not supported for make_write_at");
        return io_operation<void>(handle->fmake_write_at(offset, data, size));
    }

    io_operation<void> file_handle::make_append(const uint8_t* data, uint32_t size) {
        if (!handle)
            throw file_closed();
        if (handle->mimic_non_async.has_value())
            throw std::runtime_error("Non-async mode not supported for make_append");
        return io_operation<void>(handle->fmake_append(data, size));
    }
}

#endif
