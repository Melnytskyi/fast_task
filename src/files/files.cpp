// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <filesystem>

#include <files/files.hpp>
#include <future.hpp>
#include <tasks.hpp>
#include <tasks/util/native_workers_singleton.hpp>
#include <vector>

namespace fast_task::files {
    class File_;

    struct completion_struct {
        File_* handle;
        size_t completed_bytes = 0;
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
}
#if _WIN64
    #define NOMINMAX
    #include <Ntstatus.h>
    #include <Windows.h>
    #include <filesystem>
    #include <io.h>
    #include <winternl.h>

namespace fast_task::files {
    class File_ : public util::native_worker_handle {
        task_condition_variable awaiters;
        task_mutex mutex;
        void* handle;
        char* buffer = nullptr;
        bool fullifed = false;

        File_(bool buffer_alloc, util::native_worker_manager* manager, void* handle, char* buffer, uint32_t buffer_size, uint64_t offset)
            : native_worker_handle(manager), handle(handle), buffer_size(buffer_size), offset(offset), is_read(false), required_full(true), buffer_alloc(buffer_alloc) {
            overlapped.Offset = offset & 0xFFFFFFFF;
            overlapped.OffsetHigh = (offset >> 32) & 0xFFFFFFFF;
            if (buffer_alloc) {
                this->buffer = new char[buffer_size];
                memcpy(this->buffer, buffer, buffer_size);
            } else {
                this->buffer = buffer;
            }
        }

        File_(util::native_worker_manager* manager, void* handle, uint32_t buffer_size, uint64_t offset, bool required_full)
            : native_worker_handle(manager), handle(handle), buffer_size(buffer_size), offset(offset), is_read(true), required_full(required_full), buffer_alloc(true) {
            overlapped.Offset = offset & 0xFFFFFFFF;
            overlapped.OffsetHigh = (offset >> 32) & 0xFFFFFFFF;

            this->buffer = new char[buffer_size];
        }

        File_(util::native_worker_manager* manager, void* handle, char* buffer, uint32_t buffer_size, uint64_t offset, bool required_full)
            : native_worker_handle(manager), handle(handle), buffer_size(buffer_size), offset(offset), is_read(true), required_full(required_full), buffer_alloc(false) {
            overlapped.Offset = offset & 0xFFFFFFFF;
            overlapped.OffsetHigh = (offset >> 32) & 0xFFFFFFFF;

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

        static File_* command_write(util::native_worker_manager* manager, void* handle, char* buffer, uint32_t buffer_size, uint64_t offset) {
            return new File_(true, manager, handle, buffer, buffer_size, offset);
        }

        static File_* command_write_inline(util::native_worker_manager* manager, void* handle, char* buffer, uint32_t buffer_size, uint64_t offset) {
            return new File_(false, manager, handle, buffer, buffer_size, offset);
        }

        static File_* command_read(util::native_worker_manager* manager, void* handle, uint32_t buffer_size, uint64_t offset, bool required_full = true) {
            return new File_(manager, handle, buffer_size, offset, required_full);
        }

        static File_* command_read_inline(util::native_worker_manager* manager, void* handle, char* buffer, uint32_t buffer_size, uint64_t offset, bool required_full = true) {
            return new File_(manager, handle, buffer, buffer_size, offset, required_full);
        }

        ~File_() {
            if (buffer && buffer_alloc)
                delete[] buffer;
        }

        void cancel() {
            if (buffer && !get_data(awaiter).end_of_life) {
                if (CancelIoEx(handle, &overlapped))
                    return;
                mutex_unify unify(mutex);
                fast_task::unique_lock<mutex_unify> lock(unify);
                fullifed = true;
                if (awaiter) {
                    if (is_read && !required_full)
                        awaiter->end_dummy([&](auto&) {});
                    else
                        awaiter->end_dummy([&](auto& data) { ((completion_struct*)data)->error = io_errors::operation_canceled; });
                }
                awaiters.notify_all();
                awaiter = nullptr;
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
                    awaiter->end_dummy([&](auto& data) { auto tt = (completion_struct*)data; tt->completed_bytes = fullifed_bytes; tt->data = buffer; });
                else
                    awaiter->end_dummy([&](auto& data) { auto tt = (completion_struct*)data; tt->completed_bytes = fullifed_bytes; });
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
                        awaiter->end_dummy([&](auto& data) { auto tt = (completion_struct*)data; tt->completed_bytes = fullifed_bytes; tt->data = buffer; tt->error = e; });
                    else
                        awaiter->end_dummy([&](auto& data) { auto tt = (completion_struct*)data; tt->completed_bytes = fullifed_bytes; tt->error = e; });
                } else
                    awaiter->end_dummy([&](auto& data) { auto tt = (completion_struct*)data; tt->error = e; });
            }
            awaiters.notify_all();
            awaiter = nullptr;
        }

        void readed(uint32_t len) {
            if (is_read) {
                fullifed_bytes += len;
                if (buffer_size > fullifed_bytes) {
                    uint64_t new_offset = offset + fullifed_bytes;
                    overlapped.Offset = new_offset & 0xFFFFFFFF;
                    overlapped.OffsetHigh = (new_offset >> 32) & 0xFFFFFFFF;
                    if (!ReadFile(handle, buffer + fullifed_bytes, buffer_size - fullifed_bytes, nullptr, &overlapped))
                        error_filter(GetLastError(), 0);
                } else
                    now_fullifed();
            }
        }

        void written(uint32_t len) {
            if (!is_read) {
                fullifed_bytes += len;
                if (buffer_size > fullifed_bytes) {
                    uint64_t new_offset = offset + fullifed_bytes;
                    overlapped.Offset = new_offset & 0xFFFFFFFF;
                    overlapped.OffsetHigh = (new_offset >> 32) & 0xFFFFFFFF;
                    if (!WriteFile(handle, buffer + fullifed_bytes, buffer_size - fullifed_bytes, nullptr, &overlapped))
                        error_filter(GetLastError(), 0);
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
            if (is_read) {
                if (!ReadFile(handle, buffer, buffer_size, NULL, &overlapped)) {
                    auto err = GetLastError();
                    switch (err) {
                    case ERROR_IO_PENDING:
                        return;
                    case ERROR_HANDLE_EOF:
                        io_error_to_exception(io_errors::eof);
                        break;
                    case ERROR_NOT_ENOUGH_MEMORY:
                        io_error_to_exception(io_errors::no_enough_memory);
                        break;
                    case ERROR_INVALID_USER_BUFFER:
                        io_error_to_exception(io_errors::invalid_user_buffer);
                        break;
                    case ERROR_NOT_ENOUGH_QUOTA:
                        io_error_to_exception(io_errors::no_enough_quota);
                        break;
                    default:
                        io_error_to_exception(io_errors::unknown_error);
                        break;
                    }
                }
            } else {
                if (!WriteFile(handle, buffer, buffer_size, NULL, &overlapped)) {
                    auto err = GetLastError();
                    switch (err) {
                    case ERROR_IO_PENDING:
                        return;
                    case ERROR_HANDLE_EOF:
                        io_error_to_exception(io_errors::eof);
                        break;
                    case ERROR_NOT_ENOUGH_MEMORY:
                        io_error_to_exception(io_errors::no_enough_memory);
                        break;
                    case ERROR_INVALID_USER_BUFFER:
                        io_error_to_exception(io_errors::invalid_user_buffer);
                        break;
                    case ERROR_NOT_ENOUGH_QUOTA:
                        io_error_to_exception(io_errors::no_enough_quota);
                        break;
                    default:
                        io_error_to_exception(io_errors::unknown_error);
                        break;
                    }
                }
            }
        }

        bool error_filter(DWORD last_error, uint32_t len) {
            switch (last_error) {
            case ERROR_IO_PENDING:
                return false;
            case ERROR_HANDLE_EOF: {
                if (is_read && !required_full) {
                    now_fullifed();
                    return false;
                } else {
                    fullifed_bytes += len;
                    exception(io_errors::eof);
                    return true;
                }
            }
            case ERROR_NOT_ENOUGH_MEMORY:
                exception(io_errors::no_enough_memory);
                return true;
            case ERROR_INVALID_USER_BUFFER:
                exception(io_errors::invalid_user_buffer);
                return true;
            case ERROR_NOT_ENOUGH_QUOTA:
                exception(io_errors::no_enough_quota);
                return true;
            default:
                exception(io_errors::unknown_error);
                return true;
            }
        }

        bool status_filter(NTSTATUS last_error, uint32_t len) {
            switch (last_error) {
            case STATUS_PENDING:
                return false;
            case STATUS_END_OF_FILE: {
                if (is_read && !required_full) {
                    now_fullifed();
                    return false;
                } else {
                    fullifed_bytes += len;
                    exception(io_errors::eof);
                    return true;
                }
            }
            case STATUS_VID_INSUFFICIENT_RESOURCES_RESERVE:
                exception(io_errors::no_enough_memory);
                return true;
            case STATUS_BUFFER_OVERFLOW:
                exception(io_errors::invalid_user_buffer);
                return true;
            case STATUS_NO_MEMORY: //yea strange name
                exception(io_errors::no_enough_quota);
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

    class FileManager : public util::native_worker_manager {
        void* _handle = nullptr;
        uint64_t write_pointer;
        uint64_t read_pointer;
        pointer_mode pointer_mode;
        bool make_append = false;
        friend class File_;

        uint64_t _file_size() {
            uint64_t size = 0;
            FILE_STANDARD_INFO finfo = {};
            if (GetFileInformationByHandleEx(_handle, FileStandardInfo, &finfo, sizeof(finfo))) {
                if (finfo.EndOfFile.QuadPart > 0)
                    size = finfo.EndOfFile.QuadPart;
                else
                    size = -1;
            } else
                size = -1;
            return size;
        }

    public:
        FileManager(const char* path, size_t path_len, open_mode open, on_open_action action, share_mode share, _sync_flags flags, files::pointer_mode pointer_mode) noexcept(false)
            : pointer_mode(pointer_mode) {
            read_pointer = 0;
            write_pointer = 0;
            auto wpath = std::filesystem::path(path, path + path_len).wstring();
            DWORD wshare_mode = 0;
            if (share.read)
                wshare_mode |= FILE_SHARE_READ;
            if (share.write)
                wshare_mode |= FILE_SHARE_WRITE;
            if (share._delete)
                wshare_mode |= FILE_SHARE_DELETE;

            DWORD wflags = FILE_FLAG_OVERLAPPED;
            if (flags.delete_on_close)
                wflags |= FILE_FLAG_DELETE_ON_CLOSE;
            if (flags.no_buffering)
                wflags |= FILE_FLAG_NO_BUFFERING;
            if (flags.posix_semantics)
                wflags |= FILE_FLAG_POSIX_SEMANTICS;
            if (flags.random_access)
                wflags |= FILE_FLAG_RANDOM_ACCESS;
            if (flags.sequential_scan)
                wflags |= FILE_FLAG_SEQUENTIAL_SCAN;
            if (flags.write_through)
                wflags |= FILE_FLAG_WRITE_THROUGH;


            DWORD wopen = 0;
            switch (open) {
            case open_mode::read:
                wopen = GENERIC_READ;
                break;
            case open_mode::write:
                wopen = GENERIC_WRITE;
                break;
            case open_mode::append:
                wopen = GENERIC_WRITE;
                make_append = true;
                break;
            case open_mode::read_write:
                wopen = GENERIC_READ | GENERIC_WRITE;
                break;
            default:
                throw std::invalid_argument("Invalid open mode, excepted read, write, read_write or append, but got " + std::to_string((int)open));
            }
            DWORD creation_mode = 0;
            switch (action) {
            case on_open_action::open:
                creation_mode = OPEN_ALWAYS;
                break;
            case on_open_action::always_new:
                creation_mode = CREATE_ALWAYS;
                break;
            case on_open_action::create_new:
                creation_mode = CREATE_NEW;
                break;
            case on_open_action::open_exists:
                creation_mode = OPEN_EXISTING;
                break;
            case on_open_action::truncate_exists:
                creation_mode = TRUNCATE_EXISTING;
                break;
            default:
                throw std::invalid_argument("Invalid on open action, excepted open, always_new, create_new, open_exists or truncate_exists, but got " + std::to_string((int)open));
            }

            _handle = CreateFileW(wpath.c_str(), wopen, wshare_mode, NULL, creation_mode, wflags, NULL);
            if (_handle == INVALID_HANDLE_VALUE) {
                _handle = nullptr;
                switch (GetLastError()) {
                case ERROR_FILE_NOT_FOUND:
                    throw std::runtime_error("FileException, File not found");
                case ERROR_ACCESS_DENIED:
                    throw std::runtime_error("FileException, Access denied");
                case ERROR_FILE_EXISTS:
                case ERROR_ALREADY_EXISTS:
                    throw std::runtime_error("FileException, File exists");
                case ERROR_FILE_INVALID:
                    throw std::runtime_error("FileException, File invalid");
                case ERROR_FILE_TOO_LARGE:
                    throw std::runtime_error("FileException, File too large");
                case ERROR_INVALID_PARAMETER:
                    throw std::runtime_error("FileException, Invalid parameter");
                case ERROR_SHARING_VIOLATION:
                    throw std::runtime_error("FileException, Sharing violation");
                default:
                    throw std::runtime_error("FileException, Unknown error");
                }
            }
            util::native_workers_singleton::register_handle(_handle, this);
        }

        ~FileManager() {
            if (_handle != nullptr)
                CloseHandle(_handle);
        }

        future_ptr<std::vector<uint8_t>> read(uint32_t size, bool require_all = true) {
            File_* file = File_::command_read(this, _handle, size, read_pointer, require_all);
            switch (pointer_mode) {
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
                    std::unreachable();
                } else
                    return std::vector<uint8_t>((uint8_t*)data->data, (uint8_t*)data->data + data->completed_bytes);
            });
        }

        uint32_t read(uint8_t* data_, uint32_t size, bool require_all = true) {
            File_* file = File_::command_read_inline(this, _handle, (char*)data_, size, read_pointer, require_all);
            switch (pointer_mode) {
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
                std::unreachable();
            } else
                return data->completed_bytes;
        }

        future_ptr<void> write(const uint8_t* data_, uint32_t size) {
            if (make_append)
                return append(data_, size);

            File_* file = File_::command_write(this, _handle, (char*)data_, size, write_pointer);
            switch (pointer_mode) {
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
                    std::unreachable();
                }
            });
        }

        void write_inline(const uint8_t* data_, uint32_t size) {
            if (make_append)
                return append_inline(data_, size);
            File_* file = File_::command_write_inline(this, _handle, (char*)data_, size, write_pointer);
            switch (pointer_mode) {
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
            if (data->error != io_errors::no_error) {
                io_error_to_exception(data->error);
                std::unreachable();
            }
        }

        future_ptr<void> append(const uint8_t* data_, uint32_t size) {
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
                    std::unreachable();
                }
            });
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
            if (data->error != io_errors::no_error) {
                io_error_to_exception(data->error);
                std::unreachable();
            }
        }

        bool seek_pos(uint64_t offset, pointer_offset pointer_offset, pointer pointer) {
            switch (pointer_offset) {
            case pointer_offset::begin:
                switch (pointer_mode) {
                case pointer_mode::separated:
                    switch (pointer) {
                    case pointer::read:
                        read_pointer = offset;
                        break;
                    case pointer::write:
                        write_pointer = offset;
                        break;
                    }
                    break;
                case pointer_mode::combined:
                    read_pointer = write_pointer = offset;
                    break;
                }
                break;
            case pointer_offset::current:
                switch (pointer_mode) {
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
                    switch (pointer_mode) {
                    case pointer_mode::separated:
                        switch (pointer) {
                        case pointer::read:
                            read_pointer = size + offset;
                            break;
                        case pointer::write:
                            write_pointer = size + offset;
                            break;
                        }
                        break;
                    case pointer_mode::combined:
                        read_pointer = write_pointer = size + offset;
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

        bool seek_pos(uint64_t offset, pointer_offset pointer_offset) {
            switch (pointer_offset) {
            case pointer_offset::begin:
                read_pointer = write_pointer = offset;
                break;
            case pointer_offset::current:
                read_pointer = write_pointer += offset;
                break;
            case pointer_offset::end: {
                auto size = _file_size();
                if (size != -1)
                    read_pointer = write_pointer = size + offset;
                else
                    return false;
                break;
            }
            default:
                break;
            }
            return true;
        }

        uint64_t tell_pos(pointer pointer) {
            switch (pointer) {
            case pointer::read:
                return read_pointer;
            case pointer::write:
                return write_pointer;
            default:
                throw std::runtime_error("Invalid pointer type");
            }
        }

        bool flush() {
            return (bool)FlushFileBuffers(_handle);
        }

        uint64_t file_size() {
            auto res = _file_size();
            if (res == -1)
                return 0;
            else
                return res;
        }

        void handle(void* data, util::native_worker_handle* overlapped, unsigned long dwBytesTransferred) override {
            auto file = (File_*)overlapped;
            if (file->overlapped.Internal)
                file->status_filter((DWORD)file->overlapped.Internal, dwBytesTransferred);
            else
                file->operation_fullifed(dwBytesTransferred);
        }

        void* get_handle() {
            return _handle;
        }

        std::string get_path() const {
            size_t size = GetFinalPathNameByHandleW(_handle, nullptr, 0, FILE_NAME_NORMALIZED);
            std::wstring wpath;
            wpath.resize(size);
            if (GetFinalPathNameByHandleW(_handle, (wchar_t*)wpath.c_str(), size, FILE_NAME_NORMALIZED) == 0)
                throw std::runtime_error("FileException, GetFinalPathNameByHandleW failed");
            //remove \\?\ prefix
            return std::filesystem::path((const wchar_t*)wpath.c_str() + 4, wpath.c_str() + wpath.size() - 4).string();
        }
    };

    void* FileHandle::internal_get_handle() const noexcept {
        return handle->get_handle();
    }
}
#else
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

namespace fast_task::files {
    class File_ : public native_worker_handle {
        task_condition_variable awaiters;
        task_mutex mutex;
        int handle;
        char* buffer = nullptr;
        bool fullifed = false;

        File_(native_worker_manager* manager, int handle, const char* buffer, uint32_t buffer_size, uint64_t offset)
            : native_worker_handle(manager), handle(handle), is_read(false), buffer_size(buffer_size), offset(offset), required_full(true) {
            this->buffer = new char[buffer_size];
            memcpy(this->buffer, buffer, buffer_size);
        }

        File_(native_worker_manager* manager, int handle, uint32_t buffer_size, uint64_t offset, bool required_full = true)
            : native_worker_handle(manager), handle(handle), is_read(true), buffer_size(buffer_size), offset(offset), required_full(required_full) {
            this->buffer = new char[buffer_size];
        }

        File_(bool buffer_alloc, util::native_worker_manager* manager, void* handle, char* buffer, uint32_t buffer_size, uint64_t offset)
            : native_worker_handle(manager), handle(handle), is_read(false), buffer_size(buffer_size), offset(offset), required_full(true), buffer_alloc(buffer_alloc) {
            if (buffer_alloc) {
                this->buffer = new char[buffer_size];
                memcpy(this->buffer, buffer, buffer_size);
            } else
                this->buffer = buffer;
        }

        File_(util::native_worker_manager* manager, void* handle, uint32_t buffer_size, uint64_t offset, bool required_full)
            : native_worker_handle(manager), handle(handle), is_read(true), buffer_size(buffer_size), offset(offset), required_full(required_full), buffer_alloc(true) {
            this->buffer = new char[buffer_size];
        }

        File_(util::native_worker_manager* manager, void* handle, char* buffer, uint32_t buffer_size, uint64_t offset, bool required_full)
            : native_worker_handle(manager), handle(handle), is_read(true), buffer_size(buffer_size), offset(offset), required_full(required_full), buffer_alloc(false) {
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

        static File_* command_write(util::native_worker_manager* manager, void* handle, char* buffer, uint32_t buffer_size, uint64_t offset) {
            return new File_(true, manager, handle, buffer, buffer_size, offset);
        }

        static File_* command_write_inline(util::native_worker_manager* manager, void* handle, char* buffer, uint32_t buffer_size, uint64_t offset) {
            return new File_(false, manager, handle, buffer, buffer_size, offset);
        }

        static File_* command_read(util::native_worker_manager* manager, void* handle, uint32_t buffer_size, uint64_t offset, bool required_full = true) {
            return new File_(manager, handle, buffer_size, offset, required_full);
        }

        static File_* command_read_inline(util::native_worker_manager* manager, void* handle, char* buffer, uint32_t buffer_size, uint64_t offset, bool required_full = true) {
            return new File_(manager, handle, buffer, buffer_size, offset, required_full);
        }

        ~File_() {
            if (buffer)
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
                            awaiter->end_dummy([&](auto&) {});
                        else
                            awaiter->end_dummy([&](auto& data) { ((completion_struct*)data)->error = io_errors::operation_canceled; });
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
                    awaiter->end_dummy([&](auto& data) { auto tt = (completion_struct*)data; tt->completed_bytes = fullifed_bytes; tt->data = buffer; });
                else
                    awaiter->end_dummy([&](auto& data) { auto tt = (completion_struct*)data; tt->completed_bytes = fullifed_bytes; });
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
                        awaiter->end_dummy([&](auto& data) { auto tt = (completion_struct*)data; tt->completed_bytes = fullifed_bytes; tt->data = buffer; tt->error = e; });
                    else
                        awaiter->end_dummy([&](auto& data) { auto tt = (completion_struct*)data; tt->completed_bytes = fullifed_bytes; tt->error = e; });
                } else
                    awaiter->end_dummy([&](auto& data) { auto tt = (completion_struct*)data; tt->error = e; });
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

    class FileManager : public native_worker_manager {
        int _handle = -1;
        uint64_t write_pointer;
        uint64_t read_pointer;
        pointer_mode _pointer_mode;
        friend class File_;


        uint16_t uflags;

        uint64_t _file_size() {
            uint64_t size = 0;
            struct stat st;
            if (fstat(_handle, &st) == 0)
                size = st.st_size;
            return size;
        }

    public:
        FileManager(const char* path, size_t path_len, open_mode open, on_open_action action, share_mode share, _sync_flags flags, pointer_mode _pointer_mode) noexcept(false)
            : _pointer_mode(_pointer_mode), uflags(0) {
            read_pointer = 0;
            write_pointer = 0;
            int mode = O_NONBLOCK;

            //if(share.read)
            //    wshare_mode |= FILE_SHARE_READ;
            //if(share.write)
            //    wshare_mode |= FILE_SHARE_WRITE;
            //if(share._delete)
            //    wshare_mode |= FILE_SHARE_DELETE;

            int wflags = 0;
            if (flags.delete_on_close)
                uflags |= user_flags::FILE_FLAG_DELETE_ON_CLOSE;
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
                mode |= O_RDONLY;
                mode |= O_APPEND;
                break;
            case open_mode::read_write:
                mode |= O_RDWR;
                break;
            default:
                throw std::invalid_argument("Invalid open mode, excepted read, write, read_write or append, but got " + std::to_string((int)open));
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
                    throw std::runtime_error("FileException, File not found");
                break;
            case on_open_action::truncate_exists:
                if (!std::filesystem::exists(path))
                    throw std::runtime_error("FileException, File not found");
                mode |= O_TRUNC;
                break;
            default:
                throw std::invalid_argument("Invalid on open action, excepted open, always_new, create_new, open_exists or truncate_exists, but got " + std::to_string((int)open));
            }
            _handle = open64(path, mode, 0644);
            if (_handle == -1) {
                switch (errno) {
                case ENOENT:
                    throw std::runtime_error("FileException, File not found");
                case EACCES:
                case EPERM:
                    throw std::runtime_error("FileException, Access denied");
                case EEXIST:
                    throw std::runtime_error("FileException, File exists");
                case EISDIR:
                    throw std::runtime_error("FileException, File invalid");
                case EFBIG:
                    throw std::runtime_error("FileException, File too large");
                case E2BIG:
                case EINVAL:
                    throw std::runtime_error("FileException, Invalid parameter");
                //case ERROR_SHARING_VIOLATION:
                //    throw std::runtime_error("FileException, Sharing violation");
                default:
                    throw std::runtime_error("FileException, Unknown error");
                }
            }
        }

        ~FileManager() {
            if (_handle != -1)
                close(_handle);
        }

        future_ptr<std::vector<uint8_t>> read(uint32_t size, bool require_all = true) {
            File_* file = File_::command_read(this, _handle, size, read_pointer, require_all);
            switch (pointer_mode) {
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
                    std::unreachable();
                } else
                    return std::vector<uint8_t>((uint8_t*)data->data, (uint8_t*)data->data + data->completed_bytes);
            });
        }

        uint32_t read(uint8_t* data_, uint32_t size, bool require_all = true) {
            File_* file = File_::command_read_inline(this, _handle, (char*)data_, size, read_pointer, require_all);
            switch (pointer_mode) {
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
                std::unreachable();
            } else
                return data->completed_bytes;
        }

        future_ptr<void> write(const uint8_t* data_, uint32_t size) {
            File_* file = File_::command_write(this, _handle, (char*)data_, size, write_pointer);
            switch (pointer_mode) {
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
                    std::unreachable();
                }
            });
        }

        void write_inline(const uint8_t* data_, uint32_t size) {
            File_* file = File_::command_write_inline(this, _handle, (char*)data_, size, write_pointer);
            switch (pointer_mode) {
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
                std::unreachable();
            }
        }

        future_ptr<void> append(const uint8_t* data_, uint32_t size) {
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
                if (data->error != io_errors::no_error) {
                    io_error_to_exception(data->error);
                    std::unreachable();
                }
            });
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
                std::unreachable();
            }
        }

        bool seek_pos(uint64_t offset, pointer_offset pointer_offset, pointer pointer) {
            switch (pointer_offset) {
            case pointer_offset::begin:
                switch (_pointer_mode) {
                case pointer_mode::separated:
                    switch (pointer) {
                    case pointer::read:
                        read_pointer = offset;
                        break;
                    case pointer::write:
                        write_pointer = offset;
                        break;
                    }
                    break;
                case pointer_mode::combined:
                    read_pointer = write_pointer = offset;
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
                            read_pointer = size + offset;
                            break;
                        case pointer::write:
                            write_pointer = size + offset;
                            break;
                        }
                        break;
                    case pointer_mode::combined:
                        read_pointer = write_pointer = size + offset;
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

        bool seek_pos(uint64_t offset, pointer_offset pointer_offset) {
            switch (pointer_offset) {
            case pointer_offset::begin:
                read_pointer = write_pointer = offset;
                break;
            case pointer_offset::current:
                read_pointer = write_pointer += offset;
                break;
            case pointer_offset::end: {
                auto size = _file_size();
                if (size != -1)
                    read_pointer = write_pointer = size + offset;
                else
                    return false;
                break;
            }
            default:
                break;
            }
            return true;
        }

        uint64_t tell_pos(pointer pointer) {
            switch (pointer) {
            case pointer::read:
                return read_pointer;
            case pointer::write:
                return write_pointer;
            default:
                return nullptr;
            }
        }

        bool flush() {
            return (bool)fsync(_handle) == 0; //replace with post_fsync
        }

        uint64_t file_size() {
            auto res = _file_size();
            if (res == -1)
                return nullptr;
            else
                return res;
        }

        void handle(class native_worker_handle* overlapped, io_uring_cqe* cqe) override {
            auto file = (File_*)overlapped;
            if (cqe->res <= 0)
                file->error_filter(-cqe->res);
            else
                file->operation_fullifed(cqe->res);
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
    };
}
#endif

namespace fast_task::files {
    FileHandle::FileHandle(const char* path, size_t path_len, open_mode open, on_open_action action, _async_flags flags, share_mode share, pointer_mode pointer_mode) noexcept(false) {
        _sync_flags sync_flags;
        sync_flags.delete_on_close = flags.delete_on_close;
        sync_flags.posix_semantics = flags.posix_semantics;
        sync_flags.random_access = flags.random_access;
        sync_flags.sequential_scan = flags.sequential_scan;
        handle = nullptr;
        try {
            handle = new FileManager(path, path_len, open, action, share, sync_flags, pointer_mode);
        } catch (...) {
            if (handle)
                delete handle;
            throw;
        }
    }

    FileHandle::FileHandle(const char* path, size_t path_len, open_mode open, on_open_action action, _sync_flags flags, share_mode share, pointer_mode pointer_mode) noexcept(false) {
        handle = nullptr;
        try {
            handle = new FileManager(path, path_len, open, action, share, flags, pointer_mode);
            mimic_non_async.emplace();
        } catch (...) {
            if (handle)
                delete handle;
            throw;
        }
    }

    FileHandle::~FileHandle() {
        delete handle;
    }

    future_ptr<std::vector<uint8_t>> FileHandle::read(uint32_t size) {
        if (mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*mimic_non_async);
            auto res = handle->read(size, true);
            res->wait();
            return res;
        } else
            return handle->read(size, true);
    }

    uint32_t FileHandle::read(uint8_t* data, uint32_t size) {
        if (mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*mimic_non_async);
            return handle->read(data, size);
        } else
            return handle->read(data, size);
    }

    future_ptr<std::vector<uint8_t>> FileHandle::read_fixed(uint32_t size) {
        if (mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*mimic_non_async);
            auto res = handle->read(size, true);
            res->wait();
            return res;
        } else
            return handle->read(size, true);
    }

    uint32_t FileHandle::read_fixed(uint8_t* data, uint32_t size) {
        if (mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*mimic_non_async);
            return handle->read(data, size, true);
        } else
            return handle->read(data, size, true);
    }

    future_ptr<void> FileHandle::write(const uint8_t* data, uint32_t size) {
        if (mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*mimic_non_async);
            auto res = handle->write(data, size);
            res->wait();
            return res;
        } else
            return handle->write(data, size);
    }

    future_ptr<void> FileHandle::append(const uint8_t* data, uint32_t size) {
        if (mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*mimic_non_async);
            auto res = handle->append(data, size);
            res->wait();
            return res;
        } else
            return handle->append(data, size);
    }

    void FileHandle::write_inline(const uint8_t* data, uint32_t size) {
        if (mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*mimic_non_async);
            handle->write_inline(data, size);
        } else
            handle->write_inline(data, size);
    }

    void FileHandle::append_inline(const uint8_t* data, uint32_t size) {
        if (mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*mimic_non_async);
            handle->append_inline(data, size);
        } else
            handle->append_inline(data, size);
    }

    bool FileHandle::seek_pos(uint64_t offset, pointer_offset pointer_offset, pointer pointer) {
        if (mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*mimic_non_async);
            return handle->seek_pos(offset, pointer_offset, pointer);
        } else
            return handle->seek_pos(offset, pointer_offset, pointer);
    }

    bool FileHandle::seek_pos(uint64_t offset, pointer_offset pointer_offset) {
        if (mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*mimic_non_async);
            return handle->seek_pos(offset, pointer_offset);
        } else
            return handle->seek_pos(offset, pointer_offset);
    }

    uint64_t FileHandle::tell_pos(pointer pointer) {
        if (mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*mimic_non_async);
            return handle->tell_pos(pointer);
        } else
            return handle->tell_pos(pointer);
    }

    bool FileHandle::flush() {
        if (mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*mimic_non_async);
            return handle->flush();
        } else
            return handle->flush();
    }

    uint64_t FileHandle::size() {
        if (mimic_non_async.has_value()) {
            fast_task::lock_guard<task_mutex> lock(*mimic_non_async);
            return handle->file_size();
        } else
            return handle->file_size();
    }

    std::string FileHandle::get_path() const {
        return handle->get_path();
    }

    std::streamsize async_filebuf::make_sputn(const char* s, std::streamsize n) {
        size_t bytes_to_write = std::min(static_cast<size_t>(n), size_t(epptr() - pptr()));
        traits_type::copy(pptr(), s, bytes_to_write);
        pbump(static_cast<int>(bytes_to_write));
        if (flush_buffer() == traits_type::eof())
            return traits_type::eof();
        return static_cast<std::streamsize>(bytes_to_write);
    }

    std::streamsize async_filebuf::xsgetn(char* s, std::streamsize n) {
        if (gptr() == egptr()) {
            uint32_t bytes_read = file_handle.read(reinterpret_cast<uint8_t*>(buffer.data()), buffer_size);
            if (bytes_read == 0)
                return traits_type::eof();
            setg(buffer.data(), buffer.data(), buffer.data() + bytes_read);
        }
        size_t bytes_to_copy = std::min(static_cast<size_t>(n), size_t(egptr() - gptr()));
        traits_type::copy(s, gptr(), bytes_to_copy);
        gbump(static_cast<int>(bytes_to_copy));
        return static_cast<std::streamsize>(bytes_to_copy);
    }

    std::streamsize async_filebuf::xsputn(const char* s, std::streamsize n) {
        auto res = n;
        while (n > 0) {
            size_t available_space = pptr() < epptr() ? epptr() - pptr() : 0;
            if (available_space == 0) {
                if (flush_buffer() == traits_type::eof())
                    return traits_type::eof();
                available_space = epptr() - pptr();
            }
            size_t bytes_to_write = std::min(static_cast<size_t>(n), available_space);
            auto sput_res = make_sputn(s, static_cast<std::streamsize>(bytes_to_write));
            if (sput_res == traits_type::eof())
                return traits_type::eof();
            s += bytes_to_write;
            n -= static_cast<std::streamsize>(bytes_to_write);
        }
        return res;
    }

    async_filebuf::int_type async_filebuf::underflow() {
        if (gptr() == egptr()) {
            uint32_t bytes_read = file_handle.read(reinterpret_cast<uint8_t*>(buffer.data()), buffer_size);
            if (bytes_read == 0)
                return traits_type::eof();
            setg(buffer.data(), buffer.data(), buffer.data() + bytes_read);
        }
        return traits_type::to_int_type(*gptr());
    }

    async_filebuf::int_type async_filebuf::overflow(int_type ch) {
        if (ch != traits_type::eof()) {
            *pptr() = traits_type::to_char_type(ch);
            pbump(1);
        }
        if (flush_buffer() == traits_type::eof())
            return traits_type::eof();
        return traits_type::not_eof(ch);
    }

    int async_filebuf::flush_buffer() {
        size_t size = pptr() - pbase();
        if (size > 0) {
            file_handle.write_inline(reinterpret_cast<const uint8_t*>(pbase()), static_cast<uint32_t>(size));
            setp(buffer.data(), buffer.data() + buffer_size);
        }
        return 0;
    }

    int async_filebuf::sync() {
        return flush_buffer() == traits_type::eof() ? -1 : 0;
    }

    std::streampos async_filebuf::seekoff(std::streamoff off, std::ios_base::seekdir dir, std::ios_base::openmode which) {
        pointer_offset offset_mode;
        switch (dir) {
        case std::ios_base::beg:
            offset_mode = pointer_offset::begin;
            break;
        case std::ios_base::cur:
            offset_mode = pointer_offset::current;
            break;
        case std::ios_base::end:
            offset_mode = pointer_offset::end;
            break;
        default:
            return std::streampos(std::streamoff(-1));
        }

        pointer pointer_type = (which & std::ios_base::out) ? pointer::write : pointer::read;

        if (!file_handle.seek_pos(static_cast<uint64_t>(off), offset_mode, pointer_type))
            return std::streampos(std::streamoff(-1));

        return std::streampos(static_cast<std::streamoff>(file_handle.tell_pos(pointer_type)));
    }

    std::streampos async_filebuf::seekpos(std::streampos pos, std::ios_base::openmode which) {
        return seekoff(static_cast<std::streamoff>(pos), std::ios_base::beg, which);
    }

    async_filebuf::async_filebuf(FileHandle& fh)
        : file_handle(fh), buffer(buffer_size) {
        setg(buffer.data(), buffer.data(), buffer.data());
        setp(buffer.data(), buffer.data() + buffer_size);
    }

    async_filebuf::~async_filebuf() {
        flush_buffer();
    }

    FileHandle* handle;

    open_mode to_open_mode(std::ios_base::openmode mode) {
        if (mode & std::ios_base::in) {
            return open_mode::read;
        } else if (mode & std::ios_base::out) {
            return open_mode::write;
        } else if (mode & std::ios_base::app) {
            return open_mode::append;
        } else {
            return open_mode::read_write;
        }
    }

    on_open_action to_open_action(std::ios_base::openmode mode) {
        if (mode & std::ios_base::trunc) {
            return on_open_action::truncate_exists;
        } else if (mode & std::ios_base::ate) {
            return on_open_action::open_exists;
        } else if (mode & std::ios_base::app) {
            return on_open_action::always_new;
        } else {
            return on_open_action::open;
        }
    }

    static share_mode to_protection_mode(std::ios_base::openmode op_mod, int mode) {
        share_mode protection_mode;
        if (mode & _SH_DENYRW) {
            protection_mode.read = false;
            protection_mode.write = false;
        } else if (mode & _SH_DENYWR) {
            protection_mode.read = true;
            protection_mode.write = false;
        } else if (mode & _SH_DENYRD) {
            protection_mode.read = false;
            protection_mode.write = true;
        } else if (mode & _SH_DENYNO) {
            protection_mode.read = true;
            protection_mode.write = true;
        } else if (mode & _SH_SECURE) {
            if (op_mod & std::ios_base::in)
                protection_mode.read = true;
            else
                protection_mode.read = false;
            protection_mode.write = false;
        } else {
            protection_mode.read = true;
            protection_mode.write = true;
        }
        return protection_mode;
    }

    async_iofstream::async_iofstream(
        const char* str,
        ios_base::openmode mode,
        int prot
    )
        : async_iofstream(std::filesystem::path(str), mode, prot) {}

    async_iofstream::async_iofstream(
        const std::string& str,
        ios_base::openmode mode,
        int prot
    )
        : async_iofstream(std::filesystem::path(str), mode, prot) {}

    async_iofstream::async_iofstream(
        const wchar_t* str,
        ios_base::openmode mode,
        int prot
    )
        : async_iofstream(std::filesystem::path(str), mode, prot) {}

    async_iofstream::async_iofstream(
        const std::wstring& str,
        ios_base::openmode mode,
        int prot
    )
        : async_iofstream(std::filesystem::path(str), mode, prot) {}

    async_iofstream::async_iofstream(
        const std::filesystem::path& path,
        ios_base::openmode mode,
        int prot
    ) : std::iostream(nullptr) {
        try {
            handle = new FileHandle(path.string(), to_open_mode(mode), to_open_action(mode), _sync_flags{}, to_protection_mode(mode, prot));
            set_rdbuf(new async_filebuf(*handle));
            clear();
        } catch (...) {
            setstate(std::ios_base::badbit);
        }
    }

    async_iofstream::async_iofstream(
        const std::filesystem::path& path,
        open_mode open,
        on_open_action action,
        _sync_flags flags,
        share_mode share,
        pointer_mode pointer_mode
    ) : std::iostream(nullptr) {
        try {
            handle = new FileHandle(path.string(), open, action, flags, share, pointer_mode);
            set_rdbuf(new async_filebuf(*handle));
            clear();
        } catch (...) {
            setstate(std::ios_base::badbit);
        }
    }

    async_iofstream::~async_iofstream() {
        if (handle) {
            if (rdbuf()) {
                flush();
                delete rdbuf();
            }
            delete handle;
        }
    }

    bool async_iofstream::is_open() const {
        return handle != nullptr;
    }
}