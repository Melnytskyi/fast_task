// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_FILES
#define FAST_TASK_FILES
#include "../future.hpp"
#include "../tasks.hpp"
#include <filesystem>
#include <istream>
#include <ostream>
#include <vector>

#if _WIN64
    #define FILE_HANDLE void*
#else /*UNIX*/
    #define FILE_HANDLE int
#endif
namespace fast_task {
    namespace files {
        enum open_mode : uint8_t {
            read,
            write,
            read_write,
            append
        };

        struct share_mode { //used in windows
            bool read : 1;
            bool write : 1;
            bool _delete : 1;

            share_mode(bool read = true, bool write = true, bool _delete = false)
                : read(read), write(write), _delete(_delete) {}

            uint8_t get() const {
                union union_t {
                    share_mode self;
                    uint8_t value = 0;
                } unified{.self = *this};

                return unified.value;
            }

            void set(uint8_t value) {
                union union_t {
                    share_mode self;
                    uint8_t v = 0;
                } unified{.v = value};

                *this = unified.self;
            }
        };
        enum class pointer : uint8_t {
            read,
            write
        };
        enum class pointer_offset : uint8_t {
            begin,
            current,
            end
        };
        enum class pointer_mode : uint8_t {
            separated,
            combined
        };
        enum class on_open_action : uint8_t {
            open,
            always_new,
            create_new,
            open_exists,
            truncate_exists
        };

        struct _async_flags {
            bool delete_on_close : 1;
            bool posix_semantics : 1; //used in windows
            bool random_access : 1;   //hint to cache manager
            bool sequential_scan : 1; //hint to cache manager
            bool at_end : 1;

            uint8_t get() const {
                union union_t {
                    _async_flags self;
                    uint8_t value = 0;
                } unified{.self = *this};

                return unified.value;
            }

            void set(uint8_t value) {
                union union_t {
                    _async_flags self;
                    uint8_t v = 0;
                } unified{.v = value};

                *this = unified.self;
            }
        };

        struct _sync_flags {
            bool delete_on_close : 1;
            bool posix_semantics : 1; //used in windows
            bool random_access : 1;   //hint to cache manager
            bool sequential_scan : 1; //hint to cache manager
            bool no_buffering : 1;    //hint to cache manager, affect seek and read write operations, like disc page size aligned operations
            bool write_through : 1;   //hint to cache manager
            bool at_end : 1;

            uint8_t get() const {
                union union_t {
                    _sync_flags self;
                    uint8_t value = 0;
                } unified{.self = *this};

                return unified.value;
            }

            void set(uint8_t value) {
                union union_t {
                    _sync_flags self;
                    uint8_t v = 0;
                } unified{.v = value};

                *this = unified.self;
            }
        };

        enum class io_errors : uint8_t {
            no_error,
            eof,
            no_enough_memory,
            invalid_user_buffer,
            no_enough_quota,
            unknown_error,
            operation_canceled
        };

        class FileHandle {
            class FileManager* handle;
            std::optional<task_mutex> mimic_non_async;

        public:
            FileHandle(const char* path, size_t path_len, open_mode open, on_open_action action, _async_flags flags = {}, share_mode share = {}, pointer_mode pointer_mode = pointer_mode::combined) noexcept(false);
            FileHandle(const char* path, size_t path_len, open_mode open, on_open_action action, _sync_flags flags = {}, share_mode share = {}, pointer_mode pointer_mode = pointer_mode::combined) noexcept(false);

            FileHandle(const std::string& path, open_mode open, on_open_action action, _async_flags flags = {}, share_mode share = {}, pointer_mode pointer_mode = pointer_mode::combined) noexcept(false)
                : FileHandle(path.c_str(), path.size(), open, action, flags, share, pointer_mode) {}

            FileHandle(const std::string& path, open_mode open, on_open_action action, _sync_flags flags = {}, share_mode share = {}, pointer_mode pointer_mode = pointer_mode::combined) noexcept(false)
                : FileHandle(path.c_str(), path.size(), open, action, flags, share, pointer_mode) {}

            ~FileHandle();

            future_ptr<std::vector<uint8_t>> read(uint32_t size);
            uint32_t read(uint8_t* data, uint32_t size);

            future_ptr<std::vector<uint8_t>> read_fixed(uint32_t size);
            uint32_t read_fixed(uint8_t* data, uint32_t size);

            future_ptr<void> write(const uint8_t* data, uint32_t size);
            future_ptr<void> append(const uint8_t* data, uint32_t size);
            void write_inline(const uint8_t* data, uint32_t size);
            void append_inline(const uint8_t* data, uint32_t size);

            bool seek_pos(uint64_t offset, pointer_offset pointer_offset, pointer pointer);
            bool seek_pos(uint64_t offset, pointer_offset pointer_offset);

            uint64_t tell_pos(pointer pointer);

            bool flush();

            uint64_t size();

            FILE_HANDLE internal_get_handle() const noexcept;

            //extract full path from handle, could be not same as path in constructor
            std::string get_path() const;
        };

        class async_filebuf : public std::streambuf {
        private:
            static constexpr size_t buffer_size = 4096; // Buffer size for reading/writing
            FileHandle& file_handle;
            std::vector<char> buffer;

            std::streamsize make_sputn(const char* s, std::streamsize n);

        protected:
            std::streamsize xsgetn(char* s, std::streamsize n) override;
            std::streamsize xsputn(const char* s, std::streamsize n) override;
            int_type underflow() override;
            int_type overflow(int_type ch) override;
            int flush_buffer();
            int sync() override;
            std::streampos seekoff(std::streamoff off, std::ios_base::seekdir dir, std::ios_base::openmode which) override;
            std::streampos seekpos(std::streampos pos, std::ios_base::openmode which) override;

        public:
            explicit async_filebuf(FileHandle& fh);

            ~async_filebuf();
        };

        class async_iofstream : public std::iostream {
            FileHandle* handle;

        public:
            explicit async_iofstream(
                const char* str,
                ios_base::openmode mode = ios_base::in,
                int prot = ios_base::_Default_open_prot
            );
            explicit async_iofstream(
                const std::string& str,
                ios_base::openmode mode = ios_base::in,
                int prot = ios_base::_Default_open_prot
            );
            explicit async_iofstream(
                const wchar_t* str,
                ios_base::openmode mode = ios_base::in,
                int prot = ios_base::_Default_open_prot
            );
            explicit async_iofstream(
                const std::wstring& str,
                ios_base::openmode mode = ios_base::in,
                int prot = ios_base::_Default_open_prot
            );
            explicit async_iofstream(
                const std::filesystem::path& path,
                ios_base::openmode mode = ios_base::in | ios_base::out,
                int prot = ios_base::_Default_open_prot
            );

            explicit async_iofstream(
                const std::filesystem::path& path,
                open_mode open,
                on_open_action action,
                _sync_flags flags = {},
                share_mode share = {},
                pointer_mode pointer_mode = pointer_mode::combined
            );
            ~async_iofstream();

            bool is_open() const;
        };
    }
}

#undef FILE_HANDLE
#endif
