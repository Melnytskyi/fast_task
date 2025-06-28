// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef SRC_FILES
#define SRC_FILES
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

        union share_mode { //used in windows

            struct {
                bool read : 1;
                bool write : 1;
                bool _delete : 1;
            };

            uint8_t value = 0;

            share_mode(bool read = true, bool write = true, bool _delete = false)
                : read(read), write(write), _delete(_delete) {}
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

        union _async_flags {
            struct {
                bool delete_on_close : 1;
                bool posix_semantics : 1; //used in windows
                bool random_access : 1;   //hint to cache manager
                bool sequential_scan : 1; //hint to cache manager
            };

            uint8_t value = 0;
        };

        union _sync_flags {
            struct {
                bool delete_on_close : 1;
                bool posix_semantics : 1; //used in windows
                bool random_access : 1;   //hint to cache manager
                bool sequential_scan : 1; //hint to cache manager
                bool no_buffering : 1;    //hint to cache manager, affect seek and read write operations, like disc page size aligned operations
                bool write_through : 1;   //hint to cache manager
            };

            uint8_t value = 0;
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

        protected:
            std::streamsize xsgetn(char* s, std::streamsize n) override {
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

            std::streamsize xsputn(const char* s, std::streamsize n) override {
                size_t bytes_to_write = std::min(static_cast<size_t>(n), size_t(epptr() - pptr()));
                traits_type::copy(pptr(), s, bytes_to_write);
                pbump(static_cast<int>(bytes_to_write));
                if (flush_buffer() == traits_type::eof())
                    return traits_type::eof();
                return static_cast<std::streamsize>(bytes_to_write);
            }

            int_type underflow() override {
                if (gptr() == egptr()) {
                    uint32_t bytes_read = file_handle.read(reinterpret_cast<uint8_t*>(buffer.data()), buffer_size);
                    if (bytes_read == 0)
                        return traits_type::eof();
                    setg(buffer.data(), buffer.data(), buffer.data() + bytes_read);
                }
                return traits_type::to_int_type(*gptr());
            }

            int_type overflow(int_type ch) override {
                if (ch != traits_type::eof()) {
                    *pptr() = traits_type::to_char_type(ch);
                    pbump(1);
                }
                if (flush_buffer() == traits_type::eof())
                    return traits_type::eof();
                return traits_type::not_eof(ch);
            }

            int flush_buffer() {
                size_t size = pptr() - pbase();
                if (size > 0) {
                    file_handle.write_inline(reinterpret_cast<const uint8_t*>(pbase()), static_cast<uint32_t>(size));
                    setp(buffer.data(), buffer.data() + buffer_size);
                }
                return 0;
            }

            int sync() override {
                return flush_buffer() == traits_type::eof() ? -1 : 0;
            }

            std::streampos seekoff(std::streamoff off, std::ios_base::seekdir dir, std::ios_base::openmode which) override {
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

            std::streampos seekpos(std::streampos pos, std::ios_base::openmode which) override {
                return seekoff(static_cast<std::streamoff>(pos), std::ios_base::beg, which);
            }

        public:
            explicit async_filebuf(FileHandle& fh)
                : file_handle(fh), buffer(buffer_size) {
                setg(buffer.data(), buffer.data(), buffer.data());
                setp(buffer.data(), buffer.data() + buffer_size);
            }

            ~async_filebuf() {
                sync();
            }
        };

        class async_iofstream : public std::iostream {
            FileHandle handle;

            static open_mode to_open_mode(ios_base::openmode mode) {
                if (mode & ios_base::in) {
                    return open_mode::read;
                } else if (mode & ios_base::out) {
                    return open_mode::write;
                } else if (mode & ios_base::app) {
                    return open_mode::append;
                } else {
                    return open_mode::read_write;
                }
            }

            static on_open_action to_open_action(ios_base::openmode mode) {
                if (mode & ios_base::trunc) {
                    return on_open_action::truncate_exists;
                } else if (mode & ios_base::ate) {
                    return on_open_action::open_exists;
                } else if (mode & ios_base::app) {
                    return on_open_action::always_new;
                } else {
                    return on_open_action::open;
                }
            }

            static share_mode to_protection_mode(ios_base::openmode op_mod, int mode) {
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
                    if (op_mod & ios_base::in)
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


        public:
            explicit async_iofstream(
                const char* str,
                ios_base::openmode mode = ios_base::in,
                int prot = ios_base::_Default_open_prot
            )
                : async_iofstream(std::filesystem::path(str), mode, prot) {}

            explicit async_iofstream(
                const std::string& str,
                ios_base::openmode mode = ios_base::in,
                int prot = ios_base::_Default_open_prot
            )
                : async_iofstream(std::filesystem::path(str), mode, prot) {}

            explicit async_iofstream(
                const wchar_t* str,
                ios_base::openmode mode = ios_base::in,
                int prot = ios_base::_Default_open_prot
            )
                : async_iofstream(std::filesystem::path(str), mode, prot) {}

            explicit async_iofstream(
                const std::wstring& str,
                ios_base::openmode mode = ios_base::in,
                int prot = ios_base::_Default_open_prot
            )
                : async_iofstream(std::filesystem::path(str), mode, prot) {}

            explicit async_iofstream(
                const std::filesystem::path& path,
                ios_base::openmode mode = ios_base::in | ios_base::out,
                int prot = ios_base::_Default_open_prot
            )
                : std::iostream(new async_filebuf(handle)),
                  handle(path.string(), to_open_mode(mode), to_open_action(mode), _sync_flags{}, to_protection_mode(mode, prot)) {
            }

            explicit async_iofstream(
                const std::filesystem::path& path,
                open_mode open,
                on_open_action action,
                _sync_flags flags = {},
                share_mode share = {},
                pointer_mode pointer_mode = pointer_mode::combined
            )
                : std::iostream(new async_filebuf(handle)),
                  handle(path.string(), open, action, flags, share) {
            }

            ~async_iofstream() {
                delete rdbuf();
            }

            bool is_open() const {
                return handle.internal_get_handle() != nullptr;
            }
        };
    }
}

#undef FILE_HANDLE
#endif /* SRC_FILES */
