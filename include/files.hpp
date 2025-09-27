// Copyright Danyil Melnytskyi 2022-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef FAST_TASK_INCLUDE_FILES
#define FAST_TASK_INCLUDE_FILES
#include "future.hpp"
#include "shared.hpp"
#include "task.hpp"
#include <filesystem>
#include <istream>
#include <optional>
#include <ostream>
#include <vector>

namespace fast_task {
    namespace files {
        enum open_mode : uint8_t {
            read,
            write,
            read_write,
            append
        };

        struct FT_API share_mode { //used in windows
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

        struct FT_API _async_flags {
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

        struct FT_API _sync_flags {
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

        class FT_API file_handle {
            class file_manager* handle;

            file_handle();

        public:
            static file_handle open(const std::filesystem::path& path, open_mode open, on_open_action action, _async_flags flags = {}, share_mode share = {}, pointer_mode pointer_mode = pointer_mode::combined);
            static file_handle open(const std::filesystem::path& path, open_mode open, on_open_action action, _sync_flags flags = {}, share_mode share = {}, pointer_mode pointer_mode = pointer_mode::combined);

            static file_handle open_throws(const std::filesystem::path& path, open_mode open, on_open_action action, _async_flags flags = {}, share_mode share = {}, pointer_mode pointer_mode = pointer_mode::combined);
            static file_handle open_throws(const std::filesystem::path& path, open_mode open, on_open_action action, _sync_flags flags = {}, share_mode share = {}, pointer_mode pointer_mode = pointer_mode::combined);

            ~file_handle();

            bool is_open() const;
            void close();

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

#if _WIN64
            using native_file_handle = void*;
#else /*UNIX*/
            using native_file_handle = int;
#endif

            native_file_handle internal_get_handle() const noexcept;

            //extract full path from handle, could be not same as path in constructor
            std::string get_path() const;
        };

        template <bool _mock>
        struct __force_static_iofstream {
            inline static open_mode to_open_mode(std::ios_base::openmode mode) {
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

            inline static on_open_action to_open_action(std::ios_base::openmode mode) {
                if (mode & std::ios_base::trunc) {
                    return on_open_action::truncate_exists;
                } else if (mode & std::ios_base::app) {
                    return on_open_action::open;
#if ((defined(_MSVC_LANG) && _MSVC_LANG >= 202302L) || __cplusplus >= 202302L)
                } else if (mode & std::ios_base::noreplace) {
                    return on_open_action::create_new;
#endif
                } else if (mode & std::ios_base::ate) {
                    return on_open_action::open_exists;
                } else {
                    return on_open_action::open;
                }
            }

#if _WIN64
            inline static share_mode to_protection_mode(std::ios_base::openmode op_mod, int mode) {
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

            static constexpr inline auto default_prot = std::ios_base::_Default_open_prot;
#else
            inline static share_mode to_protection_mode(std::ios_base::openmode op_mod, [[maybe_unused]] int mode) {
                share_mode protection_mode;
                protection_mode.read = bool(op_mod & std::ios_base::in);
                protection_mode.write = false;
                return protection_mode;
            }

            static constexpr inline auto default_prot = 0;
#endif
            inline static _sync_flags to_flags(std::ios_base::openmode op_mod) {
                _sync_flags flags{};
                if (op_mod & std::ios_base::ate)
                    flags.at_end = true;

                return flags;
            }

            class async_filebuf : public std::streambuf {
            private:
                static constexpr size_t buffer_size = 4096; // Buffer size for reading/writing
                file_handle& _handle;
                std::vector<char> buffer;

                std::streamsize make_sputn(const char* s, std::streamsize n) {
                    size_t bytes_to_write = std::min(static_cast<size_t>(n), size_t(epptr() - pptr()));
                    traits_type::copy(pptr(), s, bytes_to_write);
                    pbump(static_cast<int>(bytes_to_write));
                    if (flush_buffer() == traits_type::eof())
                        return traits_type::eof();
                    return static_cast<std::streamsize>(bytes_to_write);
                }

            protected:
                std::streamsize xsgetn(char* s, std::streamsize n) override {
                    if (gptr() == egptr()) {
                        uint32_t bytes_read = _handle.read(reinterpret_cast<uint8_t*>(buffer.data()), buffer_size);
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

                int_type underflow() override {
                    if (gptr() == egptr()) {
                        uint32_t bytes_read = _handle.read(reinterpret_cast<uint8_t*>(buffer.data()), buffer_size);
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
                        _handle.write_inline(reinterpret_cast<const uint8_t*>(pbase()), static_cast<uint32_t>(size));
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

                    if (!_handle.seek_pos(static_cast<uint64_t>(off), offset_mode, pointer_type))
                        return std::streampos(std::streamoff(-1));

                    return std::streampos(static_cast<std::streamoff>(_handle.tell_pos(pointer_type)));
                }

                std::streampos seekpos(std::streampos pos, std::ios_base::openmode which) override {
                    return seekoff(static_cast<std::streamoff>(pos), std::ios_base::beg, which);
                }

            public:
                explicit async_filebuf(file_handle& fh)
                    : _handle(fh), buffer(buffer_size) {
                    setg(buffer.data(), buffer.data(), buffer.data());
                    setp(buffer.data(), buffer.data() + buffer_size);
                }

                ~async_filebuf() {
                    flush_buffer();
                }
            };

            class async_iofstream : public std::iostream {
                file_handle handle;

            public:
                explicit async_iofstream(
                    const char* str,
                    ios_base::openmode mode = ios_base::in,
                    int prot = default_prot
                )
                    : async_iofstream(std::filesystem::path(str), mode, prot) {}

                explicit async_iofstream(
                    const std::string& str,
                    ios_base::openmode mode = ios_base::in,
                    int prot = default_prot
                )
                    : async_iofstream(std::filesystem::path(str), mode, prot) {}

                explicit async_iofstream(
                    const wchar_t* str,
                    ios_base::openmode mode = ios_base::in,
                    int prot = default_prot
                )
                    : async_iofstream(std::filesystem::path(str), mode, prot) {}

                explicit async_iofstream(
                    const std::wstring& str,
                    ios_base::openmode mode = ios_base::in,
                    int prot = default_prot
                )
                    : async_iofstream(std::filesystem::path(str), mode, prot) {}

                explicit async_iofstream(
                    const std::filesystem::path& path,
                    ios_base::openmode mode = ios_base::in | ios_base::out,
                    int prot = default_prot
                ) : std::iostream(nullptr), handle(file_handle::open(path.string(), to_open_mode(mode), to_open_action(mode), to_flags(mode), to_protection_mode(mode, prot))) {
                    if (handle.is_open()) {
                        set_rdbuf(new async_filebuf(handle));
                        clear();
                    } else
                        setstate(std::ios_base::badbit);
                }

                explicit async_iofstream(
                    const std::filesystem::path& path,
                    open_mode open,
                    on_open_action action,
                    _sync_flags flags = {},
                    share_mode share = {},
                    pointer_mode pointer_mode = pointer_mode::combined
                ) : std::iostream(nullptr), handle(file_handle::open(path.string(), open, action, flags, share, pointer_mode)) {
                    if (handle.is_open()) {
                        set_rdbuf(new async_filebuf(handle));
                        clear();
                    } else
                        setstate(std::ios_base::badbit);
                }

                ~async_iofstream() {
                    if (handle.is_open()) {
                        if (rdbuf()) {
                            flush();
                            delete rdbuf();
                        }
                    }
                }

                bool is_open() const {
                    return handle.is_open();
                }
            };

            class atomic_async_ofstream : public std::iostream {
                file_handle handle;
                std::filesystem::path real_path;

            public:
                explicit atomic_async_ofstream(const char* str)
                    : atomic_async_ofstream(std::filesystem::path(str)) {}

                explicit atomic_async_ofstream(const std::string& str)
                    : atomic_async_ofstream(std::filesystem::path(str)) {}

                explicit atomic_async_ofstream(const wchar_t* str)
                    : atomic_async_ofstream(std::filesystem::path(str)) {}

                explicit atomic_async_ofstream(const std::wstring& str)
                    : atomic_async_ofstream(std::filesystem::path(str)) {}

                explicit atomic_async_ofstream(const std::filesystem::path& path)
                    : std::iostream(nullptr),
                      real_path(path),
                      handle(
                          file_handle::open(
                              path.string() + ".atomic.tmp",
                              open_mode::write,
                              on_open_action::always_new,
                              _sync_flags{},
                              share_mode{true, false, false}
                          )
                      ) {
                    if (handle.is_open()) {
                        set_rdbuf(new async_filebuf(handle));
                        clear();
                    } else
                        setstate(std::ios_base::badbit);
                }

                ~atomic_async_ofstream() {
                    if (handle.is_open()) {
                        if (rdbuf()) {
                            flush();
                            delete rdbuf();
                        }
                        handle.close();
                        std::filesystem::rename(real_path.string() + ".atomic.tmp", real_path);
                    }
                }

                bool is_open() const {
                    return handle.is_open();
                }
            };
        };

        using async_filebuf = __force_static_iofstream<true>::async_filebuf;
        using async_iofstream = __force_static_iofstream<true>::async_iofstream;
        using atomic_async_ofstream = __force_static_iofstream<true>::atomic_async_ofstream; //the writes done to temporary file and replaces the temporary with real one atomically without corrupting the data
    }
}

#endif