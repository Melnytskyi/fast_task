
// Copyright Danyil Melnytskyi 2024-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifdef _WIN64
    #include "native_workers_singleton_win.hpp"
#else
    #include "native_workers_singleton_linux.hpp"
#endif
