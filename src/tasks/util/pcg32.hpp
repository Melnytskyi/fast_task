#ifndef SRC_TASKS_UTIL_PCG32
#define SRC_TASKS_UTIL_PCG32
#include <cstdint>
#include <random>

namespace fast_task {
    class pcg32 {
        static inline constexpr uint64_t pcg32_mult = 0x5851f42d4c957f2d;

        uint64_t state;
        uint64_t inc;

    public:
        using result_type = uint32_t;

        static constexpr result_type min() noexcept {
            return 0;
        }

        static constexpr result_type max() noexcept {
            return UINT32_MAX;
        }

        pcg32() {
            std::random_device device{};
            state = (static_cast<uint64_t>(device()) << 32) | device();
            inc = ((static_cast<uint64_t>(device()) << 32) | device()) | 1;
        }

        uint32_t next() {
            uint64_t old = state;
            state = old * pcg32_mult + inc;
            uint32_t xor_shift = static_cast<uint32_t>(((old >> 18) ^ old) >> 27);
            uint32_t rot = static_cast<uint32_t>(old >> 59);
            return (xor_shift >> rot) | (xor_shift << ((~rot + 1) & 31));
        }

        result_type operator()() {
            return next();
        }
    };
}
#endif /* SRC_TASKS_UTIL_PCG32 */
