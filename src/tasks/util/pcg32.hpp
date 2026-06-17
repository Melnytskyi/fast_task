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
        pcg32(){
            std::random_device device{};
            state = device() ^ (device() >> 31);
            inc = (device() ^ (device() >> 31)) | 1;
        }

        uint32_t next() {
            uint64_t old = state;
            state = old * pcg32_mult + inc;
            uint32_t xor_shift = static_cast<uint32_t>(((old >> 18) ^ old) >> 27);
            uint32_t rot = static_cast<uint32_t>(old >> 59);
            return (xor_shift >> rot) | (xor_shift << ((~rot + 1) & 31));
        }
    };
}
#endif /* SRC_TASKS_UTIL_PCG32 */
