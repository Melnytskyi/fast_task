#ifndef FAST_TASK_HILL_CLIMBING
#define FAST_TASK_HILL_CLIMBING
//source https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/Threading/PortableThreadPool.HillClimbing.cs
// used to balance the number of threads in thread pools, ported from the C# runtime sources
// uses https://en.wikipedia.org/wiki/Hill_climbing to find the best number of threads to use
// this and hill_climbing.cpp file licensed under MIT license
#include <complex>
#include <random>
#include <tuple>
#include <vector>

#include <tasks/util/cpu_usage.hpp>

namespace fast_task::util {
    class hill_climb {
        /*const*/ uint32_t wave_period;
        /*const*/ uint32_t samples_to_measure;
        /*const*/ double target_throughput_ratio;
        /*const*/ double target_signal_to_noise_ratio;
        /*const*/ double max_change_per_second;
        /*const*/ double max_change_per_sample;
        /*const*/ uint32_t max_thread_wave_magnitude;
        /*const*/ uint32_t sample_interval_ms_low;
        /*const*/ double thread_magnitude_multiplier;
        /*const*/ uint32_t sample_interval_ms_high;
        /*const*/ double throughput_error_smoothing_factor;
        /*const*/ double gain_exponent;
        /*const*/ double max_sample_error;

        double current_control_setting = 0;
        uint64_t total_samples = 0;
        uint32_t last_thread_count = 0;
        double average_throughput_noise = 0;
        double seconds_elapsed_since_last_change = 0;
        double completions_since_last_change = 0;
        uint32_t accumulated_completion_count = 0;
        double accumulated_sample_duration_seconds = 0;
        std::vector<double> samples;
        std::vector<double> thread_counts;
        uint32_t current_sample_ms = 0;

        std::mt19937 _random_interval_generator;
        util::cpu::usage_prev_stat prev_stat;
        std::complex<double> get_wave_component(std::vector<double>& samples, uint32_t num_samples, double period);
        void set_thread_count(uint32_t thread_count);

    public:
        hill_climb();
        //new_thread_count, next_sample_ms
        std::pair<uint32_t, uint32_t> climb(uint32_t curr_thread_count, double sample_seconds, uint32_t completed_count, uint32_t min_threads, uint32_t max_threads);
    };
}
#endif
