//source https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/Threading/PortableThreadPool.HillClimbing.cs
// used to balance the number of threads in thread pools, ported from the C# runtime sources
// uses https://en.wikipedia.org/wiki/Hill_climbing to find the best number of threads to use
// this and hill_climbing.hpp file licensed under MIT license

#include <tasks/util/hill_climbing.hpp>
#define _USE_MATH_DEFINES
#include <algorithm>
#include <cassert>
#include <math.h>
#include <numbers>

#include <tasks/util/cpu_usage.hpp>

namespace fast_task::util {
    std::complex<double> hill_climb::get_wave_component(std::vector<double>& samples, uint32_t num_samples, double period) {
        assert(num_samples >= period);         // can't measure a wave that doesn't fit
        assert(period >= 2);                   // can't measure above the Nyquist frequency
        assert(num_samples <= samples.size()); // can't measure more samples than we have
        //
        // Calculate the sinusoid with the given period
        // Goertzel algorithm http://en.wikipedia.org/wiki/Goertzel_algorithm
        //
        double w = 2 * M_PI / period;
        double cos = std::cos(w);
        double coeff = 2 * cos;
        double q0, q1 = 0, q2 = 0;
        for (uint32_t i = 0; i < num_samples; ++i) {
            q0 = coeff * q1 - q2 + samples[(total_samples - num_samples + i) % samples_to_measure];
            q2 = q1;
            q1 = q0;
        }
        return std::complex<double>(q1 - q2 * cos, q2 * std::sin(w)) /= num_samples;
    }

    void hill_climb::set_thread_count(uint32_t thread_count) {
        last_thread_count = thread_count;
        std::uniform_int_distribution<uint32_t> distribution(sample_interval_ms_low, sample_interval_ms_high + 1);
        current_sample_ms = distribution(_random_interval_generator);
        seconds_elapsed_since_last_change = 0;
        completions_since_last_change = 0;
    }

    std::pair<uint32_t, uint32_t> hill_climb::climb(uint32_t current_thread_count, double sample_duration_seconds, uint32_t num_completions, uint32_t min_threads, uint32_t max_threads) {
        if (current_thread_count != last_thread_count) {
            current_control_setting += current_thread_count - last_thread_count;
            set_thread_count(current_thread_count);
        }

        //
        // update the cumulative stats for this thread count
        //
        seconds_elapsed_since_last_change += sample_duration_seconds;
        completions_since_last_change += num_completions;

        //
        // add in any data we've already collected about this sample
        //
        sample_duration_seconds += accumulated_sample_duration_seconds;
        num_completions += accumulated_completion_count;

        //
        // we need to make sure we're collecting reasonably accurate data.  since we're just counting the end
        // of each work item, we are going to be missing some data about what really happened during the
        // sample interval.  the count produced by each thread includes an initial work item that may have
        // started well before the start of the interval, and each thread may have been running some new
        // work item for some time before the end of the interval, which did not yet get counted.  so
        // our count is going to be off by +/- thread_count work items.
        //
        // the exception is that the thread that reported to us last time definitely wasn't running any work
        // at that time, and the thread that's reporting now definitely isn't running a work item now.  so
        // we really only need to consider thread_count-1 threads.
        //
        // thus the percent error in our count is +/- (thread_count-1)/num_completions.
        //
        // we cannot rely on the frequency-domain analysis we'll be doing later to filter out this error, because
        // of the way it accumulates over time.  if this sample is off by, say, 33% in the negative direction,
        // then the next one likely will be too.  the one after that will include the sum of the completions
        // we missed in the previous samples, and so will be 33% positive.  so every three samples we'll have
        // two "low" samples and one "high" sample.  this will appear as periodic variation right in the frequency
        // range we're targeting, which will not be filtered by the frequency-domain translation.
        //
        if (total_samples > 0 && ((current_thread_count - 1.0) / num_completions) >= max_sample_error) {
            // not accurate enough yet.  let's accumulate the data so far, and tell the thread_pool
            // to collect a little more.
            accumulated_sample_duration_seconds = sample_duration_seconds;
            accumulated_completion_count = num_completions;
            return {current_thread_count, 10};
        }

        //
        // we've got enough data for our sample; reset our accumulators for next time.
        //
        accumulated_sample_duration_seconds = 0;
        accumulated_completion_count = 0;

        //
        // add the current thread count and throughput sample to our history
        //
        double throughput = num_completions / sample_duration_seconds;

        uint32_t sample_index = (uint32_t)(total_samples % samples_to_measure);
        samples[sample_index] = throughput;
        thread_counts[sample_index] = current_thread_count;
        total_samples++;

        //
        // set up defaults for our metrics
        //
        std::complex<double> thread_wave_component;
        std::complex<double> throughput_wave_component;
        double throughput_error_estimate = 0;
        std::complex<double> ratio;
        double confidence = 0;

        //
        // how many samples will we use?  it must be at least the three wave periods we're looking for, and it must also be a whole
        // multiple of the primary wave's period; otherwise the frequency we're looking for will fall between two  frequency bands
        // in the fourier analysis, and we won't be able to measure it accurately.
        //
        uint32_t sample_count =
            std::min(total_samples - 1, (uint64_t)samples_to_measure) / wave_period * wave_period;

        if (sample_count > wave_period) {
            //
            // average the throughput and thread count samples, so we can scale the wave magnitudes later.
            //
            double sample_sum = 0;
            double thread_sum = 0;
            for (uint32_t i = 0; i < sample_count; i++) {
                sample_sum += samples[(total_samples - sample_count + i) % samples_to_measure];
                thread_sum += thread_counts[(total_samples - sample_count + i) % samples_to_measure];
            }
            double average_throughput = sample_sum / sample_count;
            double average_thread_count = thread_sum / sample_count;

            if (average_throughput > 0 && average_thread_count > 0) {
                //
                // calculate the periods of the adjacent frequency bands we'll be using to measure noise levels.
                // we want the two adjacent fourier frequency bands.
                //
                double adjacent_period1 = sample_count / (((double)sample_count / wave_period) + 1);
                double adjacent_period2 = sample_count / (((double)sample_count / wave_period) - 1);

                //
                // get the three different frequency components of the throughput (scaled by average
                // throughput).  our "error" estimate (the amount of noise that might be present in the
                // frequency band we're really interested in) is the average of the adjacent bands.
                //
                throughput_wave_component =
                    get_wave_component(samples, sample_count, wave_period) / average_throughput;
                throughput_error_estimate =
                    std::abs(get_wave_component(samples, sample_count, adjacent_period1) / average_throughput);
                if (adjacent_period2 <= sample_count) {
                    throughput_error_estimate = std::max(
                        throughput_error_estimate,
                        std::abs(get_wave_component(samples, sample_count, adjacent_period2) / average_throughput)
                    );
                }

                //
                // do the same for the thread counts, so we have something to compare to.  we don't measure thread count
                // noise, because there is none; these are exact measurements.
                //
                thread_wave_component =
                    get_wave_component(thread_counts, sample_count, wave_period) / average_thread_count;

                //
                // update our moving average of the throughput noise.  we'll use this later as feedback to
                // determine the new size of the thread wave.
                //
                if (average_throughput_noise == 0)
                    average_throughput_noise = throughput_error_estimate;
                else
                    average_throughput_noise =
                        (throughput_error_smoothing_factor * throughput_error_estimate) +
                        ((1.0 - throughput_error_smoothing_factor) * average_throughput_noise);

                if (std::abs(thread_wave_component) > 0) {
                    //
                    // adjust the throughput wave so it's centered around the target wave, and then calculate the adjusted throughput/thread ratio.
                    //
                    ratio = (throughput_wave_component - (target_throughput_ratio * thread_wave_component)) /
                            thread_wave_component;
                } else {
                    ratio = std::complex<double>();
                }

                //
                // calculate how confident we are in the ratio.  more noise == less confident.  this has
                // the effect of slowing down movements that might be affected by random noise.
                //
                double noise_for_confidence = std::max(average_throughput_noise, throughput_error_estimate);
                if (noise_for_confidence > 0)
                    confidence =
                        (std::abs(thread_wave_component) / noise_for_confidence) / target_signal_to_noise_ratio;
                else
                    confidence = 1.0; //there is no noise!
            }
        }

        //
        // we use just the real part of the complex ratio we just calculated.  if the throughput signal
        // is exactly in phase with the thread signal, this will be the same as taking the magnitude of
        // the complex move and moving that far up.  if they're 180 degrees out of phase, we'll move
        // backward (because this indicates that our changes are having the opposite of the intended effect).
        // if they're 90 degrees out of phase, we won't move at all, because we can't tell whether we're
        // having a negative or positive effect on throughput.
        //
        double move = std::min(1.0, std::max(-1.0, ratio.real()));

        //
        // apply our confidence multiplier.
        //
        move *= std::min(1.0, std::max(0.0, confidence));

        //
        // now apply non-linear gain, such that values around zero are attenuated, while higher values
        // are enhanced.  this allows us to move quickly if we're far away from the target, but more slowly
        // if we're getting close, giving us rapid ramp-up without wild oscillations around the target.
        //
        double gain = max_change_per_second * sample_duration_seconds;
        move = std::pow(std::abs(move), gain_exponent) * (move >= 0.0 ? 1 : -1) * gain;
        move = std::min(move, max_change_per_sample);


        //
        // if the result was positive, and cpu is > 95%, refuse the move.
        //
        if (move > 0.0)
            if (cpu::get_usage_percents(prev_stat) > 95.0)
                move = 0.0;

        //
        // apply the move to our control setting
        //
        current_control_setting += move;

        //
        // calculate the new thread wave magnitude, which is based on the moving average we've been keeping of
        // the throughput error.  this average starts at zero, so we'll start with a nice safe little wave at first.
        //
        uint32_t new_thread_wave_magnitude =
            (uint32_t)(0.5 + (current_control_setting * average_throughput_noise * target_signal_to_noise_ratio *
                              thread_magnitude_multiplier * 2.0));
        new_thread_wave_magnitude = std::min(new_thread_wave_magnitude, max_thread_wave_magnitude);
        new_thread_wave_magnitude = std::max(new_thread_wave_magnitude, (uint32_t)1);

        current_control_setting =
            std::min(double(max_threads - new_thread_wave_magnitude), current_control_setting);
        current_control_setting = std::max(double(min_threads), current_control_setting);

        //
        // calculate the new thread count (control setting + square wave)
        //
        uint32_t new_thread_count =
            (uint32_t)(current_control_setting +
                       new_thread_wave_magnitude * ((total_samples / (wave_period / 2)) % 2));

        //
        // make sure the new thread count doesn't exceed the thread_pool's limits
        //
        new_thread_count = std::min(max_threads, new_thread_count);
        new_thread_count = std::max(min_threads, new_thread_count);

        if (new_thread_count != current_thread_count)
            set_thread_count(new_thread_count);

        //
        // return the new thread count and sample interval.  this is randomized to prevent correlations with other periodic
        // changes in throughput.  among other things, this prevents us from getting confused by hill climbing instances
        // running in other processes.
        //
        // if we're at min_threads, and we seem to be hurting performance by going higher, we can't go any lower to fix this.  so
        // we'll simply stay at min_threads much longer, and only occasionally try a higher value.
        //
        uint32_t new_sample_interval;
        if (ratio.real() < 0.0 && new_thread_count == min_threads)
            new_sample_interval = (uint32_t)(0.5 + current_sample_ms * (10.0 * std::min(-ratio.real(), 1.0)));
        else
            new_sample_interval = current_sample_ms;

        return {new_thread_count, new_sample_interval};
    }

    hill_climb::hill_climb() {
        wave_period = 4;
        max_thread_wave_magnitude = 20;
        thread_magnitude_multiplier = 100 / 100.0;
        samples_to_measure = wave_period * 8;
        target_throughput_ratio = 15 / 100.0;
        target_signal_to_noise_ratio = 300 / 100.0;
        max_change_per_second = 4;
        max_change_per_sample = 20;

        sample_interval_ms_low = 10;
        sample_interval_ms_high = 200;
        throughput_error_smoothing_factor = 1 / 100.0;
        gain_exponent = 200 / 100.0;
        max_sample_error = 15 / 100.0;

        samples.resize(samples_to_measure);
        thread_counts.resize(samples_to_measure);

        std::uniform_int_distribution<uint32_t> distribution(sample_interval_ms_low, sample_interval_ms_high + 1);
        current_sample_ms = distribution(_random_interval_generator);
    }
}
