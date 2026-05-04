#!/bin/bash

MAX_JOBS=8
LOG_FILE="./test_hunt_results_$(date +%Y%m%d_%H%M%S).log"
BUILD_DIR="../out/build/Linux-Test"

echo "--- Test Hunt Started $(date) ---" > "$LOG_FILE"
cd "$BUILD_DIR" || exit 1

readarray -t executables < <(find ./tests -type f -executable | grep "/Debug/")

echo "Found ${#executables[@]} executables. Starting hunt with max $MAX_JOBS parallel jobs..."

hunt_test() {
    local test_path=$1
    local temp_log=$(mktemp)
    local temp_out=$(mktemp)
    local temp_err=$(mktemp)

    echo -e "\n=======================================================" > "$temp_log"
    echo "--- Starting hunt for: $test_path ---" >> "$temp_log"

    local hung=false
    for attempt in {1..200}; do
        "$test_path" --gtest_catch_exceptions=0 -halt_on_exception > "$temp_out" 2> "$temp_err" &
        local pid=$!

        local timeout_ticks=50
        local tick=0
        
        while kill -0 $pid 2>/dev/null; do
            sleep 0.1
            ((tick++))
            
            if [ $tick -ge $timeout_ticks ]; then
                hung=true
                echo "=== HANG at attempt $attempt ===" >> "$temp_log"

                if command -v gdb &> /dev/null; then
                    echo -e "\n--- GDB Stack Trace ---" >> "$temp_log"
                    gdb -p $pid -batch -ex "set print pretty on" -ex "print fast_task::glob" -ex "thread apply all bt full" -ex "quit" >> "$temp_log" 2>&1
                else
                    echo -e "\n[ERROR] gdb not found." >> "$temp_log"
                fi

                kill -9 $pid 2>/dev/null
                wait $pid 2>/dev/null

                echo -e "\n--- Test Console Output (STDOUT) ---" >> "$temp_log"
                cat "$temp_out" >> "$temp_log"
                
                echo -e "\n--- Test Console Error (STDERR) ---" >> "$temp_log"
                cat "$temp_err" >> "$temp_log"
                
                echo "=== END HANG DATA ===" >> "$temp_log"
                break 2
            fi
        done
    done

    if [ "$hung" = false ]; then
        echo "Result: COMPLETED 200 ATTEMPTS WITHOUT HANGING" >> "$temp_log"
    fi
    echo "--- Finished hunt for: $test_path ---" >> "$temp_log"

    cat "$temp_log" >> "$LOG_FILE"
    rm -f "$temp_log" "$temp_out" "$temp_err"
    
    echo "Finished: $test_path"
}

for exe in "${executables[@]}"; do
    hunt_test "$exe" &
    
    while [ $(jobs -pr | wc -l) -ge $MAX_JOBS ]; do
        sleep 0.5
    done
done

wait

echo -e "\nHunt completely finished. All results are saved to $LOG_FILE"