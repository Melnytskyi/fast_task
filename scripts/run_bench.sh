readarray -t executables < <(find ../out/build/Linux-Test-Rel/tests/benchmark -type f -executable)
for exe in "${executables[@]}"; do
    "$exe" 2>&1
done