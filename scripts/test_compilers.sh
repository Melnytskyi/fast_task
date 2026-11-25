#!/usr/bin/env bash
# Auto-discovers installed C++ compilers (g++, g++-*, clang++, clang++-*)
# and builds + tests fast_task with each distinct compiler binary.
#
# Usage:
#   bash scripts/test_compilers.sh [Debug|Release] [extra cmake args...]
#
# Environment variables:
#   FT_BUILD_ROOT   Base directory for build folders (default: out/build/multi)
#   FT_CTEST_ARGS   Extra arguments passed to ctest (default: "")
#   FT_JOBS         Parallel build jobs (default: 4)
#   FT_IO_TESTS     Enable I/O & network tests: ON or OFF (default: ON)

set -euo pipefail

BUILD_TYPE="${1:-Debug}"
if [ $# -gt 0 ]; then
    shift
fi
EXTRA_CMAKE_ARGS=("$@")

BUILD_ROOT="${FT_BUILD_ROOT:-out/build/multi}"
JOBS="${FT_JOBS:-4}"
IO_TESTS="${FT_IO_TESTS:-ON}"

if [ "$IO_TESTS" = "ON" ]; then
    DISABLE_IO="OFF"
else
    DISABLE_IO="ON"
fi

# Collect candidate C++ compilers from PATH and /usr/bin, deduplicated by realpath.
declare -A SEEN_REALPATHS
COMPILERS=()

add_candidate() {
    local bin="$1"
    [ -x "$bin" ] || return 0
    local rp
    rp="$(readlink -f "$bin")"
    if [ -n "${SEEN_REALPATHS[$rp]+x}" ]; then
        return 0
    fi
    SEEN_REALPATHS[$rp]=1
    COMPILERS+=("$bin")
}

for dir in $(echo "$PATH" | tr ':' ' '); do
    [ -d "$dir" ] || continue
    for pat in "g++" "g++-*" "clang++" "clang++-*"; do
        for cand in "$dir"/$pat; do
            [ -e "$cand" ] || continue
            # Skip non-compiler helpers (e.g. clang++-format, g++-ar)
            case "$(basename "$cand")" in
                g++|g++-[0-9]*|clang++|clang++-[0-9]*)
                    add_candidate "$cand"
                    ;;
            esac
        done
    done
done

if [ ${#COMPILERS[@]} -eq 0 ]; then
    echo "No supported C++ compilers found in PATH." >&2
    exit 1
fi

echo "Discovered ${#COMPILERS[@]} compiler(s):"
for cxx in "${COMPILERS[@]}"; do
    printf "  - %s (%s)\n" "$cxx" "$("$cxx" --version | head -n1)"
done
echo ""

bash scripts/check_layers.sh

FAILED=()
for cxx in "${COMPILERS[@]}"; do
    base="$(basename "$cxx")"
    cc="${cxx/g++/gcc}"
    cc="${cc/clang++/clang}"
    if [ ! -x "$cc" ]; then
        cc=""
    fi

    build_dir="${BUILD_ROOT}/${base}-${BUILD_TYPE}"
    echo "============================================================"
    echo "Compiler: $cxx ($("$cxx" --version | head -n1))"
    echo "Build dir: $build_dir"
    echo "============================================================"

    cmake_cmd=(
        cmake -B "$build_dir" -G Ninja
        "-DCMAKE_BUILD_TYPE=${BUILD_TYPE}"
        "-DCMAKE_CXX_COMPILER=${cxx}"
        "-DFAST_TASK_BUILD_TESTS=ON"
        "-DFAST_TASK_DISABLE_IO_TESTS=${DISABLE_IO}"
    )
    if [ -n "$cc" ]; then
        cmake_cmd+=("-DCMAKE_C_COMPILER=${cc}")
    fi
    if [ ${#EXTRA_CMAKE_ARGS[@]} -gt 0 ]; then
        cmake_cmd+=("${EXTRA_CMAKE_ARGS[@]}")
    fi

    if ! "${cmake_cmd[@]}"; then
        FAILED+=("${base} (configure)")
        continue
    fi

    if ! cmake --build "$build_dir" -j"$JOBS"; then
        FAILED+=("${base} (build)")
        continue
    fi

    # shellcheck disable=SC2086
    if ! ctest --test-dir "$build_dir" --timeout 14 --output-on-failure ${FT_CTEST_ARGS:-}; then
        FAILED+=("${base} (test)")
        continue
    fi
done

echo ""
echo "============================================================"
if [ ${#FAILED[@]} -eq 0 ]; then
    echo "ALL ${#COMPILERS[@]} COMPILER(S) PASSED (${BUILD_TYPE})"
    exit 0
else
    echo "FAILED COMPILERS:"
    for item in "${FAILED[@]}"; do
        echo "  - $item"
    done
    exit 1
fi
