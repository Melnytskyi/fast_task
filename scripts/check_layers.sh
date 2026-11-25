#!/bin/sh
# Fails when a scheduler-core file includes one from a higher layer.
#
# Layers, low to high:
#   0 base       hdi, thread_identity, allocators, debug_objects, futex_global,
#                dormant_broker, preemption, cpu_relax, event, notifier
#   1 pool       storage types, the ops table, the executor registry, the queue storage
#   2 notify     the floating driver and the timer glue
#   3 runtime    the singletons, the pool manager, stop-the-world, pool_wake
#   4 execution  one task on one worker thread
#
# A file may include its own layer or any lower one. Two files live in a directory
# that is not their layer: preemption.hpp is execution/ but has no dependency above
# base, and pool_wake.hpp is notify/ but wakes pools through glob, which puts it at
# the runtime layer. Ranking them by directory would describe dependencies that do
# not exist.

set -u

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root" || exit 1

layer_of() {
    case "$1" in
        tasks/core/runtime/hdi.hpp | \
            tasks/core/runtime/thread_identity.hpp | \
            tasks/core/runtime/allocators.hpp | \
            tasks/core/runtime/debug_objects.hpp | \
            tasks/core/runtime/futex_global.hpp | \
            tasks/core/pool/dormant_broker.hpp | \
            tasks/core/execution/preemption.hpp | \
            tasks/util/cpu_relax.hpp | \
            tasks/core/notify/event.hpp | \
            tasks/core/notify/notifier.hpp)
            echo 0
            ;;
        tasks/core/pool/*) echo 1 ;;
        tasks/core/notify/pool_wake.hpp) echo 3 ;;
        tasks/core/notify/*) echo 2 ;;
        tasks/core/runtime/*) echo 3 ;;
        tasks/core/execution/*) echo 4 ;;
        *) echo "" ;;
    esac
}

status=0
for file in $(find src/tasks/core -type f \( -name '*.hpp' -o -name '*.cpp' \) | sort); do
    own=$(layer_of "${file#src/}")
    [ -n "$own" ] || continue
    for target in $(sed -n 's/^#include <\(tasks\/[^>]*\)>.*/\1/p' "$file"); do
        other=$(layer_of "$target")
        [ -n "$other" ] || continue
        if [ "$other" -gt "$own" ]; then
            echo "$file (layer $own) includes $target (layer $other)" >&2
            status=1
        fi
    done
done

if [ "$status" -eq 0 ]; then
    echo "check_layers: include direction is clean"
fi

exit "$status"
