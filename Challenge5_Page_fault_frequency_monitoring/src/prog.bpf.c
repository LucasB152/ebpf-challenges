// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "Monitor.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";


/* This map store the config of the program (only 1 struct), i.e. :
 * - The size of the window (in milliseconds)
 * - The upper bound
 * - The lower bound
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pff_config);
} config_map SEC(".maps");

// This map store the timestamp of all the page fault that occured
// It's a circular array: when we reach the end of the array, the index goes back to the beginning
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_FAULTS);
    __type(key, __u32);
    __type(value, __u64);
} timestamps SEC(".maps");

/* This map store the state of the timestamp map (only 1 struct), i.e. :
 * - The index (where to put the next timestamp)
 * - The first timestamp added (used to avoid sending error before having a full window)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pff_state);
} state_map SEC(".maps");

// This perf buffer is used to send asynchronous message (TOO HIGH error, TOO LOW schedule check) to the user space
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// This struct is used in the bpf_loop
struct loop_ctx {
    __u64 now; // current timestamp
    __u64 window_ns; // size of the window (in miliseconds)
    __u64 lower_bount; // minimal number of page fault needed in the window
    __u64 count; // number of timestamp in the window
    __u64 oldest_timestamp; //oldest timestamp in the window (it will exit it in first)
    struct pff_state *state; // contains the writer index
};

/*
 * Loop function to count the number of page fault in the window (to detect TOO HIGH)
 * AND to find the oldtest page fault in the lower bound
 */
static int check_window_cb(__u32 index, struct loop_ctx *ctx) {
    __u32 idx = (ctx->state->write_idx + MAX_FAULTS - 1 - index) % MAX_FAULTS;

    __u64 *timestamp = bpf_map_lookup_elem(&timestamps, &idx);
    if (!timestamp)
        return 1;

    // if we exit the window size
    if (ctx->now - *timestamp > ctx->window_ns)
        return 1;

    // Count the number of timestamp in the window to detect TOO HIGH
    ctx->count++;

    // Only update oldest_timestamp for the first lower_bount faults
    if (ctx->count <= ctx->lower_bount)
        ctx->oldest_timestamp = *timestamp;

    return 0;
}

SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(handle_hook, struct vm_area_struct *vma, unsigned long address, unsigned int flags) {
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));

    if (comm[0]  != 'p' || comm[1]  != 'a' || comm[2]  != 'g' ||
        comm[3]  != 'e' || comm[4]  != '_' || comm[5]  != 'f' ||
        comm[6]  != 'a' || comm[7]  != 'u' || comm[8]  != 'l' ||
        comm[9]  != 't' || comm[10] != '_' || comm[11] != 'g' ||
        comm[12] != 'e' || comm[13] != 'n')
        return 0;

    __u32 zero = 0;
    struct pff_config *configuration = bpf_map_lookup_elem(&config_map, &zero);
    struct pff_state *state = bpf_map_lookup_elem(&state_map, &zero);
    if (!configuration || !state)
        return 0;

    __u64 now = bpf_ktime_get_ns();

    // Size of the window in nanoseconds
    __u64 window_ns = configuration->time_window_ms * 1000000ULL;

    if (state->first_fault_timestamp == 0)
        state->first_fault_timestamp = now;


    __u32 slot = state->write_idx % MAX_FAULTS;
    bpf_map_update_elem(&timestamps, &slot, &now, BPF_ANY);
    state->write_idx++;

    __u64 lower_bount = (__u64)configuration->lower_bound_freq_ms * configuration->time_window_ms;


    struct loop_ctx lctx = {
        .now = now,
        .window_ns = window_ns,
        .lower_bount   = lower_bount,
        .count = 0,
        .oldest_timestamp = now,
        .state = state
    };

    bpf_loop(MAX_FAULTS, check_window_cb, &lctx, 0);

    // Upper bound check
    __u64 upper_count = (__u64)configuration->upper_bound_freq_ms * configuration->time_window_ms;
    if (lctx.count > upper_count) {
        struct pff_event ev_high = {
            .type = EVENT_TOO_HIGH,
            .pid  = bpf_get_current_pid_tgid() >> 32,
        };
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev_high, sizeof(ev_high));
    }

    // Lower bound: schedule a check for when the OLDEST fault in the window will leave it.
    // At that moment, if no new fault has arrived, the count drops and may go below lower_bount.
    __u64 deadline = lctx.oldest_timestamp + window_ns;

    struct pff_event ev_sched = {
        .type        = EVENT_SCHEDULE_CHECK,
        .pid         = bpf_get_current_pid_tgid() >> 32,
        .deadline_ns = deadline,
        .first_fault_timestamp = state->first_fault_timestamp,
        .window_ns   = window_ns,
        .write_idx             = state->write_idx,
    };
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev_sched, sizeof(ev_sched));

    return 0;
}