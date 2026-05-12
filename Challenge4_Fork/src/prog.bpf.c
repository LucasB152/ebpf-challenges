// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_N       32 		//taille maximale de la fenêtre glissante
#define TASK_COMM_LEN 16 	//taille maximale d'un nom de processus Linux
#define SIGKILL     9 		//numéro du signal SIGKILL

struct config {
    __u32 n_process;          // sliding-window size
    __u64 time_separation_ns; // minimum gap in nanoseconds
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

#define SLOT_HEAD  0 // Index of the index of the head (the oldest timestamp)
#define SLOT_COUNT 1 // Index of number of timestamp currently stored
#define SLOT_WIN   2 // Index where we start storing timestamp

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, SLOT_WIN + MAX_N);
    __type(key, __u32);
    __type(value, __u64);
} window_map SEC(".maps");


SEC("tp/syscalls/sys_exit_clone")
int handle_hook(struct trace_event_raw_sys_exit *ctx)
{
    // The fork return 0 for the child
    if (ctx->ret != 0)
        return 0;

    // Verify if the parent process name is forking
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    char parent_comm[TASK_COMM_LEN];
    bpf_probe_read_kernel_str(parent_comm, sizeof(parent_comm), BPF_CORE_READ(task, real_parent, comm));

    if (parent_comm[0] != 'f' || parent_comm[1] != 'o' ||
        parent_comm[2] != 'r' || parent_comm[3] != 'k' ||
        parent_comm[4] != 'i' || parent_comm[5] != 'n' ||
        parent_comm[6] != 'g' || parent_comm[7] != '\0')
        return 0;

    // Read the configuration
    __u32 cfg_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (!cfg)
        return 0;

    __u32 n = cfg->n_process;
    __u64 t = cfg->time_separation_ns;
    if (n == 0 || n > MAX_N)
        return 0;

    __u32 k;
    k = SLOT_HEAD;
    __u64 *p_head = bpf_map_lookup_elem(&window_map, &k);
    if (!p_head)
		return 0;
    __u32 head = (__u32)(*p_head);


    k = SLOT_COUNT;
    __u64 *p_count = bpf_map_lookup_elem(&window_map, &k);
    if (!p_count)
		return 0;
    __u32 count = (__u32)(*p_count);


    __u64 now = bpf_ktime_get_ns();
    // If the slicing-window doesn't store n timestamp
    if (count < n) {
        __u32 idx = SLOT_WIN + count;
        bpf_map_update_elem(&window_map, &idx, &now, BPF_ANY);
        __u64 new_count = count + 1;
        k = SLOT_COUNT;
        bpf_map_update_elem(&window_map, &k, &new_count, BPF_ANY);

        return 0;
    }

    // If the sliding-window contains n process, we have to compare with the oldest
    __u32 oldest_idx = SLOT_WIN + head;
    __u64 *p_oldest = bpf_map_lookup_elem(&window_map, &oldest_idx);
    if (!p_oldest)
        return 0;

    if (now - *p_oldest < t) {
        // Kill the child
        bpf_printk("process deleted, now - oldest = %llu ns\n", now - *p_oldest);
        bpf_send_signal(SIGKILL);
        return 0;
    }

    // Child is allowed to be created, it replaces the oldest
    bpf_map_update_elem(&window_map, &oldest_idx, &now, BPF_ANY);
    __u64 new_head = (head + 1) % n;
    k = SLOT_HEAD;
    bpf_map_update_elem(&window_map, &k, &new_head, BPF_ANY);

    return 0;
}