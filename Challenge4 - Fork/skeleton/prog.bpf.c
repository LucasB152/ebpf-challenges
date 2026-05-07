// prog.bpf.c — Challenge 4: fork rate-limiting
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define COMM_LEN 16
#define MAX_N 32
#define MAX_N_MASK (MAX_N - 1)

struct params {
  __u32 n;
  __u64 t_ns;
  char target[COMM_LEN];
};

struct history {
  __u64 timestamps[MAX_N];
  __u32 next_idx;
  __u32 count;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct params);
  __uint(max_entries, 1);
} params_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, struct history);
  __uint(max_entries, 1024);
} history_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, __u8);
  __uint(max_entries, 4096);
} kill_list SEC(".maps");

SEC("tp_btf/sched_process_fork")
int BPF_PROG(handle_fork, struct task_struct *parent,
             struct task_struct *child) {
  __u32 key = 0;
  struct params *p = bpf_map_lookup_elem(&params_map, &key);
  if (!p)
    return 0;

  // Check that the parent matches our target comm
  char p_comm[COMM_LEN];
  BPF_CORE_READ_INTO(&p_comm, parent, comm);
  if (bpf_strncmp(p_comm, COMM_LEN, p->target) != 0)
    return 0;

  __u32 parent_pid = BPF_CORE_READ(parent, pid);
  __u32 child_pid = BPF_CORE_READ(child, pid);

  __u32 n = p->n;
  if (n == 0 || n > MAX_N)
    return 0;

  // Initialize the history for parent if not yet the case
  __u64 now = bpf_ktime_get_ns();
  struct history *h = bpf_map_lookup_elem(&history_map, &parent_pid);
  if (!h) {
    struct history nh = {};
    nh.timestamps[0] = now;
    nh.next_idx = 1 & MAX_N_MASK;
    nh.count = 1;
    bpf_map_update_elem(&history_map, &parent_pid, &nh, BPF_ANY);
    return 0;
  }

  if (h->count >= n) {
    __u32 oldest_idx = (h->next_idx + MAX_N - n) & MAX_N_MASK;
    __u64 old_ts = h->timestamps[oldest_idx];
    if (now - old_ts < p->t_ns) {
      // Mark child, as to be killed
      __u8 mark = 1;
      bpf_map_update_elem(&kill_list, &child_pid, &mark, BPF_ANY);
      bpf_printk("fork: kill child %u (parent %u, dt=%llu ns)\n", child_pid,
                 parent_pid, now - old_ts);
      return 0;
    }
  }

  // accept: append timestamp to ring buffer
  __u32 idx = h->next_idx & MAX_N_MASK;
  h->timestamps[idx] = now;
  h->next_idx = (idx + 1) & MAX_N_MASK;
  if (h->count < MAX_N)
    h->count++;

  return 0;
}

// On any syscall: if current PID is marked, kill it
SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(void *ctx) {
  __u32 pid = (__u32)bpf_get_current_pid_tgid();

  __u8 *mark = bpf_map_lookup_elem(&kill_list, &pid);
  if (!mark)
    return 0;

  bpf_map_delete_elem(&kill_list, &pid);
  bpf_send_signal(9);
  return 0;
}

// Cleanup exited process on each map if they exited
SEC("tp_btf/sched_process_exit")
int BPF_PROG(handle_exit, struct task_struct *task) {
  __u32 pid = BPF_CORE_READ(task, pid);
  bpf_map_delete_elem(&history_map, &pid);
  bpf_map_delete_elem(&kill_list, &pid);
  return 0;
}
