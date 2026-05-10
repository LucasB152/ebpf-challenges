// prog.bpf.c — Challenge 3: Caesar-cipher write
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_BUF 256
#define COMM_LEN 16

struct config {
  __u32 shift;
  char target[COMM_LEN];
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct config);
  __uint(max_entries, 1);
} config_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_write")
int handle_hook(struct trace_event_raw_sys_enter *ctx) {
  __u32 key = 0;
  struct config *cfg = bpf_map_lookup_elem(&config_map, &key);
  if (!cfg)
    return 0;

  char comm[COMM_LEN];
  bpf_get_current_comm(&comm, sizeof(comm));
  if (bpf_strncmp(comm, COMM_LEN, cfg->target) != 0)
    return 0;

  __u32 shift = cfg->shift;
  if (shift == 0)
    return 0;

  int fd = (int)ctx->args[0];
  if (fd <= 2)
    return 0

  char *buf = (char *)ctx->args[1];
  size_t count = (size_t)ctx->args[2];
  if (count > MAX_BUF)
    count = MAX_BUF;

  for (int i = 0; i < MAX_BUF; i++) {
    if (i >= (int)count)
      break;

    char c;
    if (bpf_probe_read_user(&c, 1, buf + i) != 0)
      break;

    char out;
    if (c >= 'a' && c <= 'z') {
      out = 'a' + ((c - 'a' + shift) % 26);
    } else if (c >= 'A' && c <= 'Z') {
      out = 'A' + ((c - 'A' + shift) % 26);
    } else {
      continue;
    }

    bpf_probe_write_user(buf + i, &out, 1);
  }

  return 0;
}
