// hello.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";
const char scanner_name[] = "scanner";

SEC("lsm/file_open")
int BPF_PROG(handle_hook, struct file *file) {
  char task_name[16];
  bpf_get_current_comm(&task_name, sizeof(task_name));

  if (bpf_strncmp(task_name, 16, scanner_name) == 0 && file->f_mode & 0x2) {
    return -1;
  }

  return 0;
}
