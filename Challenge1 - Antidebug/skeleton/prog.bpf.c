// hello.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

SEC("uprobe//home/student/projet2/challenge1/hangman/hangman:main")
int BPF_UPROBE(handle_hook)
{
    // https://docs.ebpf.io/linux/helper-function/bpf_get_current_task/
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    // Comme on veut accéder à des données dans le kernel, on doit utiliser une macro spéciale.
    // https://docs.ebpf.io/ebpf-library/libbpf/ebpf/BPF_CORE_READ/
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);

    char parent_comm[16];
    // Idem que la macro (la macro ne fonctionne pas pour les tableaux).
    // https://docs.ebpf.io/linux/helper-function/bpf_probe_read_kernel/
    bpf_probe_read_kernel(&parent_comm, sizeof(parent_comm), &parent->comm);

    if (parent_comm[0] == 'g' && parent_comm[1] == 'd' && parent_comm[2] == 'b') {
        bpf_printk("Anti-Debug activated\n");
        bpf_send_signal(9);
    }

    return 0;
}