// hello.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";
const char scanner_name[] = "scanner";

SEC("lsm/file_open")
int BPF_PROG(handle_hook, struct file *file)
{
        char task_name[16];
        bpf_get_current_comm(&task_name, sizeof(task_name));

        // Le mode WRITING est representer par un 2 (voir la doc)
        if(bpf_strncmp(task_name, 16, scanner_name) == 0 && file->f_mode & 0x2){
                return -1;
        }

        return 0;
}

/* SOURCES :
 * - Setup LSM -> https://eunomia.dev/tutorials/19-lsm-connect/
 * - Doc des helpers LSM -> https://github.com/torvalds/linux/blob/457391b0380335d5e9a5babdec90ac53928b23b4/include/linux/lsm_hooks.h
 * - Liste des hooks LSM -> https://github.com/torvalds/linux/blob/457391b0380335d5e9a5babdec90ac53928b23b4/include/linux/lsm_hook_defs.h
 * - Document de la struct File -> https://elixir.bootlin.com/linux/v6.19.9/source/include/linux/fs.h
 * /