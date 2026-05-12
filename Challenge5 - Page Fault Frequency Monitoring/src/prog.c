// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "Monitor.h"

/*
 *  Monotonic clock helper
 */
static unsigned long long now_ns(void)
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return (unsigned long long)tp.tv_sec * 1000000000ULL
         + (unsigned long long)tp.tv_nsec;
}

/*
 *  Global state for lower-bound check
 */
static struct {
    unsigned long long deadline_ns;
    unsigned long long first_fault_timestamp;
    unsigned long long window_ns;
    unsigned long long write_idx_at_schedule;
    int                pid;
    int                state_fd;
} g;

static void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
    (void)ctx; (void)cpu; (void)size;
    struct pff_event *ev = data;

    if (ev->type == EVENT_TOO_HIGH) {
        printf("PFF too high for process with PID %d\n", ev->pid);
        fflush(stdout);
    } else if (ev->type == EVENT_SCHEDULE_CHECK) {
        // On garde la deadline la plus proche (première à expirer)
        if (g.deadline_ns == 0 || ev->deadline_ns < g.deadline_ns) {
            g.deadline_ns           = ev->deadline_ns;
            g.first_fault_timestamp = ev->first_fault_timestamp;
            g.window_ns             = ev->window_ns;
            g.pid                   = ev->pid;
            g.write_idx_at_schedule    = ev->write_idx;
        }
    }
}

static void handle_lost(void *ctx, int cpu, __u64 cnt)
{
    (void)ctx;
    fprintf(stderr, "Lost %llu events on CPU %d\n", cnt, cpu);
}

static volatile int running = 1;
static void handle_sig(int sig) { (void)sig; running = 0; }

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int err;

    // Default values
    __u32 upper_bound_freq_ms = 100;
    __u32 lower_bound_freq_ms = 10;
    __u32 time_window_ms      = 50;

    static struct option long_opts[] = {
        {"upper_bound_freq_ms", required_argument, 0, 'u'},
        {"lower_bound_freq_ms", required_argument, 0, 'l'},
        {"time_window_ms",      required_argument, 0, 't'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'u': upper_bound_freq_ms = (__u32)atoi(optarg); break;
        case 'l': lower_bound_freq_ms = (__u32)atoi(optarg); break;
        case 't': time_window_ms      = (__u32)atoi(optarg); break;
        default:
            fprintf(stderr, "Usage: %s [--upper_bound_freq_ms N] "
                    "[--lower_bound_freq_ms N] [--time_window_ms N]\n", argv[0]);
            return 1;
        }
    }

    printf("PFF monitor: lower=%u, upper=%u, window=%ums\n",
           lower_bound_freq_ms, upper_bound_freq_ms, time_window_ms);
    fflush(stdout);

    // Open and load the BPF object file
    obj = bpf_object__open_file("prog.bpf.o", NULL);
    if (!obj) {
        perror("bpf_object__open_file");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        perror("bpf_object__load");
        bpf_object__close(obj);
        return 1;
    }

    // Write config into config_map
    struct bpf_map *config_map = bpf_object__find_map_by_name(obj, "config_map");
    if (!config_map) {
        fprintf(stderr, "config_map not found\n");
        bpf_object__close(obj);
        return 1;
    }
    struct pff_config cfg = {
        .upper_bound_freq_ms = upper_bound_freq_ms,
        .lower_bound_freq_ms = lower_bound_freq_ms,
        .time_window_ms      = time_window_ms,
    };
    __u32 key = 0;
    bpf_map__update_elem(config_map, &key, sizeof(key), &cfg, sizeof(cfg), BPF_ANY);

    /* Find and attach the BPF program */
    prog = bpf_object__find_program_by_name(obj, "handle_hook");
    if (!prog) {
        fprintf(stderr, "program not found\n");
        bpf_object__close(obj);
        return 1;
    }

    link = bpf_program__attach(prog);
    if (!link) {
        perror("bpf_program__attach");
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_map *state_map = bpf_object__find_map_by_name(obj, "state_map");
    if (!state_map) {
        fprintf(stderr, "state_map not found\n");
        bpf_object__close(obj);
        return 1;
    }
    g.state_fd      = bpf_map__fd(state_map);

    // Open perf buffer
    int perf_map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (perf_map_fd < 0) {
        fprintf(stderr, "Failed to find perf BPF map: %s\n", strerror(errno));
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }

    struct perf_buffer *pb = perf_buffer__new(perf_map_fd, 8, handle_event, handle_lost, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer: %s\n", strerror(errno));
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }

    signal(SIGINT,  handle_sig);
    signal(SIGTERM, handle_sig);

    while (running) {
        // Compute poll timeout until next lower-bound check
        int timeout_ms;
        if (g.deadline_ns == 0) {
            timeout_ms = 100;
        } else {
            unsigned long long cur = now_ns();
            if (g.deadline_ns <= cur) {
                timeout_ms = 0;
            } else {
                unsigned long long diff_ms = (g.deadline_ns - cur) / 1000000ULL;
                timeout_ms = (diff_ms > 100) ? 100 : (int)diff_ms;
            }
        }

        // Poll: wakes up on event OR timeout
        err = perf_buffer__poll(pb, timeout_ms);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "perf_buffer__poll error: %d\n", err);
            break;
        }

        // Lower-bound check if deadline has passed
        if (g.deadline_ns != 0 && now_ns() >= g.deadline_ns) {
            // Verify if there is at least 1 window passed since the first page
            if (now_ns() >= g.first_fault_timestamp + g.window_ns) {
                struct pff_state st;
                __u32 key = 0;
                if (bpf_map_lookup_elem(g.state_fd, &key, &st) == 0) {
                    // If there is no new page fault since the schedule, this means that the number of page fault in the window is below the lower bound
                    if (st.write_idx == g.write_idx_at_schedule) {
                        printf("PFF too low for process with PID %d\n", g.pid);
                        fflush(stdout);
                    }
                }
            }
            g.deadline_ns = 0;
        }
    }

    // Cleanup
    perf_buffer__free(pb);
    bpf_link__destroy(link);
    bpf_object__close(obj);

    return 0;
}