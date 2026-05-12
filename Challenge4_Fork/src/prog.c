#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile int running = 1;

static void handle_sig(int sig)
{
    running = 0;
}

struct config {
    unsigned int  n_process;
    unsigned long long time_separation_ns;
};

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [--n_process <N>] [--time_separation_sec <T>]\n"
        "  --n_process           sliding-window size (default 1, max 32)\n"
        "  --time_separation_sec minimum gap in seconds (default 1)\n",
        prog);
}

int main(int argc, char **argv)
{
    // Default values
    unsigned int n_process          = 1;
    double       time_separation_sec = 1.0;

    static const struct option long_opts[] = {
        { "n_process",           required_argument, NULL, 'n' },
        { "time_separation_sec", required_argument, NULL, 't' },
        { "help",                no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'n':
            n_process = (unsigned int)atoi(optarg);
            if (n_process == 0 || n_process > 32) {
                usage(argv[0]);
                return 1;
            }
            break;
        case 't':
            time_separation_sec = atof(optarg);
            if (time_separation_sec < 0) {
                usage(argv[0]);
                return 1;
            }
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    unsigned long long time_separation_ns =
        (unsigned long long)(time_separation_sec * 1e9);

    printf("n_process=%u  time_separation=%.3fs (%llu ns)\n",
           n_process, time_separation_sec, time_separation_ns);

    // Open the BPF object file
    struct bpf_object *obj = bpf_object__open_file("prog.bpf.o", NULL);
    if (!obj) {
        perror("bpf_object__open_file");
        return 1;
    }

	// Load the BPF object file into the kernel
    int err = bpf_object__load(obj);
    if (err) {
        perror("bpf_object__load");
        bpf_object__close(obj);
        return 1;
    }

	// Find the registered map by name
    struct bpf_map *cfg_map =
        bpf_object__find_map_by_name(obj, "config_map");
    if (!cfg_map) {
        fprintf(stderr, "map 'config_map' not found\n");
        bpf_object__close(obj);
        return 1;
    }

	// Pass the receive configuration paramaters to the map
    struct config cfg = {
        .n_process          = n_process,
        .time_separation_ns = time_separation_ns,
    };
    unsigned int key = 0;
    if (bpf_map__update_elem(cfg_map, &key, sizeof(key), &cfg, sizeof(cfg), BPF_ANY) != 0) {
        perror("bpf_map_update_elem (config_map)");
        bpf_object__close(obj);
        return 1;
    }

    // Find the BPF fprogram by name
    struct bpf_program *prog =
        bpf_object__find_program_by_name(obj, "handle_hook");
    if (!prog) {
        fprintf(stderr, "program 'handle_hook' not found\n");
        bpf_object__close(obj);
        return 1;
    }

	// Attach the BPF program to the appropriate hook
    struct bpf_link *link = bpf_program__attach(prog);
    if (!link) {
        perror("bpf_program__attach");
        bpf_object__close(obj);
        return 1;
    }

    signal(SIGINT,  handle_sig);
    signal(SIGTERM, handle_sig);

    printf("Program loaded. Press Ctrl+C to exit.\n");
    while (running)
        sleep(1);

    // Cleanup
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
