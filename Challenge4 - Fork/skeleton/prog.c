#include <bpf/libbpf.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define COMM_LEN 16

struct params {
  unsigned int n;
  unsigned long long t_ns;
  char target[COMM_LEN];
};

static volatile int running = 1;
static void handle_sig(int sig) { running = 0; }

static void usage(const char *prog) {
  fprintf(stderr,
          "Usage: %s --n_process <N> --time_separation_sec <T> "
          "<target_parent_comm>\n"
          "  --n_process            window size (1..32)\n"
          "  --time_separation_sec  threshold in seconds (e.g. 1.0)\n",
          prog);
}

int main(int argc, char **argv) {
  struct params cfg = {0};
  double t_sec = 0.0;
  int got_n = 0, got_t = 0;

  static const struct option opts[] = {
      {"n_process", required_argument, 0, 'n'},
      {"time_separation_sec", required_argument, 0, 't'},
      {"help", no_argument, 0, 'h'},
      {0, 0, 0, 0},
  };

  int c;
  while ((c = getopt_long(argc, argv, "n:t:h", opts, NULL)) != -1) {
    switch (c) {
    case 'n':
      cfg.n = (unsigned int)atoi(optarg);
      got_n = 1;
      break;
    case 't':
      t_sec = atof(optarg);
      got_t = 1;
      break;
    case 'h':
      usage(argv[0]);
      return 0;
    default:
      usage(argv[0]);
      return 1;
    }
  }

  if (!got_n || !got_t || optind >= argc) {
    usage(argv[0]);
    return 1;
  }

  cfg.t_ns = (unsigned long long)(t_sec * 1e9);
  strncpy(cfg.target, argv[optind], COMM_LEN - 1);
  cfg.target[COMM_LEN - 1] = '\0';

  // Open and load BPF object
  struct bpf_object *obj = bpf_object__open_file("prog.bpf.o", NULL);
  if (!obj) {
    perror("bpf_object__open_file");
    return 1;
  }

  if (bpf_object__load(obj)) {
    perror("bpf_object__load");
    bpf_object__close(obj);
    return 1;
  }

  // Push parameters into params_map
  struct bpf_map *map = bpf_object__find_map_by_name(obj, "params_map");
  if (!map) {
    fprintf(stderr, "params_map not found\n");
    bpf_object__close(obj);
    return 1;
  }
  __u32 key = 0;
  if (bpf_map__update_elem(map, &key, sizeof(key), &cfg, sizeof(cfg),
                           BPF_ANY)) {
    perror("bpf_map__update_elem");
    bpf_object__close(obj);
    return 1;
  }

  // Attach all programs in the object (handle_fork, handle_sys_enter,
  // handle_exit)
  struct bpf_program *prog;
  bpf_object__for_each_program(prog, obj) {
    struct bpf_link *link = bpf_program__attach(prog);
    if (!link) {
      fprintf(stderr, "attach failed for %s\n", bpf_program__name(prog));
      bpf_object__close(obj);
      return 1;
    }
  }

  signal(SIGINT, handle_sig);
  signal(SIGTERM, handle_sig);

  printf("Fork limiter active: n=%u, t=%.3fs, target=\"%s\". Ctrl+C to exit.\n",
         cfg.n, t_sec, cfg.target);

  while (running)
    sleep(1);

  bpf_object__close(obj);
  return 0;
}
