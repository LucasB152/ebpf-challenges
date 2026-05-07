#include <bpf/libbpf.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define COMM_LEN 16

struct config {
  unsigned int shift;
  char target[COMM_LEN];
};

static volatile int running = 1;

static void handle_sig(int sig) { running = 0; }

static void usage(const char *prog) {
  fprintf(stderr,
          "Usage: %s [--shift <N>] <target_process_name>\n"
          "  --shift   Caesar shift; any int (negative ok), normalized to [0,25] (default: 3)\n",
          prog);
}

int main(int argc, char **argv) {
  struct config cfg = {0};
  int raw_shift = 3; // default

  static const struct option opts[] = {
      {"shift", required_argument, 0, 's'},
      {"help",  no_argument,       0, 'h'},
      {0, 0, 0, 0},
  };

  int c;
  while ((c = getopt_long(argc, argv, "s:h", opts, NULL)) != -1) {
    switch (c) {
    case 's':
      raw_shift = atoi(optarg);
      break;
    case 'h':
      usage(argv[0]);
      return 0;
    default:
      usage(argv[0]);
      return 1;
    }
  }

  // Positional argument: target process name
  if (optind >= argc) {
    usage(argv[0]);
    return 1;
  }
  const char *target = argv[optind];

  cfg.shift = (unsigned int)(((raw_shift % 26) + 26) % 26);
  strncpy(cfg.target, target, COMM_LEN - 1);
  cfg.target[COMM_LEN - 1] = '\0';

  // Open the BPF object file
  struct bpf_object *obj = bpf_object__open_file("prog.bpf.o", NULL);
  if (!obj) {
    perror("bpf_object__open_file");
    return 1;
  }

  // Load the BPF object file into the kernel
  if (bpf_object__load(obj)) {
    perror("bpf_object__load");
    bpf_object__close(obj);
    return 1;
  }

  // Dinf the registered map by name
  struct bpf_map *map = bpf_object__find_map_by_name(obj, "config_map");
  if (!map) {
    fprintf(stderr, "config_map not found\n");
    bpf_object__close(obj);
    return 1;
  }

  // Pass the receive Encryption prameters to the map
  __u32 key = 0;
  if (bpf_map__update_elem(map, &key, sizeof(key), &cfg, sizeof(cfg),
                           BPF_ANY)) {
    perror("bpf_map__update_elem");
    bpf_object__close(obj);
    return 1;
  }

  // Find the BPF fprogram by name
  struct bpf_program *prog =
      bpf_object__find_program_by_name(obj, "handle_write");
  if (!prog) {
    fprintf(stderr, "program not found\n");
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

  signal(SIGINT, handle_sig);
  signal(SIGTERM, handle_sig);

  printf("Ciphered write active: shift=%d, target=\"%s\". Ctrl+C to exit.\n",
         cfg.shift, cfg.target);

  while (running)
    sleep(1);

  // Cleanup
  bpf_link__destroy(link);
  bpf_object__close(obj);
  return 0;
}
