#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static volatile int running = 1;

static void handle_sig(int sig) { running = 0; }

int main(void) {
  int err;

  // Open the BPF object file
  struct bpf_object *obj = bpf_object__open_file("prog.bpf.o", NULL);
  if (!obj) {
    perror("bpf_object__open_file");
    return 1;
  }

  // Load the BPF object file into the kernel
  err = bpf_object__load(obj);
  if (err) {
    perror("bpf_object__load");
    bpf_object__close(obj);
    return 1;
  }

  // Find the BPF program by name
  struct bpf_program *prog =
      bpf_object__find_program_by_name(obj, "handle_hook");
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

  printf("Program loaded. Press Ctrl+C to exit.\n");
  while (running)
    sleep(1);

  bpf_link__destroy(link); // detaches the program from the hook
  bpf_object__close(obj);  // unloads and frees the BPF object

  return 0;
}
