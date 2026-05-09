#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <time.h>

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <num_children> <interval_ms>\n", argv[0]);
        return 1;
    }
    int n = atoi(argv[1]);
    int interval_ms = atoi(argv[2]);
    double t0 = now_sec();

    for (int i = 0; i < n; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            _exit(0);
        } else if (pid > 0) {
            printf("[%6.3fs] forked child %d (pid=%d)\n",
                   now_sec() - t0, i, pid);
            fflush(stdout);
            usleep(interval_ms * 1000);
        } else {
            perror("fork");
            return 1;
        }
    }

    int killed = 0, alive = 0;
    while (1) {
        int status;
        pid_t pid = wait(&status);
        if (pid <= 0) break;
        if (WIFSIGNALED(status) && WTERMSIG(status) == 9) killed++;
        else alive++;
    }
    printf("done: %d survived, %d killed by SIGKILL\n", alive, killed);
    return 0;
}