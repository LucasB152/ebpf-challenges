#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <file> <message>\n", argv[0]);
        return 1;
    }

    int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    size_t len = strlen(argv[2]);
    if (write(fd, argv[2], len) != (ssize_t)len) {
        perror("write");
        close(fd);
        return 1;
    }

    close(fd);
    printf("wrote %zu bytes to %s\n", len, argv[1]);
    return 0;
}