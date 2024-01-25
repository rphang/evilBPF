#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>


#include "hidder.skel.h"

struct hidder_bpf *skel;

static void int_exit(int sig)
{
	hidder_bpf__destroy(skel);
	exit(0);
}

int main(int argc, char **argv)
{
    int err;

    skel = hidder_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    int my_pid = getpid();
    skel->rodata->target_pid = my_pid;

    char filename[] = "/etc/passwd";
    skel->rodata->filename_len = strlen(filename);
    strcpy(skel->rodata->filename, filename);

    char overwritten_content[] = "hello world";
    skel->rodata->overwritten_content_len = strlen(overwritten_content);
    strcpy(skel->rodata->overwritten_content, overwritten_content);

    err = hidder_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
    }

    err = hidder_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
    }

    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);
    printf("hidder_bpf loaded successfully.\n");
    printf("my pid: %d\n", my_pid);
    char buffer[1024];
    while (1) {
        sleep(2);
        int fd = open("/etc/passwd", O_RDONLY);
        read(fd, buffer, 1024);
        printf("read: %s\n", buffer);
        close(fd);
    }
    return 0;
}