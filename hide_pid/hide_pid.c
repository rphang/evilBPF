#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>

#include "hider.skel.h"

struct hider_bpf *skel;

void cleanup(int sig)
{
    printf("Detaching...\n");
    hider_bpf__destroy(skel);
    exit(0);
}

int main(int argc, char *argv[])
{
    int err;

    skel = hider_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = hider_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        return 1;
    }

    err = hider_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        return 1;
    }

    printf("Successfully started!\n");

    // Wait for Ctrl-C
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    pause();
}
