#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/bpf.h>

struct input {
    int start_id;
    int next_id;
    int open_flags;
};
/*
bpftool use
- BPF_PROG_GET_NEXT_ID (get next id) - return -1 if there's no next id
- BPF_PROG_GET_FD_BY_ID (create fd from id) - can be altered to never get access to the fd
- BPF_OBJ_GET_INFO_BY_FD (dump info ab obj, map, prog, link ,..)
*/
int main(int argc, char **argv)
{
    struct input input = {
        .start_id = 0,
        .next_id = 0,
        .open_flags = 0
    };
    syscall(__NR_bpf, BPF_PROG_GET_NEXT_ID, &input, sizeof(input));
    printf("next_id: %d\n", input.next_id); // -1 if there's no next id

    return 0;   
}