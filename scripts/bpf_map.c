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
- BPF_MAP_GET_NEXT_ID
- BPF_MAP_GET_FD_BY_ID
- BPF_OBJ_GET_INFO_BY_FD
*/
int main(int argc, char **argv)
{
    struct input input = {
        .start_id = 0,
        .next_id = 0,
        .open_flags = 0
    };
    syscall(__NR_bpf, BPF_MAP_GET_NEXT_ID, &input, sizeof(input));
    printf("next_id: %d\n", input.next_id); // -1 if there's no next id

    return 0;   
}