#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define bpf_printk(fmt, ...)                            \
({                                                      \
        char ____fmt[] = fmt;                           \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

SEC("tp/syscalls/sys_enter_getdents64")
int hide_pid(struct trace_event_raw_sys_enter *ctx)
{
    struct linux_dirent64 *dirp = (struct linux_dirent64 *)ctx->args[1];
    int pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == NULL)
    {
        return 0;
    }
    bpf_printk("Calling pid: %d", pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";