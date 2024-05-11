#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define logprefix "ssl_sniffer: "
#ifdef bpf_printk
#undef bpf_printk
#define bpf_printk(fmt, ...)                       \
    ({                                             \
        char ____fmt[] = logprefix fmt;            \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })
#endif

// Internal maps (mostly for ptr tracking)

// FD <-> SSL CTX (TODO: Look into this)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, void *);
    __uint(max_entries, 1024);
} fd_to_ssl_ctx SEC(".maps");


// Lookup maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32); // pid_tgid
    __type(value, u64); // buffer address
    __uint(max_entries, 1024);
} ptr_ssl_rw_buff SEC(".maps");

static __always_inline int handle_rw_exit(struct pt_regs *ctx, int is_write)
{
    int pid_tgid = bpf_get_current_pid_tgid();
    u64 *buf = bpf_map_lookup_elem(&ptr_ssl_rw_buff, &pid_tgid);
    if (!buf)
        return 0;
    
    int resp = PT_REGS_RC_CORE(ctx);
    if (resp <= 0)
        return 0;

    // read the buffer
    char data[256];
    bpf_core_read(data, 256, (char *)*buf);
    bpf_printk("(%d) %s\n", resp, data);
    
    return 0;
}

SEC("uprobe/fd_attach_ssl")
int probe_fd_attach_ssl(struct pt_regs *ctx)
{
    bpf_printk("fd_attach_ssl\n");
    return 0;
}

SEC("uprobe/ssl_rw_enter")
int probe_ssl_rw_enter(struct pt_regs *ctx)
{
    u64 buf = PT_REGS_PARM2_CORE(ctx);
    if (!buf)
        return 0;
    
    bpf_printk("ssl_rw_enter\n");
    int pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ptr_ssl_rw_buff, &pid_tgid, &buf, 0);
    return 0;
}

SEC("uprobe/ssl_read_return")
int probe_ssl_read_return(struct pt_regs *ctx)
{
    bpf_printk("SSL Read:\n");
    return (handle_rw_exit(ctx, 0));
}

SEC("uprobe/ssl_write_return")
int probe_ssl_write_return(struct pt_regs *ctx)
{
    bpf_printk("SSL Write:\n");
    return (handle_rw_exit(ctx, 1));
}

char _license[] SEC("license") = "GPL";