#ifndef __VMLINUX_H
#define __VMLINUX_H
#include <vmlinux.h>
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "ebpf/chunks.h"
#include "ebpf/ssl.h"
#include "ebpf/maps_bpf.h"
#include "ebpf/fd.h"

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

#define min(x, y)                      \
    ({                                 \
        typeof(x) _min1 = (x);         \
        typeof(y) _min2 = (y);         \
        (void)(&_min1 == &_min2);      \
        _min1 < _min2 ? _min1 : _min2; \
    })

// Chunk processing storage map
struct chunk_processing
{
    int loop_count;
    u32 pid;
    u64 ts;
    ssl_op_t op;
    char comm[TASK_COMM_LEN];
    size_t len_left;
    u64 buffer;
    u64 offset;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct chunk_processing);
    __uint(max_entries, 1024);
} chunk_processing_map SEC(".maps");

// Lookup maps
struct rw_event
{
    u64 buff;
    u64 len;
    void *SSL_PTR;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct rw_event);
    __uint(max_entries, 1024);
} ptr_ssl_rw_buff SEC(".maps");

/*
 * Kernel tracing for FDs
 */
SEC("tp/syscalls/sys_enter_accept")
int accept_entrypoint(struct trace_event_raw_sys_enter *ctx)
{
    u64 pidtgid = bpf_get_current_pid_tgid();
    u64 key = pidtgid << 32; // doesn't matter much we care about the return value
}

SEC("tp/syscalls/sys_enter_connect")
int connect_entrypoint(struct trace_event_raw_sys_enter *ctx)
{
    u64 pidtgid = bpf_get_current_pid_tgid();
    u64 key = pidtgid << 32 | ctx->args[0];
    int sockfd = ctx->args[0];
    if (sockfd != SOCK_DGRAM && sockfd != SOCK_STREAM && sockfd != SOCK_SEQPACKET && sockfd != SOCK_RAW && sockfd != SOCK_RDM && sockfd != SOCK_PACKET)
    {
        return 0;
    }

    struct sockaddr sa = {};
    bpf_core_read_user(&sa, sizeof(sa), (void *)ctx->args[1]);

    if (sa.sa_family != AF_INET && sa.sa_family != AF_INET6)
    {
        // Only interested in IPv4 and IPv6 (not UNIX sockets yet)
        return 0;
    }
    struct fd_event event = {0};
    event.type = FD_TYPE_CONNECT;
    event.ts = bpf_ktime_get_ns();
    event.pidtgid = key;
    event.con_type = sockfd;
    event.family = sa.sa_family;

    unsigned short int port = 0;
    if (sa.sa_family == AF_INET)
    {
        struct sockaddr_in sa4 = {};
        bpf_core_read_user(&sa4, sizeof(sa4), (void *)ctx->args[1]);
        unsigned char *dst = (unsigned char *)&sa4.sin_addr.s_addr;
        port = bpf_ntohs(sa4.sin_port);
        event.port = port;
        for (int i = 0; i < 4; i++)
        {
            event.dst_ipv4[i] = dst[i];
        }
    }
    else if (sa.sa_family == AF_INET6)
    {
        struct sockaddr_in6 sa6 = {};
        bpf_core_read_user(&sa6, sizeof(sa6), (void *)ctx->args[1]);
        unsigned short int *dst = (unsigned short int *)(&sa6.sin6_addr);
        port = bpf_ntohs(sa6.sin6_port);
        event.port = port;
        for (int i = 0; i < 8; i++)
        {
            event.dst_ipv6[i] = dst[i];
        }
    }

    bpf_map_update_elem(&fd_events_maps, &key, &event, 0);
    return 0;
}

/*
 * @brief Recursive function to process and send chunks of SSL data to user space
 *
 * @param ctx BPF context
 * @return int 0
 */
SEC("uprobe")
int recursive_chunks(struct pt_regs *ctx)
{
    u64 ptid = bpf_get_current_pid_tgid();
    u64 key = ptid; // PID + SMP processor ID (that should be unique enough... i was wrong.)
    key = (key << 32) | bpf_get_smp_processor_id();
    struct chunk_processing *cp = bpf_map_lookup_elem(&chunk_processing_map, &key);
    if (!cp)
        return 0;

    // Reserve rb
    struct chunk_event *event = bpf_ringbuf_reserve(&rb, sizeof(struct chunk_event), 0);
    if (!event)
    {
        bpf_printk("recursive_chunks: Failed to reserve ringbuf\n");
        bpf_map_delete_elem(&ptr_ssl_rw_buff, &ptid);
        bpf_map_delete_elem(&chunk_processing_map, &key);
        return 0;
    }
    // Read the chunk
    size_t len = min((size_t)cp->len_left, (size_t)MAX_DATA_LEN);
    bpf_probe_read_user(&event->data, len, (void *)(cp->buffer + cp->offset));

    // Copy data
    event->key = key;
    event->part = cp->loop_count;
    event->pid = cp->pid;
    event->ts = cp->ts;
    event->op = cp->op;
    event->len = len;
    bpf_probe_read_kernel_str(&event->comm, sizeof(event->comm), &cp->comm);

    // Update the chunk processing struct
    cp->loop_count++;
    cp->len_left -= len;
    cp->offset += len;

    // Submit the event
    bpf_ringbuf_submit(event, 0);

    // did we hit limits of tail calls?
    if (cp->loop_count >= 32)
    {
        bpf_printk("recursive_chunks: Hit tail call limit\n");
        bpf_map_delete_elem(&ptr_ssl_rw_buff, &ptid);
        bpf_map_delete_elem(&chunk_processing_map, &key);
        return 0;
    }

    if (cp->len_left != 0)
    {
        bpf_tail_call(ctx, &tailcall_map, REC_CHUNK_RB_PROG);
    }
    else
    {
        bpf_map_delete_elem(&ptr_ssl_rw_buff, &ptid); // TODO: wtf not working? we have a memleak here
        bpf_map_delete_elem(&chunk_processing_map, &key);
    }
    return 0;
}

static __always_inline int handle_rw_exit(struct pt_regs *ctx, int is_write)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    struct rw_event *event = bpf_map_lookup_elem(&ptr_ssl_rw_buff, &pid_tgid);
    if (!event)
        return 0;

    size_t len_struct = 0;
    bpf_probe_read_user(&len_struct, sizeof(size_t), (void *)(event->len));

    int resp = PT_REGS_RC_CORE(ctx);
    if (resp <= 0)
        return 0;

    if (len_struct == 0)
    {
        len_struct = resp;
    }

    // We got everything except the fd
    int *fd = bpf_map_lookup_elem(&ssl_to_fd, &event->SSL_PTR);
    if (fd)
    {
        u64 fd_key = pid_tgid << 32 | *fd;
        bpf_printk("handle_rw_exit: Found fd %d\n", *fd);
        struct fd_event *connect_event = bpf_map_lookup_elem(&fd_events_maps, &fd_key);
        if (connect_event)
        {
            if (connect_event->type == FD_TYPE_CONNECT)
            {
                bpf_printk("handle_rw_exit: (Outgoing) Found connect event\n");
            }
            else if (connect_event->type == FD_TYPE_ACCEPT)
            {
                bpf_printk("handle_rw_exit: (Incoming) Found accept event\n");
            }
            if (connect_event->family == AF_INET)
            {
                bpf_printk("dst IP: %d.%d.%d.X\n", connect_event->dst_ipv4[0], connect_event->dst_ipv4[1], connect_event->dst_ipv4[2]);
            }
            else if (connect_event->family == AF_INET6)
            {
                bpf_printk("dst IP: %x:%x:%x:...\n", bpf_ntohs(connect_event->dst_ipv6[0]), bpf_ntohs(connect_event->dst_ipv6[1]), bpf_ntohs(connect_event->dst_ipv6[2]));
            }
            bpf_printk("dst Port: %d", connect_event->port);
        }
    }

    u64 *buf = &event->buff;
    // Create the chunk processing struct
    struct chunk_processing cp = {0};
    cp.loop_count = 0;
    cp.pid = pid;
    cp.ts = bpf_ktime_get_ns();
    cp.op = is_write ? SSL_OP_WRITE : SSL_OP_READ;
    cp.len_left = len_struct;
    cp.buffer = *buf;
    cp.offset = 0;
    bpf_get_current_comm(&cp.comm, sizeof(cp.comm));

    // Store the chunk processing struct
    u64 key = pid_tgid;
    key = (key << 32) | bpf_get_smp_processor_id();
    bpf_map_update_elem(&chunk_processing_map, &key, &cp, 0);

    bpf_tail_call(ctx, &tailcall_map, REC_CHUNK_RB_PROG);
    return 0;
}

SEC("uprobe")
int probe_ssl_rw_enter(struct pt_regs *ctx)
{
    u64 SSL_ST = PT_REGS_PARM1_CORE(ctx);
    u64 buf = PT_REGS_PARM2_CORE(ctx);
    if (!buf || !SSL_ST)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct rw_event rw = {0};
    rw.buff = buf;
    rw.SSL_PTR = (void *)SSL_ST;
    bpf_map_update_elem(&ptr_ssl_rw_buff, &pid_tgid, &rw, 0);
    return 0;
}

SEC("uprobe")
int probe_ex_ssl_rw_enter(struct pt_regs *ctx)
{
    u64 SSL_ST = PT_REGS_PARM1_CORE(ctx);
    u64 buf = PT_REGS_PARM2_CORE(ctx);
    u64 len = PT_REGS_PARM4_CORE(ctx);
    if (!buf || !len || !SSL_ST)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct rw_event rw = {0};
    rw.buff = buf;
    rw.len = len;
    rw.SSL_PTR = (void *)SSL_ST;
    bpf_map_update_elem(&ptr_ssl_rw_buff, &pid_tgid, &rw, 0);
    return 0;
}

SEC("uprobe")
int probe_ssl_read_return(struct pt_regs *ctx)
{
    return (handle_rw_exit(ctx, 0));
}

SEC("uprobe")
int probe_ssl_write_return(struct pt_regs *ctx)
{
    return (handle_rw_exit(ctx, 1));
}

/*
 * OpenSSL specific probes
 */
SEC("uprobe")
int probe_ssl_set_fd(struct pt_regs *ctx)
{
    u64 SSL_ST = PT_REGS_PARM1_CORE(ctx);
    int fd = PT_REGS_PARM2_CORE(ctx);
    if (!SSL_ST || fd < 0)
        return 0;

    bpf_map_update_elem(&ssl_to_fd, &SSL_ST, &fd, 0);
    return 0;
}

SEC("uprobe")
int wtf(struct pt_regs *ctx)
{
    bpf_printk("wtf\n");
    return 0;
}

char _license[] SEC("license") = "GPL";