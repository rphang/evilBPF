#ifndef __VMLINUX_H
#define __VMLINUX_H
#include <vmlinux.h>
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "ebpf/struct_bpf.h"
#include "ebpf/maps_bpf.h"

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
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u64); // buffer address
    __uint(max_entries, 1024);
} ptr_ssl_rw_buff SEC(".maps");

SEC("uprobe")
int recursive_chunks(struct pt_regs *ctx)
{
    u64 key = bpf_get_current_pid_tgid(); // PID + SMP processor ID (that should be unique enough)
    key = (key << 32) | bpf_get_smp_processor_id();
    struct chunk_processing *cp = bpf_map_lookup_elem(&chunk_processing_map, &key);
    if (!cp)
        return 0;

    // do we hit limits of tail calls?
    if (cp->loop_count > 30)
    {
        bpf_printk("recursive_chunks: Hit tail call limit\n");
        bpf_map_delete_elem(&chunk_processing_map, &key);
        return 0;
    }

    // Reserve rb
    struct data_event *event = bpf_ringbuf_reserve(&rb, sizeof(struct data_event), 0);
    if (!event)
    {
        bpf_printk("recursive_chunks: Failed to reserve ringbuf\n");
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
    bpf_probe_read_user(&event->comm, sizeof(event->comm), cp->comm);

    // Update the chunk processing struct
    cp->loop_count++;
    cp->len_left -= len;
    cp->offset += len;

    // Submit the event
    bpf_ringbuf_submit(event, 0);

    if (cp->len_left != 0)
    {
        bpf_tail_call(ctx, &tailcall_map, REC_CHUNK_RB_PROG);
    }
    else
    {
        bpf_map_delete_elem(&chunk_processing_map, &key);
    }
    return 0;
}

static __always_inline int handle_rw_exit(struct pt_regs *ctx, int is_write)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u64 *buf = bpf_map_lookup_elem(&ptr_ssl_rw_buff, &pid_tgid);
    if (!buf)
        return 0;

    int resp = PT_REGS_RC_CORE(ctx);
    if (resp <= 0)
        return 0;

    // Create the chunk processing struct
    struct chunk_processing cp = {0};
    cp.loop_count = 0;
    cp.pid = pid;
    cp.ts = bpf_ktime_get_ns();
    cp.op = is_write ? SSL_OP_WRITE : SSL_OP_READ;
    cp.len_left = resp;
    cp.buffer = *buf;
    cp.offset = 0;
    bpf_get_current_comm(&cp.comm, sizeof(cp.comm));

    // Store the chunk processing struct
    u64 key = bpf_get_current_pid_tgid(); // PID + SMP processor ID
    key = (key << 32) | bpf_get_smp_processor_id();
    bpf_map_update_elem(&chunk_processing_map, &key, &cp, 0);

    bpf_tail_call(ctx, &tailcall_map, REC_CHUNK_RB_PROG);
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

    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ptr_ssl_rw_buff, &pid_tgid, &buf, 0);
    return 0;
}

SEC("uprobe/ssl_read_return")
int probe_ssl_read_return(struct pt_regs *ctx)
{
    return (handle_rw_exit(ctx, 0));
}

SEC("uprobe/ssl_write_return")
int probe_ssl_write_return(struct pt_regs *ctx)
{
    return (handle_rw_exit(ctx, 1));
}

char _license[] SEC("license") = "GPL";