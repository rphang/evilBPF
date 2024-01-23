#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("tp/syscalls/sys_enter_getdents64")
int hide_pid(struct trace_event_raw_sys_enter *ctx)
{
    return 0;
}