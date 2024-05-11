#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

#include "utils/libresolver.h"
#include "sniffer.skel.h"

#define __ATTACH_UPROBE(program_path, arg_func_name, ebpf_fn, is_retprobe)                              \
    do                                                                                                  \
    {                                                                                                   \
        LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, .func_name = arg_func_name, .retprobe = is_retprobe); \
        skel->links.ebpf_fn = bpf_program__attach_uprobe_opts(                                          \
            skel->progs.ebpf_fn,                                                                        \
            -1, program_path, 0, &uprobe_opts);                                                         \
        if (!skel->links.ebpf_fn)                                                                       \
        {                                                                                               \
            fprintf(stderr, "Failed to attach uprobe\n");                                               \
            return 1;                                                                                   \
        }                                                                                               \
    } while (0)

struct sniffer_bpf *skel;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static void int_exit(int sig)
{
    sniffer_bpf__destroy(skel);
    exit(0);
}

int load_bpf()
{
    int err;
    libbpf_set_print(libbpf_print_fn);
    skel = sniffer_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = sniffer_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);
    return 0;
}

int main()
{
    if (load_bpf() != 0)
    {
        return 1;
    }

    char found_path[MAX_PATH_LEN];
    char library_name[] = "libssl.so";
    if (global_search_library(library_name, found_path) != 0)
    {
        fprintf(stderr, "Failed to find library %s\n", library_name);
        return 1;
    }

    __ATTACH_UPROBE(found_path, "SSL_set_fd", probe_fd_attach_ssl, false);
    __ATTACH_UPROBE(found_path, "SSL_write", probe_ssl_rw_enter, false);
    __ATTACH_UPROBE(found_path, "SSL_write", probe_ssl_write_return, true);
    __ATTACH_UPROBE(found_path, "SSL_read", probe_ssl_rw_enter, false);
    __ATTACH_UPROBE(found_path, "SSL_read", probe_ssl_read_return, true);

    while (true)
    {
        sleep(1);
    }

    return 0;
}