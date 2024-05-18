#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include "ebpf/loader.h"
#include "utils/libresolver.h"

#define __ATTACH_SYS_LIBRARY(library_name, ebpf_fn)                                    \
    do                                                                                 \
    {                                                                                  \
        char library_path[MAX_PATH_LEN] = {0};                                         \
        if (global_search_library(library_name, library_path) == 0)                    \
        {                                                                              \
            if (ssl_attach_##ebpf_fn(library_path) != 0)                               \
            {                                                                          \
                fprintf(stderr, "Failed to attach %s probes\n", library_name);         \
                return 1;                                                              \
            }                                                                          \
            fprintf(stdout, "%s probes attached to %s\n", library_name, library_path); \
        }                                                                              \
    } while (0)

void exit_handler(int sig)
{
    fprintf(stdout, "Exiting...\n");
    ssl_exit();
    exit(0);
}

int main()
{
    if (ssl_open_load_attach() != 0)
    {
        return 1;
    }

    __ATTACH_SYS_LIBRARY("libssl.so", openssl);
    __ATTACH_SYS_LIBRARY("libgnutls.so", gnutls);
    __ATTACH_SYS_LIBRARY("libnspr4.so", nss);

    // Attach node
    char node_path[] = "/usr/local/bin/node";
    
    if (ssl_attach_openssl(node_path) != 0)
    {
        fprintf(stderr, "Failed to attach node probes\n");
        return 1;
    }

    signal(SIGINT, exit_handler);
    signal(SIGTERM, exit_handler);

    fprintf(stdout, "Press Ctrl+C to stop\n");

    if (ssl_listen_event() != 0)
    {
        fprintf(stderr, "Failed to listen event\n");
        return 1;
    }

    return 0;
}