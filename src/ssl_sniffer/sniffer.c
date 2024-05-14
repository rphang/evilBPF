#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ebpf/loader.h"
#include "utils/libresolver.h"

int main()
{
    if (ssl_load() != 0)
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

    if (ssl_attach_openssl(found_path) != 0)
    {
        fprintf(stderr, "Failed to attach openssl\n");
        return 1;
    }

    printf("Press Ctrl+C to stop\n");

    if (ssl_listen_event() != 0)
    {
        fprintf(stderr, "Failed to listen event\n");
        return 1;
    }

    return 0;
}