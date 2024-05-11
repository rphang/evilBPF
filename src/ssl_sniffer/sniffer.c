#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ebpf/entry.h"
#include "utils/libresolver.h"

int main()
{
    if (bpf_load() != 0)
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

    bpf_attach_openssl(found_path);

    while (1)
    {
        sleep(1);
    }

    return 0;
}