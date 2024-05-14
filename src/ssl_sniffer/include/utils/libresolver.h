#ifndef LIBRESOLVER_H
#define LIBRESOLVER_H

#define MAX_PATH_LEN 256
#define MAX_DEPTH 2

#ifdef __x86_64__
    #define ARCH 1
#elif __arm__    
    #define ARCH 2
#elif __i386__    
    #define ARCH 3
#elif __aarch64__
    #define ARCH 4
#else
    #define ARCH 0
#endif

int global_search_library(char *library_name, char *library_path);
int resolve_libraries(char *program_path, char *libraries[]);

static int lookup_path(const char *path, char *library_name, int strict, char *library_path, int depth);

#endif