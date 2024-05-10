#ifndef LIBRESOLVER_H
#define LIBRESOLVER_H

#define MAX_PATH_LEN 256
#define MAX_DEPTH 2

int global_search_library(char *library_name, char *library_path);
int resolve_libraries(char *program_path, char *libraries[]);

int lookup_path(const char *path, char *library_name, char *library_path, int depth);

#endif