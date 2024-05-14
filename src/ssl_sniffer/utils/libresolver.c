#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>

#include "utils/libresolver.h"

const char *COMMON_PATHS[] = {
    "/lib/",
    "/lib64/",
    "/lib32/",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/lib32/",
    "/usr/local/lib/",
};

/**
 * @brief Search for the library in the system recursively
 *
 * @param library_name The name of the library to search for (e.g. libssl.so)
 * @param library_path Buffer to store the path of the library
 *
 * @return int 0 if the library is found, -1 otherwise
 */
int global_search_library(char *library_name, char *library_path)
{

    // Search for the library in the system (we'll look into common paths)
    for (int i = 0; i < 7; i++)
    {
        int success = lookup_path(COMMON_PATHS[i], library_name, 0, library_path, 0);
        if (success == 0)
        {
            return 0;
        }
    }
    return -1;
}

/**
 * @brief Resolve all the libraries for the program
 *
 * @param program_path The path of the program
 * @param libraries The array to store the paths of the libraries
 *
 * @return int 0 if all the libraries are resolved, -1 otherwise
 */
int resolve_libraries(char *program_path, char *libraries[])
{
    // get ELF to get the list of libraries

    return -1;
}

/**
 * @brief Lookup for the library in the given path
 *
 * @param path The path to search for the library (e.g. /lib/)
 * @param library_name The name of the library to search for (e.g. libssl.so)
 * @param strict Flag to indicate if the search should be strict (i.e. the library name should match exactly or we look for versioned libraries)
 * @param library_path Buffer to store the path of the library
 * @param depth The depth of the search
 *
 * @return int 0 if the library is found, -1 otherwise
 */
static int lookup_path(const char *path, char *library_name, int strict, char *library_path, int depth)
{
    // Check if the depth is greater than the maximum depth
    if (depth > MAX_DEPTH)
        return -1;

    // is folder exists
    if (access(path, F_OK) == -1)
        return -1;

    // Create the full path of the library
    char full_path[MAX_PATH_LEN];
    memset(full_path, 0, MAX_PATH_LEN);
    snprintf(full_path, MAX_PATH_LEN, "%s%s", path, library_name);
    // Check if the library exists
    if (access(full_path, F_OK) != -1)
    {
        memcpy(library_path, full_path, MAX_PATH_LEN);
        return 0;
    }

    DIR *dir = opendir(path);
    // Search for the library in the subdirectories or the current directory if we are not strict
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        if (entry->d_type == DT_DIR)
        {
            if ((entry->d_name[0] == '.' && entry->d_name[1] == '\0') || (entry->d_name[0] == '.' && entry->d_name[1] == '.' && entry->d_name[2] == '\0'))
            {
                continue;
            }

            // Checking system arch to avoid searching in wrong directories (might be a dumb approach)
            if (strstr(entry->d_name, "linux") != NULL)
            {
                if (ARCH == 1 && strstr(entry->d_name, "x86_64") == 0)
                {
                    continue;
                }
                else if (ARCH == 2 && strstr(entry->d_name, "arm") == 0)
                {
                    continue;
                }
                else if (ARCH == 3 && strstr(entry->d_name, "i386") == 0)
                {
                    continue;
                }
                else if (ARCH == 4 && strstr(entry->d_name, "aarch64") == 0)
                {
                    continue;
                }
            }

            char new_path[MAX_PATH_LEN];
            snprintf(new_path, MAX_PATH_LEN, "%s%s/", path, entry->d_name);
            int success = lookup_path(new_path, library_name, strict, library_path, depth + 1);
            if (success == 0)
            {
                closedir(dir);
                return 0;
            }
        }
        if (!strict)
        {
            // Ignore if it's not a regular file or a symbolic link
            if (entry->d_type != DT_REG && entry->d_type != DT_LNK)
            {
                continue;
            }

            // Checking if the entry name start with the library name
            // Note: This is a naive approach, but for simplicity and my own sanity, I'm not going to think harder for now
            if (strncmp(entry->d_name, library_name, strlen(library_name)) == 0)
            {
                char full_path[MAX_PATH_LEN];
                memset(full_path, 0, MAX_PATH_LEN);
                snprintf(full_path, MAX_PATH_LEN, "%s%s", path, entry->d_name);
                memcpy(library_path, full_path, MAX_PATH_LEN);
                return 0;
            }
        }
    }
    closedir(dir);
    return -1;
}