#ifndef __STRUCTS_BPF_H
#define __STRUCTS_BPF_H

#include "definition.h"

typedef enum {
    SSL_OP_WRITE = 0,
    SSL_OP_READ = 1
} ssl_op_t;

/**
 * @brief Chunk struct for passing data from kernel to user space, for each write/recv SSL operation.
 * 
 * @param pid Process ID
 * @param ts Timestamp
 * @param comm Command name
 * @param op Operation type
 * @param len Length of data
 * @param data Data
*/
struct chunk_event {
    __u64 key;
    int part;
    __u32 pid;
    __u64 ts;
    char comm[TASK_COMM_LEN];
    ssl_op_t op;
    int len;
    char data[MAX_DATA_LEN];
};

#endif