#ifndef __DEF_SSL_BPF_H
#define __DEF_SSL_BPF_H

/*
 * Chunk struct
 */

#define TASK_COMM_LEN 16
#define MAX_DATA_LEN 1064

/*
 * Chunk map
 */

#define BUFFER_ENTRY_SIZE 256*1024*10

/*
 * Tailcalls
 */

#define REC_CHUNK_RB_PROG 0

#endif