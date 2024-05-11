#ifndef BPF_ENTRY_H
#define BPF_ENTRY_H

int bpf_load();
int bpf_attach_openssl(char* program_path);

#endif