#ifndef BPF_ENTRY_H
#define BPF_ENTRY_H

int ssl_load();
int ssl_listen_event();
int ssl_attach_openssl(char* program_path);

#endif