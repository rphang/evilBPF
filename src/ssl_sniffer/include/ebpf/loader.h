#ifndef BPF_ENTRY_H
#define BPF_ENTRY_H

int ssl_load();
void ssl_exit(); 
int ssl_listen_event();

int ssl_attach_openssl(char* program_path);
int ssl_attach_gnutls(char* program_path);
int ssl_attach_nss(char* program_path);

#endif