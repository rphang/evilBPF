#define _GNU_SOURCE
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <errno.h>
#include <linux/fcntl.h>

int simulated_size(struct dirent64 *dirp) {
    int size = 0;
    size += sizeof(dirp->d_ino);
    size += sizeof(dirp->d_off);
    size += sizeof(dirp->d_reclen);
    size += sizeof(dirp->d_type);
    size += strlen(dirp->d_name);
    size += sizeof(char);
    return size;
}

int loop_dirent(char * buf, int nread) {
    struct dirent64 *dirp;
    int bpos = 0;
    int anomaly = 0;
    for (bpos = 0; bpos < nread;) {
        dirp = (struct dirent64 *) (buf + bpos);
        int o = simulated_size(dirp);
        if (o != dirp->d_reclen && (o - dirp->d_reclen) < -19) { // dirent struct without name (yeah it's magic)
            anomaly++;
            printf("- Anomaly between %d (%s) and %d (%s)\n",
             bpos, 
             dirp->d_name, 
             dirp->d_reclen, 
             ((struct dirent64 *) (buf + bpos + dirp->d_reclen))->d_name
            );
        }
        bpos += dirp->d_reclen;
        if (dirp->d_reclen == 0) {
            break;
        }
    }
    if (bpos != nread) {
        anomaly++;
        printf("- Anomaly in buffer size: %d != %d\n", bpos, nread);
    }
    return anomaly;
}

int check_getdents(char *path, int new, char *buf) {
    int fd, nread, anomaly;
    
    fd = syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_DIRECTORY);
    if (new) {
        nread = syscall(__NR_getdents64, fd, buf, 32768);
    } else {
        nread = syscall(__NR_getdents, fd, buf, 32768);
    }
    anomaly = loop_dirent(buf, nread);
    syscall(__NR_close, fd);
    return anomaly;
}

int check_path(char *path) {
    int bad = 0;
    int anomaly1, anomaly2;
    char buf[32768];
    char buf2[32768];

    printf("getdents:\n");
    anomaly1 = check_getdents(path, 0, buf);
    printf("getdents64:\n");
    anomaly2 = check_getdents(path, 1, buf2);
    bad = anomaly1 + anomaly2;
    printf("\n");

    if (anomaly1 != anomaly2) {
        printf("Sanity check failed:\n");
        printf("- Anomaly between getdents and getdents64 (we might be able to disclose more files)\n");
    }
    
    return bad;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <path>\n", argv[0]);
        return 1;
    }

    int bad = check_path(argv[1]);
    if (bad == 0) {
        printf("(%s) is clean!\n", argv[1]);
        return 0;
    }
    
    printf("\n\nTotal anomalies: %d\n", bad);
    printf("(%s) is hidding some stuff !\n", argv[1]);

    return 0;
}