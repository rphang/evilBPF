#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_link.h>
#include <signal.h>
#include <net/if.h>
#include <assert.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>

static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;

static int ifindex;
struct bpf_object *obj = NULL;

/* This function will remove XDP from the link when program exit */
static void int_exit(int sig)
{
	bpf_xdp_attach(ifindex, -1, xdp_flags, 0);
	bpf_object__close(obj);
	exit(0);
}

int main(int argc, char *argv[])
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	int ret, err;

	if (argc != 2) {
		printf("Usage: %s IFNAME\n", argv[0]);
		return 1;
	}

	ifindex = if_nametoindex(argv[1]);
	if (!ifindex) {
		printf("get ifindex from interface name failed\n");
		return 1;
	}

	struct rlimit rlim = {
		.rlim_cur = 512UL << 20,
		.rlim_max = 512UL << 20,
	};

	err = setrlimit(RLIMIT_MEMLOCK, &rlim);
	if (err) {
		fprintf(stderr, "failed to change rlimit\n");
		return 1;
	}
    
	/* load BPF object by libbpf */
	obj = bpf_object__open_file("icmp.bpf.o", NULL);
	if (libbpf_get_error(obj)) {
		printf("Error, load BPF object failed\n");
		return 1;
	}

	/* load BPF program from the object */
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, "icmp_prog_reply");
	if (!prog) {
		printf("Error, find BPF program failed\n");
		return 1;
	}
	bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);

	err = bpf_object__load(obj);
	if (err) {
		printf("Error, load BPF object failed\n");
		return 1;
	}

	/* attach BPF program to interface with XDP mode */
	ret = bpf_xdp_attach(ifindex, bpf_program__fd(prog), xdp_flags, 0);
	if (ret) {
		err = libbpf_get_error(prog);
		printf("Error, Set XDP fd on iface %d (%s): %d\n", ifindex, argv[1], err);
		return ret;
	}
	err = bpf_obj_get_info_by_fd( bpf_program__fd(prog), &info, &info_len);
	if (err) {
		printf("can't get prog info");
		return err;
	}

	

	/* Remove attached program when program is interrupted or killed */
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	printf("Program is running on interface %s (ifindex %d)\n", argv[1], ifindex);
    while (1)
    {
		sleep(3);
    }
    
	return 0;
}
