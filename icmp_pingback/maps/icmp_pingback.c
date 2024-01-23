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
#include "icmp.skel.h"

static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;

static int ifindex;
struct icmp_bpf *obj = NULL;

/* This function will remove XDP from the link when program exit */
static void int_exit(int sig)
{
	bpf_xdp_attach(ifindex, -1, xdp_flags, 0);
	icmp_bpf__destroy(obj);
	exit(0);
}

static void update_flag(int value)
{
	int key = 0;
	int mapfd = bpf_map__fd(obj->maps.icmp_settings);
	int err = bpf_map_update_elem(mapfd, &key, &value, BPF_ANY);
	if (err) {
		printf("Error, update flag failed\n");
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	int err;

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
	obj = icmp_bpf__open_and_load();
	if (libbpf_get_error(obj)) {
		printf("Error, load BPF object failed\n");
		return 1;
	}

	int prog_fd = bpf_program__fd(obj->progs.icmp_prog_reply);
	
	err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, 0);
	if (err) {
		printf("Error, Set XDP fd on iface %d (%s)\n", ifindex, argv[1]);
		return 1;
	}

	// The following doesn't work and throw (-22 Invalid argument) on my side
	// Fallback to skb doesn't seems to work... I need to investigate
	// struct bpf_link *link = bpf_program__attach_xdp(obj->progs.icmp_prog_reply, ifindex);
	//if (!link) {
	//	printf("Error, Set XDP fd on iface %d (%s)\n", ifindex, argv[1]);
	//	return 1;
	//}

	/* Remove attached program when program is interrupted or killed */
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	printf("Program is running on interface %s (ifindex %d)\n", argv[1], ifindex);
    
	/* Maps */

	// Set the flag to 0 (enabled)
	int value = 0;
	update_flag(value);
	
	while (1)
    {
		printf("ICMP pingback is %s\n", value ? "disabled" : "enabled");
		printf("Press enter to toggle the flag\n");
		getchar();
		value = !value;
		update_flag(value);
    }
    
	return 0;
}
