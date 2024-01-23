#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_link.h>
#include <signal.h>
#include <net/if.h>
#include <assert.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

static int ifindex;
struct xdp_program *prog = NULL;

/* This function will remove XDP from the link when program exit */
static void int_exit(int sig)
{
	xdp_program__detach(prog, ifindex, XDP_MODE_SKB, 0);
	xdp_program__close(prog);
	exit(0);
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc != 2) {
		printf("Usage: %s IFNAME\n", argv[0]);
		return 1;
	}

	ifindex = if_nametoindex(argv[1]);
	if (!ifindex) {
		printf("get ifindex from interface name failed\n");
		return 1;
	}
    
	/* load XDP object by libxdp */
	prog = xdp_program__open_file("icmp.bpf.o", "icmp_reply", NULL);
	if (libxdp_get_error(prog)) {
		printf("Error, load xdp prog failed\n");
		return 1;
	}

	/* attach XDP program to interface with skb mode.
	 * Please set ulimit if you got an -EPERM error.
	 */
	ret = xdp_program__attach(prog, ifindex, XDP_MODE_SKB, 0);
	if (ret) {
		printf("Error, Set xdp fd on iface %d failed\n", ifindex);
		return ret;
	}

	/* Remove attached program when program is interrupted or killed */
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

    while (1)
    {

    }
    

	return 0;
}
