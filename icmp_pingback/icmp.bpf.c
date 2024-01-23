/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/icmp.h>

#define overflow(x, d) (x + 1 > (typeof(x))d)
#define swap(x, y) { typeof(x) tmp = x; x = y; y = tmp; }
#define eth_swap(buff, src, dst) { memcpy(buff, src, ETH_ALEN); memcpy(src, dst, ETH_ALEN); memcpy(dst, buff, ETH_ALEN); }

SEC("xdp")
int icmp_prog_reply(struct xdp_md *ctx)
{
    // Read packet data into buffer
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
   
    struct ethhdr *eth = data;
	struct iphdr *iph = (struct iphdr *)(eth + 1);
	struct icmphdr *icmph = (struct icmphdr *)(iph + 1);

    if (overflow(eth, data_end))
        return XDP_DROP; // ethernet header is not complete

    if (ntohs(eth->h_proto) != ETH_P_IP) // We can later see how to handle VLAN tagged packets or IPv6
        return XDP_PASS; // let any other packets than IP (L3) pass

    if (overflow(iph, data_end))
        return XDP_DROP; // ip header is not complete
        
    if (iph->protocol != IPPROTO_ICMP)
        return XDP_PASS; // let any other packets than ICMP pass
    
    if (overflow(icmph, data_end))
        return XDP_DROP; // icmp header is not complete
    
    if (icmph->type == 8) {
        bpf_printk("ICMP echo request received\n");
        // change the type to 0 (echo reply)
        icmph->type = 0;
        // recalculate the checksum
        icmph->checksum = 0;
        icmph->checksum = bpf_csum_diff((__be32 *)icmph, sizeof(*icmph), 0, 0, 0);
        // swap the source and destination IP addresses
        swap(iph->saddr, iph->daddr);
        // recalculate the IP header checksum
        iph->check = 0;
        iph->check = bpf_csum_diff((__be32 *)iph, sizeof(*iph), 0, 0, 0);
        // recalculate the Ethernet frame checksum
        char buff[ETH_ALEN];
        eth_swap(buff, eth->h_source, eth->h_dest);
        // send the packet back
        return XDP_PASS;
    }

    if (icmph->type == 0) {
        return XDP_PASS;
    }

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";