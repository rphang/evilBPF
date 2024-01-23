/* SPDX-License-Identifier: GPL-2.0 */
#include "bpf_helper.h"

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

    if (ntohs(eth->h_proto) != 0x0800) // We can later see how to handle VLAN tagged packets or IPv6
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
        icmph->checksum = csum_fold_helper(bpf_csum_diff(0, 0, (unsigned int *)icmph, sizeof(struct icmphdr), 0));
        // swap the source and destination IP addresses
        swap(iph->saddr, iph->daddr);
        iph->ttl = 64;
        iph->id = 24851;
        // recalculate the IP header checksum
        iph->check = 0;
        iph->check = csum_fold_helper(bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0));
        // recalculate the Ethernet frame checksum
        char buff[ETH_ALEN];
        eth_swap(buff, eth->h_source, eth->h_dest);
        // send the packet back
        return XDP_TX;
    }

    if (icmph->type == 0) {
        return XDP_PASS;
    }

    return XDP_DROP;
}
