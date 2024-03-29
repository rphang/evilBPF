/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define ETH_ALEN 6
#define overflow(x, d) (x + 1 > (typeof(x))d)
#define swap(x, y) { typeof(x) tmp = x; x = y; y = tmp; }
#define eth_swap(buff, src, dst) { __builtin_memcpy(buff, src, ETH_ALEN); __builtin_memcpy(src, dst, ETH_ALEN); __builtin_memcpy(dst, buff, ETH_ALEN); }

#define ntohs(x) __builtin_bswap16(x)

static __always_inline __u16
csum_fold_helper(__u64 csum)
{
    int i;
#pragma unroll
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static inline void csum_replace(uint16_t *sum, uint16_t old, uint16_t new)
{
	uint16_t csum = ~*sum;

	csum += ~old;
	csum += csum < (uint16_t)~old;

	csum += new;
	csum += csum < (uint16_t)new;

	*sum = ~csum;
}

void *memcpy(void *dest, const void *src, size_t n);

char _license[] SEC("license") = "GPL";