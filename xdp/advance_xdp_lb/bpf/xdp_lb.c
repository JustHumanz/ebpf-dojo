#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


#ifndef IPV4
#define IPV4(A, B, C, D) ((A) | (B << 8) | (C << 16) | (D << 24))
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define ETH_ALEN	6
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/

struct lb_ip {
    unsigned char lb_mac[ETH_ALEN];
    __be32 be_count;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __be32);
	__type(value, struct lb_ip);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 256);
} LB4_LB_XDP SEC(".maps");

struct backend {
	__be32 s_addr;
    unsigned char s_mac[ETH_ALEN];
    __be16 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __be32);
	__type(value, struct backend);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 256);
} LB4_BE_XDP SEC(".maps");

struct ct {
	__be32 cl_addr;
    unsigned char c_mac[ETH_ALEN];
    union 
    {
        struct backend be;
    };
    
};

struct ct_key {
    __be32 dst;
    __be16 dport;
    __be16 sport;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct ct_key);
	__type(value, struct ct);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 65536*2);
} LB4_CT_XDP SEC(".maps");


static __always_inline __u16 csum_fold_helper(__u64 csum) {
    int i;
#pragma unroll
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16 iph_csum(struct iphdr *iph) {
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}


SEC("xdp_lb")
int load_balancer(struct xdp_md *ctx) {

    __u32 nh_off = 0;

    // Read data
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    // Handle data as an ethernet frame header
    struct ethhdr *eth = data;

    // Check frame header size
    nh_off = sizeof(*eth);
    if (data + nh_off > data_end) {
        return XDP_PASS;
    }

    // Check protocol
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Check packet header size
    struct iphdr *iph = data + nh_off;
    nh_off += sizeof(struct iphdr);
    if (data + nh_off > data_end) {
        return XDP_PASS;
    }

    // Check protocol
    if (iph->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    // Check tcp header size
    struct tcphdr *tcph = data + nh_off;
    nh_off += sizeof(struct tcphdr);
    if (data + nh_off > data_end) {
        return XDP_PASS;
    }
    
    // Save the lb ip addr
    const __be32 old_lb = iph->daddr; 

    // Find the lb ip addr
    struct lb_ip *lb = bpf_map_lookup_elem(&LB4_LB_XDP, &iph->daddr);
    if (lb) {
        // Check tcp port
        // Client -> lb and filter it with port 80
        if (bpf_ntohs(tcph->dest) == 80) {
            struct ct_key key = {
                .dport = tcph->dest,
                .sport = tcph->source,
                .dst = iph->daddr,
            };

            struct ct *client = bpf_map_lookup_elem(&LB4_CT_XDP, &key);
            if (!client) {
                __u32 be_id = (bpf_get_prandom_u32() % lb->be_count);
                bpf_printk("backend id %lu",be_id);                
                struct backend *real_be = bpf_map_lookup_elem(&LB4_BE_XDP, &be_id);
                if (real_be) {
                    struct ct val = {
                        .cl_addr = iph->saddr,
                        .be = *real_be,
                    };

                    memcpy(val.c_mac,eth->h_source, ETH_ALEN);
                    bpf_map_update_elem(&LB4_CT_XDP, &key, &val, BPF_NOEXIST);

                    // Override mac address
                    // I hate this do do multiple swaping ip&mac, TODO: optimization
                    iph->daddr = real_be->s_addr;
                    memcpy(eth->h_dest, real_be->s_mac, ETH_ALEN);     
                } else {
                    bpf_printk("Unknow backend id %lu",be_id);
                    return XDP_DROP;
                }

            } else {
                // Override mac address
                iph->daddr = client->be.s_addr;
                memcpy(eth->h_dest, client->be.s_mac, ETH_ALEN);     
            }

        } else if (bpf_ntohs(tcph->dest) >= 32768) { // This pkt was from BE to client and need to change the dst addr from lb ip to client ip
            struct ct_key key = {
                .dport = tcph->source,
                .sport = tcph->dest,
                .dst = iph->daddr,
            };

            struct ct *client = bpf_map_lookup_elem(&LB4_CT_XDP, &key);
            if (client) {
                // Override mac address
                iph->daddr = client->cl_addr;
                memcpy(eth->h_dest, client->c_mac, ETH_ALEN); 

            } else {
                bpf_printk("Unknow client, dport %lu sport %lu", tcph->dest,tcph->source);
                return XDP_DROP;
            }
        } else {
            return XDP_DROP;
        }

        iph->saddr = old_lb;
        memcpy(eth->h_source, lb->lb_mac, ETH_ALEN);

        iph->check = iph_csum(iph);           
        return XDP_TX;

    } else {
        return XDP_PASS;
    }
}

char _license[4] SEC("license") = "GPL";