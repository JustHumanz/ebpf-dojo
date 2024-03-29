
#define KBUILD_MODNAME "load_balancer"
#include <linux/bpf.h>     // struct __sk_buff
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


#ifndef IPV4
#define IPV4(A, B, C, D) ((A) | (B << 8) | (C << 16) | (D << 24))
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

//const __be32 backend_ip = IPV4(200,0,0,30);
//unsigned char backend_mac[ETH_ALEN] = {0x52,0x54,0x00,0x80,0x76,0xef}; //52:54:00:80:76:ef

const __be32 lb_ip = IPV4(200,0,0,50);
unsigned char lb_mac[ETH_ALEN] = {0x52,0x54,0x00,0x82,0x45,0x28};  //52:54:00:82:45:28

//const __be32 client_ip = IPV4(200,0,0,100);
//unsigned char client_mac[ETH_ALEN] = {0x52,0x54,0x00,0x1d,0xf2,0x18};  //52:54:00:1d:f2:18 

struct backend {
	__be32 s_addr;
    unsigned char s_mac[ETH_ALEN];
    __be16 pad;
};

#define MAX_BE 2

struct backend backends[MAX_BE] = {
    {
        .s_addr = IPV4(200,0,0,30),
        .s_mac = {0x52,0x54,0x00,0x80,0x76,0xef},
    },
    {
        .s_addr = IPV4(200,0,0,10),
        .s_mac = {0x52,0x54,0x00,0xa3,0xc4,0xa0},
    },
};

struct ct {
	__be32 cl_addr;
    unsigned char c_mac[ETH_ALEN];
    struct backend be;
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
} LB4_XDP SEC(".maps");


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
    
    if (iph->daddr == lb_ip) {
        // Check tcp port
        // Client -> lb and filter it with port 80
        if (bpf_ntohs(tcph->dest) == 80) {
            struct ct_key key = {
                .dport = tcph->dest,
                .sport = tcph->source,
                .dst = iph->daddr,
            };

            struct backend real_be;
            struct ct *client = bpf_map_lookup_elem(&LB4_XDP, &key);
            if (!client) {
                __u32 backend_id = (bpf_get_prandom_u32() % MAX_BE);
                real_be = backends[backend_id];

                bpf_printk("backend addr %lu ",real_be.s_addr);
                struct ct val = {
                    .cl_addr = iph->saddr,
                    .be = real_be,
                };

                memcpy(val.c_mac,eth->h_source, ETH_ALEN);
                bpf_map_update_elem(&LB4_XDP, &key, &val, BPF_NOEXIST);
            } else {
                real_be = client->be;
            }

            // Override mac address
            iph->daddr = real_be.s_addr;
            memcpy(eth->h_dest, real_be.s_mac, ETH_ALEN);     
        } else if (bpf_ntohs(tcph->dest) >= 32768) { //This one pkt from lb to client
            struct ct_key key = {
                .dport = tcph->source,
                .sport = tcph->dest,
                .dst = iph->daddr,
            };

            struct ct *client = bpf_map_lookup_elem(&LB4_XDP, &key);
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
    } 

    iph->saddr = lb_ip;
    memcpy(eth->h_source, lb_mac, ETH_ALEN);

    iph->check = iph_csum(iph);    

    
    return XDP_TX;
}

char _license[4] SEC("license") = "GPL";