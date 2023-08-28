
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


const __be32 backend_ip = IPV4(10,0,0,20);
unsigned char backend_mac[ETH_ALEN] = {0x00,0x00,0x00,0x00,0x01,0x02}; //{0x52,0x54,0x00,0x80,0x76,0xef}; //52:54:00:80:76:ef

const __be32 lb_ip = IPV4(10,0,0,10);
unsigned char lb_mac[ETH_ALEN] = {0x00,0x00,0x00,0x00,0x01,0x01}; //{0x52,0x54,0x00,0x82,0x45,0x28};  //52:54:00:82:45:28

const __be32 client_ip = IPV4(200,0,0,100);
unsigned char client_mac[ETH_ALEN] = {0x52,0x54,0x00,0x1d,0xf2,0x18};  //52:54:00:1d:f2:18 

struct ct {
	__be32 cl_addr;
    unsigned char c_mac[ETH_ALEN];
	__be16 sport;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __be16);
	__type(value, struct ct);
	__uint(max_entries, 32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
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
    int rc = XDP_PASS;
    __u32 nh_off = 0;

    // Read data
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    // Handle data as an ethernet frame header
    struct ethhdr *eth = data;

    // Check frame header size
    nh_off = sizeof(*eth);
    if (data + nh_off > data_end) {
        return rc;
    }

    // Check protocol
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return rc;
    }

    // Check packet header size
    struct iphdr *iph = data + nh_off;
    nh_off += sizeof(struct iphdr);
    if (data + nh_off > data_end) {
        return rc;
    }

    // Check protocol
    if (iph->protocol != IPPROTO_TCP) {
        return rc;
    }

    // Check tcp header size
    struct tcphdr *tcph = data + nh_off;
    nh_off += sizeof(struct tcphdr);
    if (data + nh_off > data_end) {
        return rc;
    }
    
    // Check tcp port
    if (bpf_ntohs(tcph->dest) != 80) {
        return rc;
    }

    struct ct *ct_val = bpf_map_lookup_elem(&LB4_XDP, &tcph->source);
    if (ct_val) {
        iph->daddr = ct_val->cl_addr;
        memcpy(eth->h_dest,ct_val->c_mac,ETH_ALEN);
    } else {
        bpf_printk("new client %lu",iph->addrs.saddr);
        struct ct new_ct = {
            .cl_addr = iph->addrs.saddr,
            .sport = tcph->source,
        };

        memcpy(new_ct.c_mac, eth->h_source, ETH_ALEN);

        bpf_printk("sport %lu addr %lu mac %s",new_ct.sport,new_ct.cl_addr,new_ct.c_mac);
        bpf_map_update_elem(&LB4_XDP, &tcph->source, &new_ct, BPF_NOEXIST);

        iph->daddr = backend_ip;
        memcpy(eth->h_dest, backend_mac, ETH_ALEN);
    }

//    if (iph->saddr == client_ip) {
//        // Override mac address
//        iph->daddr = backend_ip;
//        memcpy(eth->h_dest, backend_mac, ETH_ALEN);
//    } else {
//        iph->daddr = client_ip;
//        memcpy(eth->h_dest, client_mac, ETH_ALEN);
//    }


    iph->saddr = lb_ip;
    memcpy(eth->h_source, lb_mac, ETH_ALEN);
    iph->check = iph_csum(iph);    

    return XDP_TX;
}

char _license[4] SEC("license") = "GPL";