#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>

#define IPPROTO_UDP 17

char _license[] SEC("license") = "GPL";

SEC("xdp_udp")
int xdp(struct xdp_md *ctx)
{
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

    // Check pkt protocol
    if (iph->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

    // Check udp header size
    struct udphdr *udph = data + nh_off;
    nh_off += sizeof(struct udphdr);
    if (data + nh_off > data_end) {
        return XDP_PASS;
    }

    if (bpf_ntohs(udph->dest) == 2525) {
        bpf_printk("Drop udp pkt, src addr %lu dst port %lu\n",iph->saddr,bpf_ntohs(udph->dest));
        return XDP_DROP;
    }


    return XDP_PASS;
}