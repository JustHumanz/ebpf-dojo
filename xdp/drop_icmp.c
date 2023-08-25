#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>

#define IPPROTO_ICMP 1

char _license[] SEC("license") = "GPL";

SEC("xdp_icmp")
int drop_icmp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data_end < data + sizeof(struct ethhdr)) { // not our packet
        return XDP_PASS;
    }

    struct ethhdr  *eth  = data;
    struct iphdr   *ip   = (data + sizeof(struct ethhdr));        

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end) {
        if (ip->protocol == IPPROTO_ICMP) {
            bpf_printk("Drop icmp, src addr %u\n",ip->saddr);
            return XDP_DROP;
        }            
    }

    return XDP_PASS;
}