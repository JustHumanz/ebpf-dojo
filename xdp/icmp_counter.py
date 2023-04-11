from bcc import BPF 
from bcc.utils import printb

prog = """
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>

BPF_HISTOGRAM(counter, u64);

int icmp_counter (struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;
    
    struct ethhdr  *eth  = data;
    struct iphdr   *ip   = (data + sizeof(struct ethhdr));
    struct icmphdr *icmp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) <= data_end) {
        if (ip->protocol == IPPROTO_ICMP) {
            counter.increment(1);
        }   
    }
    
    return XDP_PASS;
}
"""
device = "enp1s0" 
b = BPF(text=prog)
fn = b.load_func("icmp_counter", BPF.XDP) 
b.attach_xdp(device, fn, 0) 

try:
    b.trace_print() 
except KeyboardInterrupt: 

    dist = b.get_table("counter") 
    for k, v in sorted(dist.items()): 
        print("DEST_PORT : %10d, COUNT : %10d" % (k.value, v.value)) 

b.remove_xdp(device, 0) 