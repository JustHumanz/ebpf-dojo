from bcc import BPF
from pyroute2 import IPRoute, IPDB

proxy_bpf = """
    #include <linux/bpf.h>
    #include <linux/if_ether.h>
    #include <linux/ip.h>
    #include <linux/tcp.h>
    #include <linux/icmp.h>
    #include <linux/in.h>
    #include <linux/pkt_cls.h>
    #include <linux/stddef.h>

    int ingress(struct __sk_buff *skb)
    {
        const __be32 pod_ip = 0x640000C8;     // 200.0.0.100

        void *data = (void *)(long)skb->data;
        void *data_end = (void *)(long)skb->data_end;
        if (data_end < data + sizeof(struct ethhdr)) { // not our packet
            return TC_ACT_OK;
        }

        struct ethhdr  *eth  = data;
        struct iphdr   *ip   = (data + sizeof(struct ethhdr));        

        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end) {
            if (ip->saddr == pod_ip && ip->protocol == IPPROTO_ICMP) {
                bpf_trace_printk("Drop icmp, src addr %u\\n",ip->saddr);
                return TC_ACT_SHOT;
            }            
        }

        return TC_ACT_OK;
    }
"""

ipr = IPRoute()
ipdb = IPDB(nl=ipr)
ifc = ipdb.interfaces.virbr2
proxy_bpf = BPF(text=proxy_bpf)

drop_icmp = proxy_bpf.load_func("ingress", BPF.SCHED_CLS)

ipr.tc("add", "clsact", ifc.index)
ipr.tc("add-filter", "bpf", ifc.index, ":1", fd=drop_icmp.fd,name=drop_icmp.name, parent="ffff:fff2",classid=1, action="drop",sec="ingress")

try:
    print("All Ready...")
    proxy_bpf.trace_print()
except KeyboardInterrupt:
    print("Ending Demo...")
finally:
    ipr.tc("del", "clsact", ifc.index, "ffff:")
    ipdb.release()