#include <linux/bpf.h>     // struct __sk_buff
#include <linux/pkt_cls.h> // TC_ACT_OK
#include <linux/ip.h>      // struct iphdr
#include <linux/tcp.h>     // struct tcphdr
#include <linux/udp.h>     // struct udphdr
#include <stdint.h>        // uint32_t
#include <stddef.h>        // offsetof()
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

#ifndef __section
# define __section(NAME)                  \
       __attribute__((section(NAME), used))
#endif

#define ETH_HLEN 14
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#ifndef IPV4
#define IPV4(A, B, C, D) ((A) | (B << 8) | (C << 16) | (D << 24))
#endif

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)						\
	(* NAME)(__VA_ARGS__) = (void *) BPF_FUNC_##NAME
#endif

#ifndef tcp_flag_byte
#define tcp_flag_byte(th) (((__uint8_t *)th)[13])
#endif


static int BPF_FUNC(skb_store_bytes, struct __sk_buff *skb, uint32_t off,
		    const void *from, uint32_t len, uint32_t flags);
static int BPF_FUNC(csum_diff, void *from, uint32_t from_size, void *to,
		    uint32_t to_size, uint32_t seed);
static int BPF_FUNC(l3_csum_replace, struct __sk_buff *skb, uint32_t off,
		    uint32_t from, uint32_t to, uint32_t flags);
static int BPF_FUNC(l4_csum_replace, struct __sk_buff *skb, uint32_t off,
		    uint32_t from, uint32_t to, uint32_t flags);


const int l3_off = ETH_HLEN;    // IP header offset
const int l4_off = l3_off + 20; // TCP header offset: l3_off + sizeof(struct iphdr)

struct proto_ct_key {
	__be32 dst_ip;
	__be16 dport;
    __be16 sport;
    __be32 proto;
};

struct tcp_ct_val {
	__be32 src_ip;
	__be32 flag;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct proto_ct_key);
	__type(value, struct tcp_ct_val);
	__uint(max_entries, 32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} TCP_CT SEC(".maps");

struct icmp_ct_val {
    __be32 src_ip;
    __be32 reply;
    __be64 ts;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __be16);
	__type(value, struct icmp_ct_val);
	__uint(max_entries, 32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ICMP_CT SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct proto_ct_key);
	__type(value, struct icmp_ct_val);
	__uint(max_entries, 32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} UDP_CT SEC(".maps");

const __be32 nat_ip = IPV4(200,0,0,50);
const __be32 net_ip = IPV4(200,0,0,0);
const __be32 mask = IPV4(255, 255, 255, 0); 
const int proto_allowed_arr[] = {sizeof(struct icmphdr), sizeof(struct udphdr), sizeof(struct tcphdr)};

__section("egress")
int tc_egress(struct __sk_buff *skb) {
    __be32 sum;                     // IP checksum

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (data_end < data + sizeof(struct ethhdr) + sizeof(struct iphdr)) { // not our packet
        return TC_ACT_OK;
    }

    struct iphdr *ip4 = (struct iphdr *)(data + sizeof(struct ethhdr));    
    //Check if dst addr is 1 network
    if ((ip4->daddr&mask) != net_ip){  
        return TC_ACT_OK;
    } 

    //Check packet size
    for (size_t i = 0; i < sizeof(proto_allowed_arr) / sizeof(proto_allowed_arr[0]); i++)
    {
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + proto_allowed_arr[i] > data_end ) { //Not our icmp/udp/tcp packet
            bpf_printk("not our pkt %d hdr size %d proto %u \n",data_end,proto_allowed_arr[i],ip4->protocol);
            return TC_ACT_OK;
        }
    }

    if (ip4->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp_pkt = (struct icmphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
        bpf_printk("[egress_icmp] pkt, icmp id %d\n",icmp_pkt->un.echo.id >> 8);

        struct icmp_ct_val new_icmp_val = {
            .src_ip = ip4->saddr,
        };

        struct icmp_ct_val *icmp_val = bpf_map_lookup_elem(&ICMP_CT, &icmp_pkt->un.echo.id);
        if (!icmp_val) {
            //New icmp CT
            bpf_map_update_elem(&ICMP_CT, &icmp_pkt->un.echo.id, &new_icmp_val, BPF_NOEXIST);
        } else {
            //Update icmp CT
            icmp_val->ts = bpf_ktime_get_ns();
            icmp_val->reply = 0;
            bpf_map_update_elem(&ICMP_CT, &icmp_pkt->un.echo.id, icmp_val, BPF_EXIST);
        }

        sum = csum_diff((void *)&ip4->saddr, 4, (void *)&nat_ip, 4, 0);
        skb_store_bytes(skb, l3_off + offsetof(struct iphdr, saddr), (void *)&nat_ip, 4, 0);
        l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check), 0, sum, 0);

    } else if (ip4->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_pkt = (struct tcphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));

        __u8 tcpflags = ((__uint8_t *)tcp_pkt)[13];
        bpf_printk("[egress_tcp] pkt, src %lu dst %lu flag %u\n",tcp_pkt->source,tcp_pkt->dest,tcpflags);

        struct proto_ct_key tcp_key = {
            .dst_ip = ip4->daddr,
            .dport = tcp_pkt->dest,
            .sport = tcp_pkt->source,
            .proto = IPPROTO_TCP,
        };

        struct tcp_ct_val tcp_val = {
            .src_ip = ip4->saddr,
            .flag = tcpflags,
        };

        if (tcpflags == 2) { //2 => 0x02 = syn
            bpf_map_update_elem(&TCP_CT, &tcp_key, &tcp_val, BPF_ANY); 
        } else if (tcpflags == 17) {
            
        }

        sum = csum_diff((void *)&ip4->saddr, 4, (void *)&nat_ip, 4, 0);
        skb_store_bytes(skb, l3_off + offsetof(struct iphdr, saddr), (void *)&nat_ip, 4, 0);
        l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check), 0, sum, 0);
        l4_csum_replace(skb, l4_off + offsetof(struct tcphdr, check), 0, sum, BPF_F_PSEUDO_HDR);

    } else if (ip4->protocol == IPPROTO_UDP) {
        struct udphdr *udp_pkt = (struct udphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
        bpf_printk("[egress_udp] pkt, src %lu dst %lu\n",udp_pkt->source,udp_pkt->dest);

        struct proto_ct_key udp_key = {
            .dst_ip = ip4->daddr,
            .dport = udp_pkt->dest,
            .sport = udp_pkt->source,
            .proto = IPPROTO_UDP,
        };

        struct icmp_ct_val udp_val = {
            .src_ip = ip4->saddr,
            .reply = 0,
            .ts = bpf_ktime_get_ns(),
        };

        struct icmp_ct_val *udp_val_kv = bpf_map_lookup_elem(&UDP_CT, &udp_key);
        if (!udp_val_kv) {
            //New udp CT
            bpf_map_update_elem(&UDP_CT, &udp_key, &udp_val, BPF_NOEXIST);
        } else {
            //Update udp CT
            udp_val_kv->ts = bpf_ktime_get_ns();
            udp_val_kv->reply = 0;
            bpf_map_update_elem(&UDP_CT, &udp_key, udp_val_kv, BPF_EXIST);
        }

        sum = csum_diff((void *)&ip4->saddr, 4, (void *)&nat_ip, 4, 0);
        skb_store_bytes(skb, l3_off + offsetof(struct iphdr, saddr), (void *)&nat_ip, 4, 0);
        l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check), 0, sum, 0);
        l4_csum_replace(skb, l4_off + offsetof(struct udphdr, check), 0, sum, BPF_F_PSEUDO_HDR);
    }

    return TC_ACT_OK;
}

__section("ingress")
int tc_ingress(struct __sk_buff *skb) {
    __be32 sum;                             // IP checksum

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (data_end < data + l4_off) {         // not our packet
        return TC_ACT_OK;
    }

    struct iphdr *ip4 = (struct iphdr *)(data + sizeof(struct ethhdr));    

    //Check dst addr
    if (ip4->daddr != nat_ip){  
        return TC_ACT_OK;
    }   

    for (size_t i = 0; i < sizeof(proto_allowed_arr) / sizeof(proto_allowed_arr[0]); i++)
    {
        if (data_end < data + sizeof(struct ethhdr) + sizeof(struct iphdr) + proto_allowed_arr[i]) { // not our icmp/udp/tcp packet
            return TC_ACT_OK;
        }
    }

    if (ip4->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp_pkt = (struct icmphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
        bpf_printk("[ingress_icmp] pkt, icmp id %d\n",icmp_pkt->un.echo.id >> 8);

        struct icmp_ct_val *icmp_val = bpf_map_lookup_elem(&ICMP_CT, &icmp_pkt->un.echo.id);
        if (icmp_val) {
            const __be32 * src_ip = &icmp_val->src_ip;
            icmp_val->reply = 1;
            bpf_map_update_elem(&ICMP_CT, &icmp_pkt->un.echo.id, icmp_val, BPF_EXIST);

            sum = csum_diff((void *)&ip4->daddr, 4, (void *)src_ip, 4, 0);
            skb_store_bytes(skb, l3_off + offsetof(struct iphdr, daddr), (void *)src_ip, 4, 0);
            l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check), 0, sum, 0);
        }

    } else if (ip4->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_pkt = (struct tcphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
        __u8 tcpflags = ((__uint8_t *)tcp_pkt)[13];
        bpf_printk("[ingress_tcp] pkt, src %lu dst %lu flag %u\n",tcp_pkt->source,tcp_pkt->dest,tcpflags);

        struct proto_ct_key tcp_key = {
            .dst_ip = ip4->saddr,
            .dport = tcp_pkt->source,
            .sport = tcp_pkt->dest,
            .proto = IPPROTO_TCP,
        };

        struct tcp_ct_val *tcp_val = bpf_map_lookup_elem(&TCP_CT, &tcp_key);
        if (tcp_val) {
            const __be32 * src_ip = &tcp_val->src_ip;
            if (tcpflags == 17 || tcpflags == 20){ //fin,ack = 17 && rst = 20
                bpf_map_delete_elem(&TCP_CT,&tcp_key); //delete from map
            };

            sum = csum_diff((void *)&ip4->daddr, 4, (void *)src_ip, 4, 0);
            skb_store_bytes(skb, l3_off + offsetof(struct iphdr, daddr), (void *)src_ip, 4, 0);
            l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check), 0, sum, 0);           
            l4_csum_replace(skb, l4_off + offsetof(struct tcphdr, check), 0, sum, BPF_F_PSEUDO_HDR);     
        }
    } else if (ip4->protocol == IPPROTO_UDP) {
        struct udphdr *udp_pkt = (struct udphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));     
        bpf_printk("[ingress_udp] pkt, src %lu dst %lu flag %u\n",udp_pkt->source,udp_pkt->dest);

        struct proto_ct_key udp_key = {
            .dst_ip = ip4->saddr,
            .dport = udp_pkt->source,
            .sport = udp_pkt->dest,
            .proto = IPPROTO_UDP,
        };

        struct icmp_ct_val *udp_val_kv = bpf_map_lookup_elem(&UDP_CT, &udp_key);
        if (udp_val_kv) {
            const __be32 * src_ip = &udp_val_kv->src_ip;
            udp_val_kv->ts = bpf_ktime_get_ns();
            udp_val_kv->reply = 1;
            bpf_map_update_elem(&UDP_CT, &udp_key, udp_val_kv, BPF_EXIST);

            sum = csum_diff((void *)&ip4->daddr, 4, (void *)src_ip, 4, 0);
            skb_store_bytes(skb, l3_off + offsetof(struct iphdr, daddr), (void *)src_ip, 4, 0);
            l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check), 0, sum, 0);           
            l4_csum_replace(skb, l4_off + offsetof(struct udphdr, check), 0, sum, BPF_F_PSEUDO_HDR);     
        }
    }

    return TC_ACT_OK;
}


char __license[] __section("license") = "GPL";