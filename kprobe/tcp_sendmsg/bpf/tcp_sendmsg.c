#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"


struct ip_key_t {
	__be32 saddr;
	__be32 daddr;
	__u32 pid;
	__u16 lport;
	__u16 dport;
};

struct traffic_t {
	size_t sent;
	size_t received;
};


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct ip_key_t);
	__type(value, struct traffic_t);
	__uint(pinning, LIBBPF_PIN_BY_NAME); 
} IP_MAP SEC(".maps");

static volatile const u32 target_uid = -1;
static volatile const u16 sport = -1;
static volatile const u16 eport = -1;

static int probe_tcp(bool receiving, struct sock *sk, size_t size) {
    u32 uid = bpf_get_current_uid_gid() >> 32;
    if (uid != target_uid) {
        return 0;
    }

	u16 dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	u16 src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
	// check if osd connection
	if (dst_port >= eport && dst_port <= sport) {
		return 0;
	}

    u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct traffic_t *trafficp;
	struct ip_key_t ip_key = {
        .lport = src_port,
        .dport = dst_port,
        .pid = pid,
    };

	bpf_printk("recv %lu srcport %lu dport %lu pid %lu",receiving,src_port,dst_port,pid);
    bpf_probe_read_kernel(&ip_key.saddr,sizeof(sk->__sk_common.skc_rcv_saddr),&sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&ip_key.daddr,sizeof(sk->__sk_common.skc_daddr),&sk->__sk_common.skc_daddr);

    trafficp = bpf_map_lookup_elem(&IP_MAP, &ip_key);
	if (!trafficp) {
		struct traffic_t zero;

		if (receiving) {
			zero.sent = 0;
			zero.received = size;
		} else {
			zero.sent = size;
			zero.received = 0;
		}

		bpf_map_update_elem(&IP_MAP, &ip_key, &zero, BPF_NOEXIST);
	} else {
		if (receiving)
			trafficp->received += size;
		else
			trafficp->sent += size;

		bpf_map_update_elem(&IP_MAP, &ip_key, trafficp, BPF_EXIST);
	}

    return 0;    
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
	return probe_tcp(false, sk, size);
}

/*
 * tcp_recvmsg() would be obvious to trace, but is less suitable because:
 * - we'd need to trace both entry and return, to have both sock and size
 * - misses tcp_read_sock() traffic
 * we'd much prefer tracepoints once they are available.
 */
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(tcp_cleanup_rbuf, struct sock *sk, int copied) {
	if (copied <= 0)
		return 0;

	return probe_tcp(true, sk, copied);
}

char LICENSE[] SEC("license") = "GPL";