#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

static int ctx_dst_port(const struct bpf_sock_addr *ctx)
{
	volatile __u32 dport = ctx->user_port;

	return (__be16)dport;
}

void ctx_set_port(struct bpf_sock_addr *ctx, __be16 dport)
{
	ctx->user_port = (__u32)dport;
}

struct lb4_key {
	__be32 address;
	__be16 dport;
	 __u16 pad;
};

struct lb4_service {
	__u32 count;
};


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct lb4_key);
	__type(value, struct lb4_service);
	__uint(max_entries, 32);
} LB4_SERVICES_MAP_V2 SEC(".maps");


struct lb4_backend {
	__be32 address;		/* Service endpoint IPv4 address */
	__be16 port;		/* L4 port filter */
	__u16 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct lb4_backend);
	__uint(max_entries, 32);
} LB4_BACKEND_MAP SEC(".maps");

static int fwd(struct bpf_sock_addr *ctx) {
	__be16 dst_port = ctx_dst_port(ctx);
	__be32 dst_ip = ctx->user_ip4;
		

	struct lb4_key svckey = {
		.address	= dst_ip, 
		.dport		= dst_port,
		.pad = 0,
	};	

	struct lb4_service *svc = bpf_map_lookup_elem(&LB4_SERVICES_MAP_V2, &svckey);
	if (svc) {
		__u32 rand = bpf_get_prandom_u32();
		__u32 backend_id = (rand % svc->count) + 1;
		
		struct lb4_backend * backend = bpf_map_lookup_elem(&LB4_BACKEND_MAP,&backend_id);
		if (backend) {
			ctx->user_ip4 = backend->address;
			ctx_set_port(ctx, backend->port);
		}
	}

    return 0;

}

SEC("cgroup/connect4")
int connect4_lb(struct bpf_sock_addr *ctx) {
    fwd(ctx);

    return 1;
}

