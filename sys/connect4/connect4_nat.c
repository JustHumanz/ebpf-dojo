#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

static int fwd(struct bpf_sock_addr *ctx) {
    const __be32 real_ip = 0x320000C8;     // 200.0.0.50
    const __be32 cluster_ip = 0xa000064;     // 100.0.0.10

    if (ctx->user_ip4 == cluster_ip){
        ctx->user_ip4 = real_ip;
        return 0;
    }

    return 0;

}

SEC("cgroup/connect4")
int proxy(struct bpf_sock_addr *ctx) {
    fwd(ctx);
    return 1;
}