// lsm-connect.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1
#define AF_INET 2

static volatile const __u16 target_blocked = -1;
static volatile const __u32 target_uid = -1;


SEC("lsm/socket_listen")
int BPF_PROG(restrict_socket, struct socket * sock, int backlog) {

    u32 uid = bpf_get_current_uid_gid() >> 32;
    if (uid != target_uid) {
        return 0;
    }

    // Only IPv4 in this example
    if (sock->ops->family != AF_INET) {
        return 0;
    }

    bpf_printk("listen port %lu uid %lu",sock->sk->__sk_common.skc_num,sock->sk->sk_uid);


    if (sock->sk->__sk_common.skc_num == target_blocked) {
        bpf_printk("lsm: blocking %d", sock->sk->__sk_common.skc_num);
        return -EPERM;
    }
    return 0;
}