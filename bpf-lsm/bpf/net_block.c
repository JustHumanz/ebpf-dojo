// lsm-connect.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1
#define AF_INET 2

static volatile const __u32 target_blocked = -1;
static volatile const __u32 target_uid = -1;


SEC("lsm/socket_connect")
int BPF_PROG(restrict_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    // Satisfying "cannot override a denial" rule
    if (ret != 0) {
        return ret;
    }

    u32 uid = bpf_get_current_uid_gid() >> 32;
    if (uid != target_uid) {
        return 0;
    }
    
    // Only IPv4 in this example
    if (address->sa_family != AF_INET) {
        return 0;
    }

    // Cast the address to an IPv4 socket address
    struct sockaddr_in *addr = (struct sockaddr_in *)address;

    // Where do you want to go?
    __u32 dest = addr->sin_addr.s_addr;
    bpf_printk("lsm: found connect to %d", dest);

    if (dest == target_blocked) {
        bpf_printk("lsm: blocking %d", dest);
        return -EPERM;
    }
    return 0;
}