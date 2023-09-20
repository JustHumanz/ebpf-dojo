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
const char fmt_data[] = "%02x ";
unsigned char databuf[256];

SEC("lsm/socket_recvmsg")
int BPF_PROG(restrict_recvmsg, struct socket * sock,struct msghdr * msg, int size, int flags) {

    u32 uid = bpf_get_current_uid_gid() >> 32;
    if (uid != target_uid) {
        return 0;
    }

    // Only IPv4 in this example
    if (sock->ops->family != AF_INET) {
        return 0;
    }
    bpf_printk("listen port %lu src port %lu",sock->sk->__sk_common.skc_num,sock->sk->__sk_common.skc_dport);


    if (sock->sk->__sk_common.skc_num == target_blocked) {
    struct iov_iter *iter= &(msg->msg_iter);
    struct iovec *iter_data = (struct iovec *)&(iter->__iov);
    int read_success=-1;
    long unsigned int iov_seg_count;//count of iovec's
    unsigned char iov_type;//0 is iter_iovec
    unsigned long iov_count;//total data length in iter
    unsigned long iov_length;//length of current iovec
    unsigned long iov_offset;//iovec's to skip in iter
    unsigned long read_length;//final length in the data buffer

    read_success=bpf_probe_read(&iov_type, sizeof(unsigned char), &(iter->iter_type));
    if(read_success!=0) {
        return 0;
    } 
    read_success=bpf_probe_read(&iov_seg_count, sizeof(long unsigned int), &(iter->nr_segs));
    if(read_success!=0) {
        return 0;
    } 
   read_success=bpf_probe_read(&iov_count, sizeof(unsigned long), &(iter->count));
    if(read_success!=0) {
        return 0;
    } 
    read_success=bpf_probe_read(&iov_offset, sizeof(unsigned long), &(iter->iov_offset));
    if(read_success!=0) {
        return 0;
    } 

    void* startaddress;
    read_success=bpf_probe_read(&startaddress, sizeof(void*), &(iter_data->iov_base));
    if(read_success!=0){
        return 0;
    }
    
    
    read_success=bpf_probe_read(&iov_length, sizeof(size_t), &(iter_data->iov_len));
    if(read_success!=0){
        return 0;
    }
    
    if(iov_length< 256){//change against iov_count
        read_length=iov_length;//change against iov_count
    }else{
        read_length=256;
    } 
    read_success=bpf_probe_read(databuf, read_length, startaddress);
    

        bpf_printk("payload %c %c %c full payload %s",(unsigned char )databuf[0],(unsigned char )databuf[1],(unsigned char )databuf[2],(unsigned char *)&databuf);

        if (databuf[0] == 71 && databuf[1] == 69 && databuf[2] == 84){
            bpf_printk("lsm: blocking %lu", databuf);
            return -EPERM;            
        }
    }
    return 0;
}