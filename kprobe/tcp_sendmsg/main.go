package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate sh -c "echo Generating for amd64"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tcp_top ./bpf/tcp_sendmsg.c -- -DOUTPUT_SKB -D__TARGET_ARCH_x86 -I./bpf/headers

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

// NetToHostLong converts a 32-bit integer from network to host byte order, aka "ntohl"
func NetToHostLong(i uint32) uint32 {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, i)
	return binary.LittleEndian.Uint32(data)
}

func main() {

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	spec, err := loadTcp_top()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("set target_uid")
	if err := spec.RewriteConstants(map[string]interface{}{
		"target_uid": uint32(115),
		"sport":      uint16(6800),
		"eport":      uint16(7300),
	}); err != nil {
		log.Fatal(err)
	}

	var objs tcp_topObjects
	fmt.Println("load objs")
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf/tc/globals/",
		},
	}); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	fmt.Println("load tcp_sendmsg kprobe")
	kp_tcp_msg, err := link.Kprobe("tcp_sendmsg", objs.TcpSendmsg, nil)
	if err != nil {
		log.Fatal(err)
	}

	defer kp_tcp_msg.Close()

	fmt.Println("load tcp_cleanup_rbuf kprobe")
	kp_tcp_clean, err := link.Kprobe("tcp_cleanup_rbuf", objs.TcpCleanupRbuf, nil)
	if err != nil {
		log.Fatal(err)
	}

	defer kp_tcp_clean.Close()
	for {
		var (
			nextkey tcp_topIpKeyT
			nextval tcp_topTrafficT
			entries = objs.IP_MAP.Iterate()
		)

		for entries.Next(&nextkey, &nextval) {
			src_ip := int2ip(NetToHostLong(nextkey.Daddr))
			msg := fmt.Sprintf("dst ip %s:%d send %d recv %d", src_ip, nextkey.Dport, nextval.Sent, nextval.Received)
			fmt.Println(msg)
		}

		time.Sleep(1 * time.Second)
	}

}
