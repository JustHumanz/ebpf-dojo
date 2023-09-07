package main

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
)

//go:generate sh -c "echo Generating for amd64"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang xdp_lb ./bpf/xdp_lb.c -- -DOUTPUT_SKB -D__TARGET_ARCH_x86

func IPV4(ip string) uint32 {
	ip_list := []int{}
	for _, v := range strings.Split(ip, ".") {
		tmp, err := strconv.Atoi(v)
		if err != nil {
			log.Fatal("invalid ip format ", err)
		}
		ip_list = append(ip_list, tmp)
	}

	return uint32((ip_list[0]) | (ip_list[1] << 8) | (ip_list[2] << 16) | (ip_list[3] << 24))
}

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := xdp_lbObjects{}
	err := loadXdp_lbObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf/xdp/globals/",
		},
	})
	if err != nil {
		log.Fatal("err load obj", err)
	}

	LB4BE_XDP := objs.LB4BE_XDP
	LB4LB_XDP := objs.LB4LB_XDP

	Backends := []xdp_lbBackend{
		{
			S_addr: IPV4("200.0.0.30"),
			S_mac:  [6]uint8{0x52, 0x54, 0x00, 0x80, 0x76, 0xef},
		},
		{
			S_addr: IPV4("200.0.0.20"),
			S_mac:  [6]uint8{0x52, 0x54, 0x00, 0xda, 0x9c, 0xa3},
		},
		{
			S_addr: IPV4("200.0.0.10"),
			S_mac:  [6]uint8{0x52, 0x54, 0x00, 0xa3, 0xc4, 0xa0},
		},
	}

	for i, v := range Backends {
		fmt.Println(fmt.Sprintf("Put kv BE %d to map", v.S_addr))
		if err := LB4BE_XDP.Put(uint32(i), v); err != nil {
			log.Fatal("Failed to put BE ", err)
		}
	}

	LBval := xdp_lbLbIp{
		BeCount: uint32(len(Backends)),
		LbMac:   [6]uint8{0x52, 0x54, 0x00, 0x1d, 0xf2, 0x18},
	}

	fmt.Println("Add LB ip to map")
	if err := LB4LB_XDP.Put(IPV4("200.0.0.100"), LBval); err != nil {
		log.Fatal(err)
	}

	iface := "enp3s0"
	lo, err := netlink.LinkByName(iface)
	if err != nil {
		log.Fatal("Invalid interface ", err)
	}

	fmt.Println("Attach prog to iface ", iface)
	err = netlink.LinkSetXdpFdWithFlags(lo, objs.LoadBalancer.FD(), 1<<1) //https://github.com/shemminger/iproute2/blob/505c65aa44c58bb772b007b83be560370eba25a6/include/uapi/linux/if_link.h#L1293
	if err != nil {
		log.Fatal("failed to attach prog ", err)
	}
}
