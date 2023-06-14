package main

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type icmp_ct struct {
	src_ip uint32 `align:"src_ip"`
	reply  uint16 `align:"reply"`
}

func main() {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Printf("failed to set temporary RLIMIT_MEMLOCK: %v", err)
		return
	}

	bpfMap := 171 //bpftool map list | grep ICMP_CT | awk -F ":" '{print $1}'
	m, err := ebpf.NewMapFromID(ebpf.MapID(bpfMap))
	if err != nil {
		log.Fatalf("bpf map(%d) not found, err: %v", bpfMap, err)
	}
	fmt.Println(m.IsPinned())

	var val *icmp_ct
	err = m.Lookup(uint16(17664), val)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(val)
}
