package main

import (
	"log"

	"C"

	"golang.org/x/sys/unix"
)
import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"os"
	"os/signal"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang socket_lb ./socket_lb.c

type SvcKey struct {
	Address uint32 `align:"address"`
	Dport   uint16 `align:"dport"`
	Pad     uint16 `align:"pad"`
}

type SvcVal struct {
	Count uint32 `align:"count"`
}

type LbBeVal struct {
	Address uint32 `align:"address"`
	Port    uint16 `align:"port"`
	Pad     uint16 `align:"pad"`
}

func newCancelableContext() context.Context {
	doneCh := make(chan os.Signal, 1)
	signal.Notify(doneCh, os.Interrupt)

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	go func() {
		<-doneCh
		cancel()
	}()

	return ctx
}

func IpToU32(ip string) uint32 {
	var long uint32
	binary.Read(bytes.NewBuffer(net.ParseIP(ip).To4()), binary.LittleEndian, &long)
	return long
}

func PortToU16(port uint16) uint16 {
	bs := make([]byte, 2)
	binary.LittleEndian.PutUint16(bs, port)
	return binary.BigEndian.Uint16(bs)
}

func main() {
	// Increase the resource limit of the current process to provide sufficient space
	// for locking memory for the BPF maps.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Printf("failed to set temporary RLIMIT_MEMLOCK: %v", err)
		return
	}

	ctx := newCancelableContext()

	// Load the BPF program into the kernel from an ELF.
	// ExecSnoopObjects contains all objects (BPF programs and maps) after they have been loaded into the kernel:
	// TracepointSyscallsSysEnterExecve and TracepointSyscallsSysExitExecve BPF programs,
	// Events and Execs BPF maps.
	objs := socket_lbObjects{}
	if err := loadSocket_lbObjects(&objs, nil); err != nil {
		log.Printf("failed to load BPF programs and maps: %v", err)
		return
	}

	if err := objs.Connect4Lb.Pin("/sys/fs/bpf/humanz_lb"); err != nil {
		log.Printf("failed to pin BPF programs and maps: %v", err)
		return
	}

	if err := objs.LB4SERVICES_MAP_V2.Pin("/sys/fs/bpf/humanz_lb_SVC"); err != nil {
		log.Printf("failed to pin BPF SVC: %v", err)
		return
	}

	if err := objs.LB4BACKEND_MAP.Pin("/sys/fs/bpf/humanz_lb_BE"); err != nil {
		log.Printf("failed to pin BPF BE: %v", err)
		return
	}

	newSvcKey := SvcKey{
		Address: IpToU32("100.0.0.10"), // virtual ip
		Dport:   PortToU16(8081),
		Pad:     uint16(0),
	}

	newSvcVal := SvcVal{
		Count: uint32(2),
	}

	if err := objs.LB4SERVICES_MAP_V2.Put(newSvcKey, newSvcVal); err != nil {
		log.Fatalf("Failed to put SVC map %v", err)
	}

	newBEVal_1 := LbBeVal{
		Address: IpToU32("200.0.0.40"), // backend 1
		Port:    PortToU16(8081),
		Pad:     uint16(0),
	}

	newBEVal_2 := LbBeVal{
		Address: IpToU32("200.0.0.60"), // backend 2
		Port:    PortToU16(8081),
		Pad:     uint16(0),
	}

	for i, v := range []LbBeVal{newBEVal_1, newBEVal_2} {
		if err := objs.LB4BACKEND_MAP.Put(uint32(i+1), v); err != nil {
			log.Fatalf("Failed to put LB map %v", err)
		}
	}

	// Housekeeping
	defer objs.Close()
	defer objs.Connect4Lb.Unpin()
	defer objs.LB4BACKEND_MAP.Unpin()
	defer objs.LB4SERVICES_MAP_V2.Unpin()
	// Wait until done
	<-ctx.Done()
}
