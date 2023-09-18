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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang connect4_lb ./bpf/connect4_lb.c

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
	}

	ctx := newCancelableContext()

	// Load the BPF program into the kernel from an ELF.
	// ExecSnoopObjects contains all objects (BPF programs and maps) after they have been loaded into the kernel:
	// TracepointSyscallsSysEnterExecve and TracepointSyscallsSysExitExecve BPF programs,
	// Events and Execs BPF maps.
	objs := connect4_lbObjects{}
	if err := loadConnect4_lbObjects(&objs, nil); err != nil {
		log.Printf("failed to load BPF programs and maps: %v", err)
	}

	if err := objs.Connect4Lb.Pin("/sys/fs/bpf/humanz_lb"); err != nil {
		log.Printf("failed to pin BPF programs and maps: %v", err)
	}

	if err := objs.LB4SERVICES_MAP.Pin("/sys/fs/bpf/humanz_lb_SVC"); err != nil {
		log.Printf("failed to pin BPF SVC: %v", err)
	}

	if err := objs.LB4BACKEND_MAP.Pin("/sys/fs/bpf/humanz_lb_BE"); err != nil {
		log.Printf("failed to pin BPF BE: %v", err)
	}

	newSvcKey := connect4_lbLb4Key{
		Address: IpToU32("100.0.0.10"), // virtual ip
		Dport:   PortToU16(8081),
	}

	be := []connect4_lbLb4Backend{
		{
			Address: IpToU32("200.0.0.20"), // backend 1
			Port:    PortToU16(8081),
		},
		{
			Address: IpToU32("200.0.0.30"), // backend 2
			Port:    PortToU16(8081),
		},
	}

	if err := objs.LB4SERVICES_MAP.Put(newSvcKey, uint32(len(be))); err != nil {
		log.Fatalf("Failed to put SVC map %v", err)
	}

	for i, v := range be {
		if err := objs.LB4BACKEND_MAP.Put(uint32(i+1), v); err != nil {
			log.Fatalf("Failed to put LB map %v", err)
		}
	}

	// Housekeeping
	defer objs.Close()
	defer objs.Connect4Lb.Unpin()
	defer objs.LB4BACKEND_MAP.Unpin()
	defer objs.LB4SERVICES_MAP.Unpin()
	// Wait until done
	<-ctx.Done()
}
