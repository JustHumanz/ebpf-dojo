package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate sh -c "echo Generating for amd64"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang socket_block ./bpf/socket_block.c -- -DOUTPUT_SKB -D__TARGET_ARCH_x86

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

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	ctx := newCancelableContext()

	spec, err := loadSocket_block()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("set target_uid")
	if err := spec.RewriteConstants(map[string]interface{}{
		"target_uid":     uint32(1000),
		"target_blocked": uint16(8811),
	}); err != nil {
		log.Fatal(err)
	}

	objs := socket_blockObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	lsm_socket_block, err := link.AttachLSM(link.LSMOptions{
		Program: objs.RestrictSocket,
	})
	if err != nil {
		log.Fatal(err)
	}

	defer lsm_socket_block.Close()
	<-ctx.Done()

}
