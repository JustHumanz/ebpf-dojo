package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

/*
#include <time.h>
static unsigned long long get_nsecs(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000UL + ts.tv_nsec;
}
*/
import "C"

type Icmp_ct struct {
	Src_ip uint32 `align:"src_ip"`
	Reply  uint32 `align:"reply"`
	Ts     uint64 `align:"ts"`
}

type Proto_ct struct {
	Dst_ip uint32 `align:"dst_ip"`
	Dport  uint16 `align:"dport"`
	Sport  uint16 `align:"sport"`
	Proto  uint32 `align:"proto"`
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

func LoadMap(mapid int) *ebpf.Map {
	m, err := ebpf.NewMapFromID(ebpf.MapID(mapid))
	if err != nil {
		log.Fatalf("bpf map(%d) not found, err: %v", mapid, err)
	}
	return m
}
func main() {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Printf("failed to set temporary RLIMIT_MEMLOCK: %v", err)
		return
	}

	ctx := newCancelableContext()
	IcmpBpfMap := LoadMap(171) //bpftool map list | grep ICMP_CT | awk -F ":" '{print $1}'
	UdpBpfMap := LoadMap(172)

	IcmpTimeout := 20 //sec

	go func() {
		for {
			var (
				nextkey uint16
				nextval Icmp_ct
				entries = IcmpBpfMap.Iterate()
				now     = uint64(C.get_nsecs())
			)

			fmt.Println("Cleaning ICMP CT")
			for entries.Next(&nextkey, &nextval) {
				ts := (now - nextval.Ts) / 1000000000
				fmt.Println("Deleting", nextkey)

				if ts >= uint64(IcmpTimeout) {
					err := IcmpBpfMap.Delete(nextkey)
					if err != nil {
						log.Fatal(err)
					}
				}
			}

			time.Sleep(time.Duration(IcmpTimeout) * time.Second)

		}
	}()

	UDPTimeout := 30 //sec
	go func() {
		for {
			var (
				nextkey Proto_ct
				nextval Icmp_ct
				entries = UdpBpfMap.Iterate()
				now     = uint64(C.get_nsecs())
			)

			fmt.Println("Cleaning UDP CT")
			for entries.Next(&nextkey, &nextval) {
				ts := (now - nextval.Ts) / 1000000000
				fmt.Println("Deleting", nextkey)
				if ts >= uint64(UDPTimeout) {
					err := UdpBpfMap.Delete(nextkey)
					if err != nil {
						log.Fatal(err)
					}
				}
			}

			time.Sleep(time.Duration(UDPTimeout) * time.Second)
		}
	}()

	<-ctx.Done()
}
