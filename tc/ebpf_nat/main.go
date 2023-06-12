package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
)

const Egress = "egress"
const Ingress = "ingress"

type Icmp_CT struct {
	src_ip uint32 `align:"src_ip"`
	reply  uint8  `align:"reply"`
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tc_nat ./tc_nat.c

func GenereateSpec(Name string, bpf_program *ebpf.Program, AttachTo string) ebpf.ProgramSpec {
	return ebpf.ProgramSpec{
		Name: Name,
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			// set exit code to 0
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License:      "GPL",
		AttachTarget: bpf_program,
		AttachTo:     AttachTo,
	}
}

func main() {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Printf("failed to set temporary RLIMIT_MEMLOCK: %v", err)
		return
	}

	// Load the BPF program into the kernel from an ELF.
	objs := tc_natObjects{}

	ifaceName := "virbr2"
	devID, err := net.InterfaceByName(ifaceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not get interface ID: %v\n", err)
		return
	}

	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open rtnetlink socket: %v\n", err)
		return
	}
	defer func() {
		if err := tcnl.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "could not close rtnetlink socket: %v\n", err)
		}
	}()

	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
			Parent:  tc.HandleIngress,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}

	if err := tcnl.Qdisc().Add(&qdisc); err != nil {
		fmt.Fprintf(os.Stderr, "could not assign clsact to %s: %v\n", ifaceName, err)
		return
	}

	for _, v := range []string{Ingress, Egress} {
		fmt.Println("Setup", v)
		// Handcraft a eBPF program for the example.
		spec := GenereateSpec(fmt.Sprintf("tc_%s", v), objs.TcEgress, v)

		// Load the eBPF program into the kernel.
		prog, err := ebpf.NewProgram(&spec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load eBPF program: %v\n", err)
			return
		}

		fd := uint32(prog.FD())
		flags := uint32(0x1)

		filter := tc.Object{
			tc.Msg{
				Family:  unix.AF_UNSPEC,
				Ifindex: uint32(devID.Index),
				Handle:  0,
				Parent: func() uint32 {
					if v == Ingress {
						return core.BuildHandle(tc.HandleRoot, tc.HandleMinIngress)
					}
					return core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress)
				}(),
				Info: 0x300,
			},
			tc.Attribute{
				Kind: "bpf",
				BPF: &tc.Bpf{
					FD:    &fd,
					Flags: &flags,
				},
			},
		}

		//Attach the Egress
		if err := tcnl.Filter().Add(&filter); err != nil {
			fmt.Fprintf(os.Stderr, "could not attach filter for eBPF program: %v\n", err)
			return
		}
	}

	for {
		var (
			val     = make([]interface{}, 0)
			key     = make([]interface{}, 0)
			nextKey uint32
		)

		_, err = objs.ICMP_CT.BatchLookup(nil, &nextKey, key, val, nil)
		if err != nil {
			log.Fatal(err)
		}

		for i := 0; i < len(key); i++ {
			fmt.Println(key[i], val[i])
		}

		time.Sleep(10)
	}
}
