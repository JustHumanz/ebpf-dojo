// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"C"

	"github.com/cilium/ebpf"
)

type tc_natIcmpCtVal struct {
	SrcIp uint32
	Reply uint8
	_     [3]byte
}

type tc_natProtoCtKey struct {
	DstIp uint32
	Dport uint16
	Sport uint16
}

type tc_natProtoCtVal struct {
	SrcIp uint32
	Flag  uint16
	Pad   uint16
}

// loadTc_nat returns the embedded CollectionSpec for tc_nat.
func loadTc_nat() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Tc_natBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load tc_nat: %w", err)
	}

	return spec, err
}

// loadTc_natObjects loads tc_nat and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*tc_natObjects
//	*tc_natPrograms
//	*tc_natMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadTc_natObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadTc_nat()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// tc_natSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tc_natSpecs struct {
	tc_natProgramSpecs
	tc_natMapSpecs
}

// tc_natSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tc_natProgramSpecs struct {
	TcEgress  *ebpf.ProgramSpec `ebpf:"tc_egress"`
	TcIngress *ebpf.ProgramSpec `ebpf:"tc_ingress"`
}

// tc_natMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tc_natMapSpecs struct {
	ICMP_CT  *ebpf.MapSpec `ebpf:"ICMP_CT"`
	PROTO_CT *ebpf.MapSpec `ebpf:"PROTO_CT"`
}

// tc_natObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadTc_natObjects or ebpf.CollectionSpec.LoadAndAssign.
type tc_natObjects struct {
	tc_natPrograms
	tc_natMaps
}

func (o *tc_natObjects) Close() error {
	return _Tc_natClose(
		&o.tc_natPrograms,
		&o.tc_natMaps,
	)
}

// tc_natMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadTc_natObjects or ebpf.CollectionSpec.LoadAndAssign.
type tc_natMaps struct {
	ICMP_CT  *ebpf.Map `ebpf:"ICMP_CT"`
	PROTO_CT *ebpf.Map `ebpf:"PROTO_CT"`
}

func (m *tc_natMaps) Close() error {
	return _Tc_natClose(
		m.ICMP_CT,
		m.PROTO_CT,
	)
}

// tc_natPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadTc_natObjects or ebpf.CollectionSpec.LoadAndAssign.
type tc_natPrograms struct {
	TcEgress  *ebpf.Program `ebpf:"tc_egress"`
	TcIngress *ebpf.Program `ebpf:"tc_ingress"`
}

func (p *tc_natPrograms) Close() error {
	return _Tc_natClose(
		p.TcEgress,
		p.TcIngress,
	)
}

func _Tc_natClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed tc_nat_bpfel.o
var _Tc_natBytes []byte