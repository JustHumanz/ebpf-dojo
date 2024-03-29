// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || loong64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type xdp_lbBackend struct {
	S_addr uint32
	S_mac  [6]uint8
	Pad    uint16
}

type xdp_lbCt struct {
	ClAddr uint32
	C_mac  [6]uint8
	_      [2]byte
	Be     xdp_lbBackend
}

type xdp_lbCtKey struct {
	Dst   uint32
	Dport uint16
	Sport uint16
}

type xdp_lbLbIp struct {
	LbMac   [6]uint8
	_       [2]byte
	BeCount uint32
}

// loadXdp_lb returns the embedded CollectionSpec for xdp_lb.
func loadXdp_lb() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Xdp_lbBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load xdp_lb: %w", err)
	}

	return spec, err
}

// loadXdp_lbObjects loads xdp_lb and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*xdp_lbObjects
//	*xdp_lbPrograms
//	*xdp_lbMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadXdp_lbObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadXdp_lb()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// xdp_lbSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type xdp_lbSpecs struct {
	xdp_lbProgramSpecs
	xdp_lbMapSpecs
}

// xdp_lbSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type xdp_lbProgramSpecs struct {
	LoadBalancer *ebpf.ProgramSpec `ebpf:"load_balancer"`
}

// xdp_lbMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type xdp_lbMapSpecs struct {
	LB4BE_XDP *ebpf.MapSpec `ebpf:"LB4_BE_XDP"`
	LB4CT_XDP *ebpf.MapSpec `ebpf:"LB4_CT_XDP"`
	LB4LB_XDP *ebpf.MapSpec `ebpf:"LB4_LB_XDP"`
}

// xdp_lbObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadXdp_lbObjects or ebpf.CollectionSpec.LoadAndAssign.
type xdp_lbObjects struct {
	xdp_lbPrograms
	xdp_lbMaps
}

func (o *xdp_lbObjects) Close() error {
	return _Xdp_lbClose(
		&o.xdp_lbPrograms,
		&o.xdp_lbMaps,
	)
}

// xdp_lbMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadXdp_lbObjects or ebpf.CollectionSpec.LoadAndAssign.
type xdp_lbMaps struct {
	LB4BE_XDP *ebpf.Map `ebpf:"LB4_BE_XDP"`
	LB4CT_XDP *ebpf.Map `ebpf:"LB4_CT_XDP"`
	LB4LB_XDP *ebpf.Map `ebpf:"LB4_LB_XDP"`
}

func (m *xdp_lbMaps) Close() error {
	return _Xdp_lbClose(
		m.LB4BE_XDP,
		m.LB4CT_XDP,
		m.LB4LB_XDP,
	)
}

// xdp_lbPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadXdp_lbObjects or ebpf.CollectionSpec.LoadAndAssign.
type xdp_lbPrograms struct {
	LoadBalancer *ebpf.Program `ebpf:"load_balancer"`
}

func (p *xdp_lbPrograms) Close() error {
	return _Xdp_lbClose(
		p.LoadBalancer,
	)
}

func _Xdp_lbClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed xdp_lb_bpfel.o
var _Xdp_lbBytes []byte
