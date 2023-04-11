// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type socket_lbLb4Backend struct {
	Address uint32
	Port    uint16
	Pad     uint16
}

type socket_lbLb4Key struct {
	Address uint32
	Dport   uint16
	Pad     uint16
}

type socket_lbLb4Service struct{ Count uint32 }

// loadSocket_lb returns the embedded CollectionSpec for socket_lb.
func loadSocket_lb() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Socket_lbBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load socket_lb: %w", err)
	}

	return spec, err
}

// loadSocket_lbObjects loads socket_lb and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*socket_lbObjects
//	*socket_lbPrograms
//	*socket_lbMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadSocket_lbObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadSocket_lb()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// socket_lbSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type socket_lbSpecs struct {
	socket_lbProgramSpecs
	socket_lbMapSpecs
}

// socket_lbSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type socket_lbProgramSpecs struct {
	Connect4Lb *ebpf.ProgramSpec `ebpf:"connect4_lb"`
}

// socket_lbMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type socket_lbMapSpecs struct {
	LB4BACKEND_MAP     *ebpf.MapSpec `ebpf:"LB4_BACKEND_MAP"`
	LB4SERVICES_MAP_V2 *ebpf.MapSpec `ebpf:"LB4_SERVICES_MAP_V2"`
}

// socket_lbObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadSocket_lbObjects or ebpf.CollectionSpec.LoadAndAssign.
type socket_lbObjects struct {
	socket_lbPrograms
	socket_lbMaps
}

func (o *socket_lbObjects) Close() error {
	return _Socket_lbClose(
		&o.socket_lbPrograms,
		&o.socket_lbMaps,
	)
}

// socket_lbMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadSocket_lbObjects or ebpf.CollectionSpec.LoadAndAssign.
type socket_lbMaps struct {
	LB4BACKEND_MAP     *ebpf.Map `ebpf:"LB4_BACKEND_MAP"`
	LB4SERVICES_MAP_V2 *ebpf.Map `ebpf:"LB4_SERVICES_MAP_V2"`
}

func (m *socket_lbMaps) Close() error {
	return _Socket_lbClose(
		m.LB4BACKEND_MAP,
		m.LB4SERVICES_MAP_V2,
	)
}

// socket_lbPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadSocket_lbObjects or ebpf.CollectionSpec.LoadAndAssign.
type socket_lbPrograms struct {
	Connect4Lb *ebpf.Program `ebpf:"connect4_lb"`
}

func (p *socket_lbPrograms) Close() error {
	return _Socket_lbClose(
		p.Connect4Lb,
	)
}

func _Socket_lbClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed socket_lb_bpfel.o
var _Socket_lbBytes []byte
