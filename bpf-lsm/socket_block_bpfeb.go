// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64be || armbe || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadSocket_block returns the embedded CollectionSpec for socket_block.
func loadSocket_block() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Socket_blockBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load socket_block: %w", err)
	}

	return spec, err
}

// loadSocket_blockObjects loads socket_block and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*socket_blockObjects
//	*socket_blockPrograms
//	*socket_blockMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadSocket_blockObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadSocket_block()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// socket_blockSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type socket_blockSpecs struct {
	socket_blockProgramSpecs
	socket_blockMapSpecs
}

// socket_blockSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type socket_blockProgramSpecs struct {
	RestrictSocket *ebpf.ProgramSpec `ebpf:"restrict_socket"`
}

// socket_blockMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type socket_blockMapSpecs struct {
}

// socket_blockObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadSocket_blockObjects or ebpf.CollectionSpec.LoadAndAssign.
type socket_blockObjects struct {
	socket_blockPrograms
	socket_blockMaps
}

func (o *socket_blockObjects) Close() error {
	return _Socket_blockClose(
		&o.socket_blockPrograms,
		&o.socket_blockMaps,
	)
}

// socket_blockMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadSocket_blockObjects or ebpf.CollectionSpec.LoadAndAssign.
type socket_blockMaps struct {
}

func (m *socket_blockMaps) Close() error {
	return _Socket_blockClose()
}

// socket_blockPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadSocket_blockObjects or ebpf.CollectionSpec.LoadAndAssign.
type socket_blockPrograms struct {
	RestrictSocket *ebpf.Program `ebpf:"restrict_socket"`
}

func (p *socket_blockPrograms) Close() error {
	return _Socket_blockClose(
		p.RestrictSocket,
	)
}

func _Socket_blockClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed socket_block_bpfeb.o
var _Socket_blockBytes []byte
