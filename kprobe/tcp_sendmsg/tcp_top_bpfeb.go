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

type tcp_topIpKeyT struct {
	Saddr uint32
	Daddr uint32
	Pid   uint32
	Lport uint16
	Dport uint16
}

type tcp_topTrafficT struct {
	Sent     uint64
	Received uint64
}

// loadTcp_top returns the embedded CollectionSpec for tcp_top.
func loadTcp_top() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Tcp_topBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load tcp_top: %w", err)
	}

	return spec, err
}

// loadTcp_topObjects loads tcp_top and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*tcp_topObjects
//	*tcp_topPrograms
//	*tcp_topMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadTcp_topObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadTcp_top()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// tcp_topSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tcp_topSpecs struct {
	tcp_topProgramSpecs
	tcp_topMapSpecs
}

// tcp_topSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tcp_topProgramSpecs struct {
	TcpCleanupRbuf *ebpf.ProgramSpec `ebpf:"tcp_cleanup_rbuf"`
	TcpSendmsg     *ebpf.ProgramSpec `ebpf:"tcp_sendmsg"`
}

// tcp_topMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tcp_topMapSpecs struct {
	IP_MAP *ebpf.MapSpec `ebpf:"IP_MAP"`
}

// tcp_topObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadTcp_topObjects or ebpf.CollectionSpec.LoadAndAssign.
type tcp_topObjects struct {
	tcp_topPrograms
	tcp_topMaps
}

func (o *tcp_topObjects) Close() error {
	return _Tcp_topClose(
		&o.tcp_topPrograms,
		&o.tcp_topMaps,
	)
}

// tcp_topMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadTcp_topObjects or ebpf.CollectionSpec.LoadAndAssign.
type tcp_topMaps struct {
	IP_MAP *ebpf.Map `ebpf:"IP_MAP"`
}

func (m *tcp_topMaps) Close() error {
	return _Tcp_topClose(
		m.IP_MAP,
	)
}

// tcp_topPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadTcp_topObjects or ebpf.CollectionSpec.LoadAndAssign.
type tcp_topPrograms struct {
	TcpCleanupRbuf *ebpf.Program `ebpf:"tcp_cleanup_rbuf"`
	TcpSendmsg     *ebpf.Program `ebpf:"tcp_sendmsg"`
}

func (p *tcp_topPrograms) Close() error {
	return _Tcp_topClose(
		p.TcpCleanupRbuf,
		p.TcpSendmsg,
	)
}

func _Tcp_topClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed tcp_top_bpfeb.o
var _Tcp_topBytes []byte
