// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package btrfswatch

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type btrfswatchEvent struct {
	Fsid  [16]uint8
	Label [256]int8
	DevId uint32
	Ret   int32
}

// loadBtrfswatch returns the embedded CollectionSpec for btrfswatch.
func loadBtrfswatch() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BtrfswatchBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load btrfswatch: %w", err)
	}

	return spec, err
}

// loadBtrfswatchObjects loads btrfswatch and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*btrfswatchObjects
//	*btrfswatchPrograms
//	*btrfswatchMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBtrfswatchObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBtrfswatch()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// btrfswatchSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type btrfswatchSpecs struct {
	btrfswatchProgramSpecs
	btrfswatchMapSpecs
}

// btrfswatchSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type btrfswatchProgramSpecs struct {
	BtrfsRecoverLogTrees     *ebpf.ProgramSpec `ebpf:"btrfs_recover_log_trees"`
	BtrfsRecoverLogTreesExit *ebpf.ProgramSpec `ebpf:"btrfs_recover_log_trees_exit"`
}

// btrfswatchMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type btrfswatchMapSpecs struct {
	BtrfsRecoverLogTreesErrors *ebpf.MapSpec `ebpf:"btrfs_recover_log_trees_errors"`
	PendingCalls               *ebpf.MapSpec `ebpf:"pending_calls"`
	RegisteredDevices          *ebpf.MapSpec `ebpf:"registered_devices"`
}

// btrfswatchObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBtrfswatchObjects or ebpf.CollectionSpec.LoadAndAssign.
type btrfswatchObjects struct {
	btrfswatchPrograms
	btrfswatchMaps
}

func (o *btrfswatchObjects) Close() error {
	return _BtrfswatchClose(
		&o.btrfswatchPrograms,
		&o.btrfswatchMaps,
	)
}

// btrfswatchMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBtrfswatchObjects or ebpf.CollectionSpec.LoadAndAssign.
type btrfswatchMaps struct {
	BtrfsRecoverLogTreesErrors *ebpf.Map `ebpf:"btrfs_recover_log_trees_errors"`
	PendingCalls               *ebpf.Map `ebpf:"pending_calls"`
	RegisteredDevices          *ebpf.Map `ebpf:"registered_devices"`
}

func (m *btrfswatchMaps) Close() error {
	return _BtrfswatchClose(
		m.BtrfsRecoverLogTreesErrors,
		m.PendingCalls,
		m.RegisteredDevices,
	)
}

// btrfswatchPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBtrfswatchObjects or ebpf.CollectionSpec.LoadAndAssign.
type btrfswatchPrograms struct {
	BtrfsRecoverLogTrees     *ebpf.Program `ebpf:"btrfs_recover_log_trees"`
	BtrfsRecoverLogTreesExit *ebpf.Program `ebpf:"btrfs_recover_log_trees_exit"`
}

func (p *btrfswatchPrograms) Close() error {
	return _BtrfswatchClose(
		p.BtrfsRecoverLogTrees,
		p.BtrfsRecoverLogTreesExit,
	)
}

func _BtrfswatchClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed btrfswatch_x86_bpfel.o
var _BtrfswatchBytes []byte
