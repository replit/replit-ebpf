// Package btrfswatch is a go wrapper for interfacing with the eBPF program in btrfswatch.c
package btrfswatch

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 btrfswatch btrfswatch.c

type Manager struct {
	objs     btrfswatchObjects
	cleanups []func() error
}

type Event btrfswatchEvent

type EventReader struct {
	rd *ringbuf.Reader
}

func NewManager() (*Manager, error) {
	mgr := &Manager{}

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("Removing memlock: %w", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	if err := loadBtrfswatchObjects(&mgr.objs, nil); err != nil {
		return nil, fmt.Errorf("Loading eBPF objects: %w", err)
	}
	mgr.cleanups = append(mgr.cleanups, mgr.objs.Close)

	// Attach count_packets to the network interface.
	{
		link, err := link.Kprobe("btrfs_recover_log_trees", mgr.objs.BtrfsRecoverLogTrees, &link.KprobeOptions{})
		if err != nil {
			return nil, fmt.Errorf("Attaching kprobe: %w", err)
		}
		mgr.cleanups = append(mgr.cleanups, link.Close)
	}

	{
		link, err := link.Kretprobe("btrfs_recover_log_trees", mgr.objs.BtrfsRecoverLogTreesExit, &link.KprobeOptions{})
		if err != nil {
			return nil, fmt.Errorf("Attaching kretprobe: %w", err)
		}
		mgr.cleanups = append(mgr.cleanups, link.Close)
	}

	return mgr, nil
}

func (mgr *Manager) RegisterDevice(dev uint32) (*EventReader, error) {
	err := mgr.objs.btrfswatchMaps.RegisteredDevices.Put(dev, true)
	if err != nil {
		return nil, fmt.Errorf("RegisteredDevices.Put: %w", err)
	}

	rd, err := ringbuf.NewReader(mgr.objs.BtrfsRecoverLogTreesErrors)
	if err != nil {
		return nil, fmt.Errorf("creating ringbuf reader: %w", err)
	}

	return &EventReader{rd}, nil
}

func (mgr *Manager) Close() error {
	slices.Reverse(mgr.cleanups)

	var errs []error
	for _, f := range mgr.cleanups {
		errs = append(errs, f())
	}

	return errors.Join(errs...)
}

func (evtrdr *EventReader) Read() (*Event, error) {
	record, err := evtrdr.rd.Read()
	if err != nil {
		return nil, err
	}

	var entry Event
	err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &entry)
	if err != nil {
		return nil, fmt.Errorf("decoding btrfswatch event: %w", err)
	}

	return &entry, nil
}

func (evtrdr *EventReader) Close() error {
	return evtrdr.rd.Close()
}
