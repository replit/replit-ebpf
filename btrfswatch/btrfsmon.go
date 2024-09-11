// Package btrfswatch is a go wrapper for interfacing with the eBPF program in btrfswatch.c
package btrfswatch

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 btrfswatch btrfswatch.c

type Manager struct {
	objs     btrfswatchObjects
	cleanups []func() error
	demux    *eventDemux
}

type Event btrfswatchEvent

type eventDemux struct {
	rd *ringbuf.Reader

	devMapLock sync.RWMutex
	devMap     map[uint32]chan Event
}

type EventReader struct {
	dev       uint32
	eventChan chan Event
	mgr       *Manager
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

	rd, err := ringbuf.NewReader(mgr.objs.BtrfsRecoverLogTreesErrors)
	if err != nil {
		return nil, fmt.Errorf("creating ringbuf reader: %w", err)
	}
	mgr.demux = newEventDemux(rd)
	mgr.cleanups = append(mgr.cleanups, mgr.demux.close)
	go mgr.demux.run()

	return mgr, nil
}

func (mgr *Manager) RegisterDevice(dev uint32) (*EventReader, error) {
	err := mgr.objs.btrfswatchMaps.RegisteredDevices.Put(dev, true)
	if err != nil {
		return nil, fmt.Errorf("RegisteredDevices.Put: %w", err)
	}

	eventChan := make(chan Event, 1)
	mgr.demux.addDevice(dev, eventChan)

	return &EventReader{
		dev:       dev,
		eventChan: eventChan,
		mgr:       mgr,
	}, nil
}

func (mgr *Manager) UnregisterDevice(dev uint32) error {
	err := mgr.objs.btrfswatchMaps.RegisteredDevices.Delete(dev)
	if err != nil {
		return fmt.Errorf("RegisteredDevices.Delete: %w", err)
	}

	mgr.demux.removeDevice(dev)
	return nil
}

func (mgr *Manager) Close() error {
	slices.Reverse(mgr.cleanups)

	var errs []error
	for _, f := range mgr.cleanups {
		errs = append(errs, f())
	}

	return errors.Join(errs...)
}

func newEventDemux(rd *ringbuf.Reader) *eventDemux {
	return &eventDemux{
		rd:     rd,
		devMap: make(map[uint32]chan Event),
	}
}

func (demux *eventDemux) addDevice(dev uint32, eventChan chan Event) {
	demux.devMapLock.Lock()
	defer demux.devMapLock.Unlock()

	demux.devMap[dev] = eventChan
}

func (demux *eventDemux) removeDevice(dev uint32) {
	demux.devMapLock.Lock()
	defer demux.devMapLock.Unlock()

	delete(demux.devMap, dev)
}

func (demux *eventDemux) run() error {
	for {
		record, err := demux.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("reading ringbuf: %w", err)
		}

		var entry Event
		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &entry)
		if err != nil {
			return fmt.Errorf("decoding btrfswatch event: %w", err)
		}

		demux.devMapLock.RLock()

		c, ok := demux.devMap[entry.DevId]
		if !ok {
			return fmt.Errorf("devid %d does not exist", entry.DevId)
		}

		// don't block other streams while waiting for one
		select {
		case c <- entry:
		default:
		}

		demux.devMapLock.RUnlock()
	}
}

func (demux *eventDemux) close() error {
	return demux.rd.Close()
}

func (evtrdr *EventReader) Read() (*Event, error) {
	event, ok := <-evtrdr.eventChan
	if !ok {
		return nil, errors.New("reader is closed")
	}

	return &event, nil
}

func (evtrdr *EventReader) Close() error {
	evtrdr.mgr.UnregisterDevice(evtrdr.dev)
	close(evtrdr.eventChan)
	return nil
}
