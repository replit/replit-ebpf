// Package auditwatch is a go wrapper for interfacing with the eBPF program in auditwatch.c
package auditwatch

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 auditwatch auditwatch.c

type Manager struct {
	objs     auditwatchObjects
	cleanups []func() error
	demux    *eventDemux
}

type Event auditwatchEvent

type eventDemux struct {
	rd *ringbuf.Reader

	cgroupMapLock sync.RWMutex
	cgroupMap     map[uint64]map[chan Event]struct{}
}

type EventReader struct {
	cgroupId  uint64
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
	if err := loadAuditwatchObjects(&mgr.objs, nil); err != nil {
		return nil, fmt.Errorf("Loading eBPF objects: %w", err)
	}
	mgr.cleanups = append(mgr.cleanups, mgr.objs.Close)

	{
		link, err := link.Kprobe("common_lsm_audit", mgr.objs.CommonLsmAudit, &link.KprobeOptions{})
		if err != nil {
			return nil, fmt.Errorf("Attaching kprobe: %w", err)
		}
		mgr.cleanups = append(mgr.cleanups, link.Close)
	}

	rd, err := ringbuf.NewReader(mgr.objs.ApparmorDenials)
	if err != nil {
		return nil, fmt.Errorf("creating ringbuf reader: %w", err)
	}
	mgr.demux = newEventDemux(rd)
	mgr.cleanups = append(mgr.cleanups, mgr.demux.close)
	go func() {
		err := mgr.demux.run()
		if err != nil {
			log.WithError(err).Error("demux.run")
		}
	}()

	return mgr, nil
}

func (mgr *Manager) RegisterCgroup(cgroupId uint64) (*EventReader, error) {
	err := mgr.objs.auditwatchMaps.RegisteredCgroups.Put(cgroupId, true)
	if err != nil {
		return nil, fmt.Errorf("RegisteredCgroups.Put: %w", err)
	}

	eventChan := make(chan Event, 1)
	mgr.demux.addCgroup(cgroupId, eventChan)

	return &EventReader{
		cgroupId:  cgroupId,
		eventChan: eventChan,
		mgr:       mgr,
	}, nil
}

func (mgr *Manager) UnregisterCgroup(cgroupId uint64, eventChan chan Event) error {
	err := mgr.objs.auditwatchMaps.RegisteredCgroups.Delete(cgroupId)
	if err != nil {
		return fmt.Errorf("RegisteredCgroups.Delete: %w", err)
	}

	mgr.demux.removeCgroup(cgroupId, eventChan)
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
		rd:        rd,
		cgroupMap: make(map[uint64]map[chan Event]struct{}),
	}
}

func (demux *eventDemux) addCgroup(cgroupId uint64, eventChan chan Event) {
	demux.cgroupMapLock.Lock()
	defer demux.cgroupMapLock.Unlock()

	if demux.cgroupMap[cgroupId] == nil {
		demux.cgroupMap[cgroupId] = make(map[chan Event]struct{})
	}

	demux.cgroupMap[cgroupId][eventChan] = struct{}{}
}

func (demux *eventDemux) removeCgroup(cgroupId uint64, eventChan chan Event) {
	demux.cgroupMapLock.Lock()
	defer demux.cgroupMapLock.Unlock()

	delete(demux.cgroupMap[cgroupId], eventChan)

	if demux.cgroupMap[cgroupId] == nil {
		delete(demux.cgroupMap, cgroupId)
	}
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
			return fmt.Errorf("decoding auditwatch event: %w", err)
		}

		err = func() error {
			demux.cgroupMapLock.RLock()
			defer demux.cgroupMapLock.RUnlock()

			chans, ok := demux.cgroupMap[entry.CgroupId]
			if !ok {
				return fmt.Errorf("devid %d does not exist", entry.CgroupId)
			}

			for c := range chans {
				// don't block other streams while waiting for one
				select {
				case c <- entry:
				default:
					log.
						WithField("cgroup", entry.CgroupId).
						Warn("dropping message")
				}
			}

			return nil
		}()
		if err != nil {
			return err
		}
	}
}

func (demux *eventDemux) close() error {
	return demux.rd.Close()
}

func (evtrdr *EventReader) Read(ctx context.Context) (*Event, error) {
	select {
	case event, ok := <-evtrdr.eventChan:
		if !ok {
			return nil, errors.New("reader is closed")
		}
		return &event, nil

	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (evtrdr *EventReader) Close() error {
	evtrdr.mgr.UnregisterCgroup(evtrdr.cgroupId, evtrdr.eventChan)
	close(evtrdr.eventChan)
	return nil
}
