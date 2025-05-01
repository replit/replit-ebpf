// Package ebpf defines a gRPC service that exposes eBPF functionality defined in other packages.
package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/replit/replit-ebpf/auditwatch"
	"github.com/replit/replit-ebpf/btrfswatch"
)

// Service is an implementation of ebpfpb.EbpfServer.
type Service struct {
	UnimplementedEbpfServer

	btrfswatchMgr *btrfswatch.Manager
	auditwatchMgr *auditwatch.Manager
}

// ServiceOpts are the options that can be provided to NewService.
type ServiceOpts struct {
	BtrfswatchMgr *btrfswatch.Manager
	AuditwatchMgr *auditwatch.Manager
}

// NewService returns a new instance of an Ebpf service.
func NewService(opts ServiceOpts) (*Service, error) {
	return &Service{
		btrfswatchMgr: opts.BtrfswatchMgr,
		auditwatchMgr: opts.AuditwatchMgr,
	}, nil
}

func (s *Service) MonitorBtrfs(
	r *MonitorBtrfsRequest,
	stream Ebpf_MonitorBtrfsServer,
) error {
	dev := (r.Major << 20) | r.Minor
	rd, err := s.btrfswatchMgr.RegisterDevice(dev)
	if err != nil {
		return fmt.Errorf("registering device: %w", err)
	}

	go func() {
		<-stream.Context().Done()
		rd.Close()
	}()

	for {
		select {
		case <-stream.Context().Done():
			return errors.New("stream context canceled")
		default:
		}

		entry, err := rd.Read(stream.Context())
		if err != nil {
			return fmt.Errorf("reading event: %w", err)
		}

		id, err := uuid.FromBytes(entry.Fsid[:])
		if err != nil {
			return fmt.Errorf("decoding fsid: %w", err)
		}

		err = stream.Send(&MonitorBtrfsResponse{
			Major: major(entry.DevId),
			Minor: minor(entry.DevId),
			Uuid:  id.String(),
			Ret:   entry.Ret,
		})
		if err != nil {
			return fmt.Errorf("stream send: %w", err)
		}
	}
}

func major(dev uint32) uint32 {
	return dev >> 20
}

func minor(dev uint32) uint32 {
	return dev & ((1 << 20) - 1)
}

func isCgroupEmpty(cgroupEventsPath string) (bool, error) {
	contents, err := os.ReadFile(cgroupEventsPath)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", cgroupEventsPath, err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(contents)), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		if key == "populated" && value == "0" {
			return true, nil
		}
	}
	return false, nil
}

func (s *Service) MonitorAppArmorAuditDenials(
	r *MonitorAppArmorAuditDenialsRequest,
	stream Ebpf_MonitorAppArmorAuditDenialsServer,
) error {
	if !strings.HasPrefix(r.CgroupName, "/") {
		return fmt.Errorf("cgroup name is not in the correct format")
	}
	cgroupPath := "/sys/fs/cgroup" + r.CgroupName
	cgroupEventsPath := path.Join(cgroupPath, "cgroup.events")
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("fsnotify.NewWatcher: %w", err)
	}
	defer watcher.Close()

	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if !event.Has(fsnotify.Write) {
					continue
				}
				empty, err := isCgroupEmpty(cgroupEventsPath)
				if err != nil {
					log.WithError(err).Error("isCgroupEmpty")
					return
				}
				if empty {
					cancel()
					return
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.WithError(err).Error("watch")
			}
		}
	}()
	err = watcher.Add(cgroupEventsPath)
	if err != nil {
		return fmt.Errorf("watcher.Add: %w", err)
	}

	handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, cgroupPath, 0)
	if err != nil {
		return fmt.Errorf("get cgroup handle: %w", err)
	}
	if handle.Size() != 8 {
		return fmt.Errorf("cgroup handle of incorrect size: %d", handle.Size())
	}
	cgroupId := binary.NativeEndian.Uint64(handle.Bytes())
	a, err := s.auditwatchMgr.RegisterCgroup(cgroupId)
	if err != nil {
		return fmt.Errorf("registering cgroup: %w", err)
	}
	defer a.Close()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		entry, err := a.Read(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return fmt.Errorf("reading event: %w", err)
		}

		err = stream.Send(&MonitorAppArmorAuditDenialsResponse{
			Path: unix.ByteSliceToString(entry.Path[:]),
		})
		if err != nil {
			return fmt.Errorf("stream send: %w", err)
		}
	}
}
