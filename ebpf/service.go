// Package ebpf defines a gRPC service that exposes eBPF functionality defined in other packages.
package ebpf

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/uuid"

	"github.com/replit/replit-ebpf/btrfswatch"
)

// Service is an implementation of ebpfpb.EbpfServer.
type Service struct {
	UnimplementedEbpfServer

	stop          <-chan (os.Signal)
	btrfswatchMgr *btrfswatch.Manager
}

// ServiceOpts are the options that can be provided to NewService.
type ServiceOpts struct {
	Stop          <-chan (os.Signal)
	BtrfswatchMgr *btrfswatch.Manager
}

// NewService returns a new instance of an Ebpf service.
func NewService(opts ServiceOpts) (*Service, error) {
	return &Service{
		stop:          opts.Stop,
		btrfswatchMgr: opts.BtrfswatchMgr,
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
		<-s.stop
		rd.Close()
	}()

	for {
		select {
		case <-s.stop:
			return errors.New("received stop signal, shutting down")
		default:
		}

		entry, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("reading ringbuf: %w", err)
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
