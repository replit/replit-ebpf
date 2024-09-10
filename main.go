package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bdwatch bdwatch.c

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

func main() {
	device := flag.String("device", "", "device to watch")
	flag.Parse()

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs bdwatchObjects

	if err := loadBdwatchObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// Attach count_packets to the network interface.
	{
		link, err := link.Kprobe("btrfs_recover_log_trees", objs.BtrfsRecoverLogTrees, &link.KprobeOptions{})
		if err != nil {
			log.Fatal("Attaching kprobe:", err)
		}
		defer link.Close()
	}

	{
		link, err := link.Kretprobe("btrfs_recover_log_trees", objs.BtrfsRecoverLogTreesExit, &link.KprobeOptions{})
		if err != nil {
			log.Fatal("Attaching kretprobe:", err)
		}
		defer link.Close()
	}

	log.Println("Waiting...")

	// exit the program when interrupted.
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	stat, err := os.Stat(*device)
	if err != nil {
		panic(err)
	}
	dev := stat.Sys().(*syscall.Stat_t).Rdev
	fmt.Printf("dev %d %d:%d\n", dev, unix.Major(dev), unix.Minor(dev))
	err = objs.bdwatchMaps.RegisteredDevices.Put(convertDevice(stat.Sys().(*syscall.Stat_t).Rdev), true)
	if err != nil {
		panic(err)
	}

	rd, err := ringbuf.NewReader(objs.BtrfsRecoverLogTreesErrors)
	if err != nil {
		panic(err)
	}

	go func() {
		<-stop
		rd.Close()
	}()

	var entry bdwatchEvent
	for {
		select {
		case <-stop:
			return
		default:
		}
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			panic(err)
		}

		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &entry)
		if err != nil {
			panic(err)
		}

		id, err := uuid.FromBytes(entry.Fsid[:])
		if err != nil {
			panic(err)
		}
		log.Printf("Major:%d Minor:%d UUID:%s Ret: %d",
			major(entry.DevId),
			minor(entry.DevId),
			id,
			entry.Ret,
		)
	}
}

func major(dev uint32) uint32 {
	return dev >> 20
}
func minor(dev uint32) uint32 {
	return dev & ((1 << 20) - 1)
}
func convertDevice(dev uint64) uint32 {
	minor := uint32(unix.Minor(dev))
	major := uint32(unix.Major(dev))
	return (major << 20) | minor
}
