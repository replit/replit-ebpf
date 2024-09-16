package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/replit/replit-ebpf/btrfswatch"
	ebpfpb "github.com/replit/replit-ebpf/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	socketName = "ebpf_test.sock"
	diskPath   = "disk.img"
)

var (
	client ebpfpb.EbpfClient

	tmpDir string

	devPath1 string
	devPath2 string
	dev1     uint32
	dev2     uint32
)

func TestMain(m *testing.M) {
	// os.Exit does not run defers, so we put TestMain's implementation in
	// a different function so defers are ran before we exit.
	os.Exit(testMain(m))
}

func testMain(m *testing.M) int {
	var err error
	tmpDir, err = os.MkdirTemp("", "ebpf-test")
	if err != nil {
		log.Fatal("Making temp dir:", err)
	}
	defer os.RemoveAll(tmpDir)

	mgr, err := btrfswatch.NewManager()
	if err != nil {
		log.Fatal("Initializing btrfswatch:", err)
	}

	ebpfService, err := ebpfpb.NewService(ebpfpb.ServiceOpts{
		BtrfswatchMgr: mgr,
	})
	if err != nil {
		log.Fatal("Starting eBPF gRPC service:", err)
	}

	socketPath := path.Join(tmpDir, socketName)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatal("Listen on unix socket:", err)
	}
	defer listener.Close()

	grpcS := grpc.NewServer()
	ebpfpb.RegisterEbpfServer(grpcS, ebpfService)

	go grpcS.Serve(listener)

	conn, err := grpc.Dial(
		socketPath,
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", addr)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatal("Creating gRPC client:", err)
	}
	defer conn.Close()

	client = ebpfpb.NewEbpfClient(conn)

	{
		cleanup, err := setupDevice(&devPath1, &dev1)
		if err != nil {
			log.Fatal("setupDevice:", err)
		}
		defer cleanup()
	}
	{
		cleanup, err := setupDevice(&devPath2, &dev2)
		if err != nil {
			log.Fatal("setupDevice:", err)
		}
		defer cleanup()
	}

	return m.Run()
}

func setupDevice(path *string, dev *uint32) (func() error, error) {
	out, err := exec.
		Command("sudo", "losetup", "-f", "--show", diskPath).
		CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("losetup %s: %w", string(out), err)
	}

	*path = strings.TrimSpace(string(out))

	stat, err := os.Stat(*path)
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}
	rdev := stat.Sys().(*syscall.Stat_t).Rdev
	*dev = convertDevice(rdev)

	return func() error {
		return exec.Command("sudo", "losetup", "-d", *path).Run()
	}, nil
}

func TestBasic(t *testing.T) {
	ctx := context.Background()

	devMajor := major(dev1)
	devMinor := minor(dev1)

	stream, err := client.MonitorBtrfs(ctx, &ebpfpb.MonitorBtrfsRequest{
		Major: devMajor,
		Minor: devMinor,
	})
	require.NoError(t, err)

	dir, err := os.MkdirTemp("", t.Name())
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	// this should error since the disk is corrupted
	err = exec.Command("mount", devPath1, dir).Run()
	require.Error(t, err)

	response, err := stream.Recv()
	require.NoError(t, err)

	assert.Equal(t, response.Major, devMajor)
	assert.Equal(t, response.Minor, devMinor)
}

func TestDemux(t *testing.T) {
	ctx := context.Background()

	devMajor1 := major(dev1)
	devMinor1 := minor(dev1)

	devMajor2 := major(dev2)
	devMinor2 := minor(dev2)

	stream1, err := client.MonitorBtrfs(ctx, &ebpfpb.MonitorBtrfsRequest{
		Major: devMajor1,
		Minor: devMinor1,
	})
	require.NoError(t, err)

	stream2, err := client.MonitorBtrfs(ctx, &ebpfpb.MonitorBtrfsRequest{
		Major: devMajor2,
		Minor: devMinor2,
	})

	dir, err := os.MkdirTemp("", t.Name())
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	// this should error since the disk is corrupted
	err = exec.Command("mount", devPath2, dir).Run()
	require.Error(t, err)

	// this should error since the disk is corrupted
	err = exec.Command("mount", devPath1, dir).Run()
	require.Error(t, err)

	{
		response, err := stream1.Recv()
		require.NoError(t, err)

		assert.Equal(t, response.Major, devMajor1)
		assert.Equal(t, response.Minor, devMinor1)
	}

	{
		response, err := stream2.Recv()
		require.NoError(t, err)

		assert.Equal(t, response.Major, devMajor2)
		assert.Equal(t, response.Minor, devMinor2)
	}
}

func TestMultipleSubsPerDevice(t *testing.T) {
	ctx := context.Background()

	devMajor := major(dev1)
	devMinor := minor(dev1)

	stream1, err := client.MonitorBtrfs(ctx, &ebpfpb.MonitorBtrfsRequest{
		Major: devMajor,
		Minor: devMinor,
	})
	require.NoError(t, err)

	stream2, err := client.MonitorBtrfs(ctx, &ebpfpb.MonitorBtrfsRequest{
		Major: devMajor,
		Minor: devMinor,
	})

	dir, err := os.MkdirTemp("", t.Name())
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	// this should error since the disk is corrupted
	err = exec.Command("mount", devPath1, dir).Run()
	require.Error(t, err)

	// both streams should receive despite only generating one message
	{
		response, err := stream1.Recv()
		require.NoError(t, err)

		assert.Equal(t, response.Major, devMajor)
		assert.Equal(t, response.Minor, devMinor)
	}

	{
		response, err := stream2.Recv()
		require.NoError(t, err)

		assert.Equal(t, response.Major, devMajor)
		assert.Equal(t, response.Minor, devMinor)
	}
}

func TestMultipleMessages(t *testing.T) {
	ctx := context.Background()

	devMajor := major(dev1)
	devMinor := minor(dev1)

	stream, err := client.MonitorBtrfs(ctx, &ebpfpb.MonitorBtrfsRequest{
		Major: devMajor,
		Minor: devMinor,
	})
	require.NoError(t, err)

	dir, err := os.MkdirTemp("", t.Name())
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	iters := 10
	doneChan := make(chan struct{})
	go func() {
		defer close(doneChan)

		for range iters {
			// this should error since the disk is corrupted
			err := exec.Command("mount", devPath1, dir).Run()
			require.Error(t, err)
		}
	}()

	for range iters {
		response, err := stream.Recv()
		require.NoError(t, err)

		assert.Equal(t, response.Major, devMajor)
		assert.Equal(t, response.Minor, devMinor)
	}

	<-doneChan
}

func TestMultipleConcurrentStreams(t *testing.T) {
	ctx := context.Background()

	devMajor1 := major(dev1)
	devMinor1 := minor(dev1)

	devMajor2 := major(dev2)
	devMinor2 := minor(dev2)

	stream1, err := client.MonitorBtrfs(ctx, &ebpfpb.MonitorBtrfsRequest{
		Major: devMajor1,
		Minor: devMinor1,
	})
	require.NoError(t, err)

	stream2, err := client.MonitorBtrfs(ctx, &ebpfpb.MonitorBtrfsRequest{
		Major: devMajor2,
		Minor: devMinor2,
	})
	require.NoError(t, err)

	var wg sync.WaitGroup

	dir, err := os.MkdirTemp("", t.Name())
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	iters := 10
	wg.Add(1)
	go func() {
		defer wg.Done()

		for range iters {
			// this should error since the disk is corrupted
			err := exec.Command("mount", devPath1, dir).Run()
			require.Error(t, err)

			// this should error since the disk is corrupted
			err = exec.Command("mount", devPath2, dir).Run()
			require.Error(t, err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		for range iters {
			response, err := stream1.Recv()
			require.NoError(t, err)

			assert.Equal(t, response.Major, devMajor1)
			assert.Equal(t, response.Minor, devMinor1)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		for range iters {
			response, err := stream2.Recv()
			require.NoError(t, err)

			assert.Equal(t, response.Major, devMajor2)
			assert.Equal(t, response.Minor, devMinor2)
		}
	}()

	wg.Wait()
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
