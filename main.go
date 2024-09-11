package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"

	"google.golang.org/grpc"

	"github.com/replit/replit-ebpf/btrfswatch"
	ebpfpb "github.com/replit/replit-ebpf/ebpf"
)

func main() {
	socketName := flag.String("socket-name", "/run/conman/conkid/ebpf.sock", "unix socket to listen on")
	flag.Parse()

	mgr, err := btrfswatch.NewManager()
	if err != nil {
		log.Fatal("Initializing btrfswatch:", err)
	}

	log.Printf("Listening at %s...", *socketName)

	// exit the program when interrupted.
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	ebpfService, err := ebpfpb.NewService(ebpfpb.ServiceOpts{
		BtrfswatchMgr: mgr,
	})
	if err != nil {
		log.Fatal("Starting eBPF gRPC service:", err)
	}

	listener, err := net.Listen("unix", *socketName)
	if err != nil {
		log.Fatal("Listen on unix socket:", err)
	}
	defer listener.Close()

	grpcS := grpc.NewServer()
	ebpfpb.RegisterEbpfServer(grpcS, ebpfService)

	go grpcS.Serve(listener)

	<-stop

	log.Println("Shutting down...")
	grpcS.GracefulStop()
	mgr.Close()
}
