package main

import (
	"flag"
	"net"
	"os"
	"os/signal"
	"path"

	"github.com/coreos/go-systemd/v22/activation"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/replit/replit-ebpf/btrfswatch"
	ebpfpb "github.com/replit/replit-ebpf/ebpf"
)

func main() {
	socketName := flag.String("socket-name", "", "unix socket to listen on")
	logJSON := flag.Bool("log-json", false, "format log messages as JSON")
	flag.Parse()

	if *logJSON {
		log.SetFormatter(&log.JSONFormatter{})
	} else {
		log.SetFormatter(&log.TextFormatter{ForceColors: true})
	}

	mgr, err := btrfswatch.NewManager()
	if err != nil {
		log.WithError(err).Fatal("Initializing btrfswatch")
	}

	// exit the program when interrupted.
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	ebpfService, err := ebpfpb.NewService(ebpfpb.ServiceOpts{
		BtrfswatchMgr: mgr,
	})
	if err != nil {
		log.WithError(err).Fatal("Starting eBPF gRPC service")
	}

	var listener net.Listener
	if *socketName == "" {
		listeners, err := activation.Listeners()
		if err != nil {
			log.WithError(err).Fatal("Getting systemd sockets")
		}
		if len(listeners) != 1 {
			log.Fatalf("Wrong number of sockets, got %d", len(listeners))
		}

		listener = listeners[0]
	} else {
		err = os.MkdirAll(path.Dir(*socketName), 0o755)
		if err != nil {
			log.WithError(err).Fatal("Creating socket directory")
		}
		err = os.RemoveAll(*socketName)
		if err != nil {
			log.WithError(err).Fatal("Removing socket")
		}

		listener, err = net.Listen("unix", *socketName)
		if err != nil {
			log.WithError(err).Fatal("Listen on unix socket")
		}
		defer listener.Close()
	}

	log.Infof("Listening at %s...", listener.Addr().String())

	grpcS := grpc.NewServer()
	ebpfpb.RegisterEbpfServer(grpcS, ebpfService)

	go grpcS.Serve(listener)

	<-stop

	log.Infoln("Shutting down...")
	grpcS.GracefulStop()
	mgr.Close()
}
