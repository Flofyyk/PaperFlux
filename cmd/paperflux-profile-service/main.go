package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"universal-bypass-tool/provision"
)

func main() {
	address := flag.String("listen", "0.0.0.0:24000", "Profile discovery TCP address")
	path := flag.String("profiles", "", "Private JSON profile source (0600)")
	flag.Parse()
	if *path == "" {
		log.Fatal("--profiles is required")
	}
	if _, err := provision.LoadFile(*path); err != nil {
		log.Fatal(err)
	}
	listener, err := net.Listen("tcp", *address)
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	log.Print("PaperFlux profile discovery started; encrypted configuration only")
	service := &provision.Service{Source: func() ([]provision.Profile, error) { return provision.LoadFile(*path) }}
	if err := service.Serve(ctx, listener); err != nil {
		log.Fatal(err)
	}
}
