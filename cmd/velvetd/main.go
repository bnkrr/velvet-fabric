package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	linuxbackend "github.com/velvet-fabric/velvet-fabric/internal/linux"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	velvetruntime "github.com/velvet-fabric/velvet-fabric/internal/runtime"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
)

func main() {
	configPath := flag.String("config", "", "path to a NodeSpec JSON file")
	once := flag.Bool("once", false, "exit after every configured adjacent Link is established")
	interval := flag.Duration("reconcile-interval", 15*time.Second, "kernel reconciliation interval")
	flag.Parse()
	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "velvetd: --config is required")
		os.Exit(2)
	}
	if *interval <= 0 {
		fmt.Fprintln(os.Stderr, "velvetd: --reconcile-interval must be positive")
		os.Exit(2)
	}
	nodeSpec, err := spec.Load(*configPath)
	if err != nil {
		log.Fatalf("velvetd: %v", err)
	}
	desired, err := reconcile.BuildDesiredState(nodeSpec)
	if err != nil {
		log.Fatalf("velvetd: %v", err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	encoder := json.NewEncoder(os.Stdout)
	var logMu sync.Mutex
	runner := velvetruntime.Runner{Desired: desired, Reconciler: reconcile.New(linuxbackend.New()), Interval: *interval, Log: func(event velvetruntime.Event) {
		logMu.Lock()
		defer logMu.Unlock()
		_ = encoder.Encode(event)
	}}
	if err := runner.Run(ctx, *once); err != nil && err != context.Canceled {
		log.Fatalf("velvetd: %v", err)
	}
}
