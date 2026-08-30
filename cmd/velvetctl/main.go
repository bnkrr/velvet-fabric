package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/control"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
)

type resolvedLink struct {
	PeerName         string   `json:"peer_name"`
	InterfaceName    string   `json:"interface_name"`
	ListenPort       int      `json:"listen_port"`
	BootstrapAddress string   `json:"bootstrap_address"`
	VFPDiscovery     string   `json:"vfp_discovery"`
	Endpoints        []string `json:"endpoints"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "resolve":
		resolve(os.Args[2:])
	case "status", "reload", "shutdown":
		request(os.Args[1], os.Args[2:])
	default:
		usage()
	}
}

func resolve(arguments []string) {
	flags := flag.NewFlagSet("resolve", flag.ExitOnError)
	configPath := flags.String("config", "", "path to a NodeSpec JSON file")
	_ = flags.Parse(arguments)
	if *configPath == "" {
		fatal("velvetctl resolve: --config is required")
	}
	nodeSpec, err := spec.Load(*configPath)
	if err != nil {
		fatal("velvetctl resolve: %v", err)
	}
	desired, err := reconcile.BuildDesiredState(nodeSpec)
	if err != nil {
		fatal("velvetctl resolve: %v", err)
	}
	links := make([]resolvedLink, 0, len(desired.Links))
	for _, item := range desired.Links {
		links = append(links, resolvedLink{PeerName: item.PeerName, InterfaceName: item.InterfaceName, ListenPort: item.ListenPort, BootstrapAddress: item.BootstrapAddress.String(), VFPDiscovery: "ipv6-link-local-multicast", Endpoints: append([]string(nil), item.Endpoints...)})
	}
	result := map[string]any{
		"api_version": spec.APIVersion, "node_uid": desired.UID,
		"loopback_v6": desired.LoopbackV6.String(), "loopback_interface": reconcile.LoopbackInterface,
		"vfp_port": desired.VFPPort, "fabric_table_id": desired.FabricTableID, "links": links,
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
}

func request(command string, arguments []string) {
	flags := flag.NewFlagSet(command, flag.ExitOnError)
	socket := flags.String("socket", "", "velvetd control socket")
	configPath := flags.String("config", "", "derive the control socket from this NodeSpec")
	_ = flags.Parse(arguments)
	if *socket == "" && *configPath != "" {
		nodeSpec, err := spec.Load(*configPath)
		if err != nil {
			fatal("velvetctl %s: %v", command, err)
		}
		*socket = filepath.Join("/run/velvet", nodeSpec.Node.UID.UUID, "velvetd.ctl")
	}
	if *socket == "" {
		fatal("velvetctl %s: --socket or --config is required", command)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var result any
	if err := control.Request(ctx, *socket, command, &result); err != nil {
		fatal("velvetctl %s: %v", command, err)
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: velvetctl <resolve|status|reload|shutdown> [options]")
	os.Exit(2)
}

func fatal(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}
