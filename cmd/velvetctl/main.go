package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
)

type resolvedLink struct {
	PeerName         string   `json:"peer_name"`
	InterfaceName    string   `json:"interface_name"`
	ListenPort       int      `json:"listen_port"`
	BootstrapAddress string   `json:"bootstrap_address"`
	BootstrapPeer    string   `json:"bootstrap_peer"`
	VFPRole          string   `json:"vfp_role"`
	Endpoints        []string `json:"endpoints"`
}

func main() {
	if len(os.Args) < 2 || os.Args[1] != "resolve" {
		fmt.Fprintln(os.Stderr, "usage: velvetctl resolve --config PATH")
		os.Exit(2)
	}
	flags := flag.NewFlagSet("resolve", flag.ExitOnError)
	configPath := flags.String("config", "", "path to a NodeSpec JSON file")
	_ = flags.Parse(os.Args[2:])
	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "velvetctl resolve: --config is required")
		os.Exit(2)
	}
	nodeSpec, err := spec.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "velvetctl resolve: %v\n", err)
		os.Exit(1)
	}
	desired, err := reconcile.BuildDesiredState(nodeSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "velvetctl resolve: %v\n", err)
		os.Exit(1)
	}
	links := make([]resolvedLink, 0, len(desired.Links))
	for _, item := range desired.Links {
		role := "listener"
		if item.Dialer {
			role = "dialer"
		}
		links = append(links, resolvedLink{PeerName: item.PeerName, InterfaceName: item.InterfaceName, ListenPort: item.ListenPort, BootstrapAddress: item.BootstrapAddress.String(), BootstrapPeer: item.BootstrapPeer.String(), VFPRole: role, Endpoints: append([]string(nil), item.Endpoints...)})
	}
	result := map[string]any{
		"api_version":     spec.APIVersion,
		"node_uid":        desired.UID,
		"loopback_v6":     desired.LoopbackV6.String(),
		"vfp_port":        desired.VFPPort,
		"fabric_table_id": desired.FabricTableID,
		"links":           links,
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
}
