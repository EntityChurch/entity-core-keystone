// Command host runs a standalone entity-core-protocol-go peer on a TCP port.
// It is the S4-ready conformance host: validate-peer dials it. Flags:
//
//	-port               TCP port to listen on (0 = auto-assign)
//	-seed               hex 32-byte Ed25519 seed (default: a fixed dev seed)
//	-debug-open-grants  mint the degenerate [default -> *] seed (reach write ops)
//	-validate           bootstrap the §7a system/validate/* conformance handlers
//
// On startup it prints a single line "LISTENING <port>" so a harness can learn
// the bound port, then serves until killed.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/entity-core/entity-core-protocol-go/peer"
)

func main() {
	port := flag.Int("port", 0, "TCP port to listen on (0 = auto)")
	seedHex := flag.String("seed", "", "hex 32-byte Ed25519 seed (default: fixed dev seed)")
	openGrants := flag.Bool("debug-open-grants", false, "mint the degenerate [default -> *] seed")
	validate := flag.Bool("validate", false, "bootstrap the §7a system/validate/* handlers")
	flag.Parse()

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 0x01 // fixed dev seed
	}
	if *seedHex != "" {
		raw, err := hex.DecodeString(*seedHex)
		if err != nil || len(raw) != 32 {
			fmt.Fprintln(os.Stderr, "host: -seed must be 64 hex chars (32 bytes)")
			os.Exit(2)
		}
		seed = raw
	}

	var opts []peer.Option
	if *openGrants {
		opts = append(opts, peer.WithOpenGrants())
	}
	if *validate {
		opts = append(opts, peer.WithConformance())
	}

	p, err := peer.NewPeer(seed, opts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "host: bootstrap:", err)
		os.Exit(1)
	}
	ln, err := p.Listen(*port)
	if err != nil {
		fmt.Fprintln(os.Stderr, "host: listen:", err)
		os.Exit(1)
	}
	defer ln.Close()

	fmt.Printf("LISTENING %d\n", ln.Port())
	fmt.Fprintf(os.Stderr, "host: peer %s on 127.0.0.1:%d\n", p.LocalPeer(), ln.Port())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}
