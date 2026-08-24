// Command host runs a standalone entity-core-protocol-go peer on a TCP port.
// It is the S4-ready conformance host: validate-peer dials it. Flags:
//
//	-port               TCP port to listen on (0 = auto-assign)
//	-name               load a persistent Ed25519 identity from the standard
//	                    on-disk location ~/.entity/peers/NAME/keypair (the
//	                    entity-core PEM keypair: base64 of a 32-byte seed — the
//	                    convention the Go entity-peer --name and peer-manager use)
//	-seed               hex 32-byte Ed25519 seed (additive override; default is
//	                    0x11 x 32, the cohort responder seed — peer_id byte-stable)
//	-debug-open-grants  mint the degenerate [default -> *] seed (reach write ops)
//	-validate           bootstrap the §7a system/validate/* conformance handlers
//
// On startup it prints a single line "LISTENING <port>" so a harness can learn
// the bound port, then serves until killed.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/entity-core/entity-core-protocol-go/peer"
)

// loadSeedFromName loads the 32-byte Ed25519 seed from the standard on-disk
// keypair (Go entity-peer --name / peer-manager convention):
// ~/.entity/peers/NAME/keypair, a PEM whose body is base64(seed) between
// BEGIN/END ENTITY PRIVATE KEY lines.
func loadSeedFromName(name string) []byte {
	home := os.Getenv("HOME")
	if home == "" {
		home = "/root"
	}
	path := filepath.Join(home, ".entity", "peers", name, "keypair")
	pem, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "host: --name %s: %v\n", name, err)
		os.Exit(2)
	}
	var body strings.Builder
	for _, line := range strings.Split(string(pem), "\n") {
		if strings.HasPrefix(line, "-----") {
			continue
		}
		body.WriteString(strings.TrimSpace(line))
	}
	seed, err := base64.StdEncoding.DecodeString(body.String())
	if err != nil {
		fmt.Fprintf(os.Stderr, "host: --name %s: base64: %v\n", name, err)
		os.Exit(2)
	}
	if len(seed) != 32 {
		fmt.Fprintf(os.Stderr, "host: --name %s: expected a 32-byte seed, got %d bytes\n", name, len(seed))
		os.Exit(2)
	}
	return seed
}

func main() {
	port := flag.Int("port", 0, "TCP port to listen on (0 = auto)")
	name := flag.String("name", "", "load persistent identity from ~/.entity/peers/NAME/keypair")
	seedHex := flag.String("seed", "", "hex 32-byte Ed25519 seed (additive override)")
	openGrants := flag.Bool("debug-open-grants", false, "mint the degenerate [default -> *] seed")
	validate := flag.Bool("validate", false, "bootstrap the §7a system/validate/* handlers")
	flag.Parse()

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 0x11 // fixed test seed → stable peer_id (cohort responder seed)
	}
	if *name != "" {
		seed = loadSeedFromName(*name)
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
