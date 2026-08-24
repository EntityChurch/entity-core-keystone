package host

// entity-core-protocol-odin — standalone peer host.
//
// The runnable target for S4 conformance: boots a single Peer listener on a TCP
// port and blocks until signalled, so an external oracle (entity-core-go
// `validate-peer`) can drive the live wire surface against it.
//
//   --port N               listen port (default 7777; 0 = auto-assign)
//   --name NAME            load a persistent Ed25519 identity from the standard
//                          on-disk location ~/.entity/peers/NAME/keypair (the
//                          entity-core PEM keypair: base64 of a 32-byte seed
//                          between BEGIN/END ENTITY PRIVATE KEY lines — the same
//                          convention the Go entity-peer --name / peer-manager use)
//   --debug-open-grants    select the degenerate `default → *` seed policy
//   --validate             register the §7a system/validate/* conformance handlers
//                          (off by default; dispatch-outbound is a standing dialer)
//
// Binds loopback (127.0.0.1); run the validator in the same network namespace. A
// single `LISTENING …` line goes to stdout once bound — a run script waits for it.

import ec "../src"
import "core:crypto"
import "core:encoding/base64"
import "core:fmt"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:thread"

Conn_State :: struct {
	io:   ec.Io,
	conn: ec.Conn,
	sock: net.TCP_Socket,
}

serve_connection :: proc(peer: ^ec.Peer, sock: net.TCP_Socket) {
	ec.set_no_delay(sock) // low-latency request/response (§7b handshake churn)
	cs := new(Conn_State)
	cs.sock = sock
	cs.io = ec.io_init(sock)
	cs.conn = ec.Conn{}
	ec.read_loop(peer, &cs.conn, &cs.io) // blocks until close
	ec.io_destroy(&cs.io)
	ec.conn_destroy(&cs.conn)
	net.close(sock)
	free(cs)
}

main :: proc() {
	port := 7777
	open_grants := false
	validate := false
	seed := random_seed()

	args := os.args
	i := 1
	for i < len(args) {
		arg := args[i]
		switch arg {
		case "--port":
			if i + 1 >= len(args) {
				fmt.eprintln("error: --port requires an integer")
				os.exit(2)
			}
			p, ok := strconv.parse_int(args[i + 1])
			if !ok {
				fmt.eprintln("error: bad --port value")
				os.exit(2)
			}
			port = p
			i += 1
		case "--name":
			if i + 1 >= len(args) {
				fmt.eprintln("error: --name requires a value")
				os.exit(2)
			}
			seed = load_seed_from_name(args[i + 1])
			i += 1
		case "--debug-open-grants":
			open_grants = true
		case "--validate":
			validate = true
		case "-h", "--help":
			fmt.println("usage: entity-core-peer [--port N] [--name NAME] [--debug-open-grants] [--validate]")
			return
		case:
			fmt.eprintfln("error: unknown argument '%s'", arg)
			os.exit(2)
		}
		i += 1
	}

	peer, perr := ec.peer_create(ec.Create_Options{seed = seed, open_grants = open_grants, conformance = validate})
	if perr != .None {
		fmt.eprintfln("error: peer_create failed: %v", perr)
		os.exit(1)
	}
	free_all(context.temp_allocator)

	sock, bound_port, ok := ec.transport_listen(port)
	if !ok {
		fmt.eprintln("error: listen failed")
		os.exit(1)
	}

	// single readiness line on stdout (harness greps ^LISTENING)
	fmt.printfln(
		"LISTENING 127.0.0.1:%d peer_id=%s open_grants=%v validate=%v",
		bound_port,
		peer.local_peer,
		open_grants,
		validate,
	)
	os.flush(os.stdout)

	// accept loop — each connection served on its own thread (§4.8)
	for {
		client, _, aerr := net.accept_tcp(sock)
		if aerr != nil {
			break
		}
		t := thread.create_and_start_with_poly_data2(&peer, client, proc(peer: ^ec.Peer, s: net.TCP_Socket) {
			serve_connection(peer, s)
		}, context, .Normal, true)
		_ = t
	}
}

random_seed :: proc() -> [32]u8 {
	s: [32]u8
	crypto.rand_bytes(s[:])
	return s
}

// load_seed_from_name loads the 32-byte Ed25519 seed from the standard on-disk
// keypair (Go entity-peer --name convention): ~/.entity/peers/NAME/keypair, a PEM
// whose body is base64(seed) between BEGIN/END ENTITY PRIVATE KEY lines.
load_seed_from_name :: proc(name: string) -> [32]u8 {
	home := os.get_env("HOME", context.allocator)
	if home == "" {
		home = "/root"
	}
	path := strings.concatenate({home, "/.entity/peers/", name, "/keypair"})
	defer delete(path)
	data, rerr := os.read_entire_file_from_path(path, context.allocator)
	if rerr != nil {
		fmt.eprintfln("error: --name %s: cannot read %s", name, path)
		os.exit(2)
	}
	defer delete(data)

	// concatenate the base64 body: every line that does not start with '-'.
	body := strings.builder_make()
	defer strings.builder_destroy(&body)
	lines := strings.split_lines(string(data))
	defer delete(lines)
	for raw in lines {
		line := strings.trim(raw, " \t\r")
		if len(line) == 0 || line[0] == '-' {
			continue
		}
		strings.write_string(&body, line)
	}
	b64 := strings.to_string(body)
	decoded, derr := base64.decode(b64)
	if derr != nil {
		fmt.eprintfln("error: --name %s: malformed base64 keypair", name)
		os.exit(2)
	}
	defer delete(decoded)
	if len(decoded) != 32 {
		fmt.eprintfln("error: --name %s: expected a 32-byte seed, got %d bytes", name, len(decoded))
		os.exit(2)
	}
	seed: [32]u8
	copy(seed[:], decoded)
	return seed
}
