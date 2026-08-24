package smoke

// S3 smoke runner — the phase exit gate. Two Odin peers talk over real loopback
// TCP through the full dispatch chain: the §4.1 handshake (initiator hello →
// authenticate), 404 on an unregistered path, an authority-gated tree get (200),
// a capability request (200), and 8-way `request_id` demux of concurrently-issued
// replies (N7). Then a clean teardown.
//
// Leak-checked: the whole run uses a mem.Tracking_Allocator; any un-freed entity
// / envelope / store binding is reported (the free-correctness conformance bonus
// unique to the no-GC peer).

import ec "../src"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:os"
import "core:strings"
import "core:thread"

pass_count := 0
fail_count := 0

check :: proc(name: string, ok: bool) {
	if ok {
		pass_count += 1
	} else {
		fail_count += 1
	}
	fmt.printfln("  [%s] %s", "PASS" if ok else "FAIL", name)
}

Serve_Args :: struct {
	peer: ^ec.Peer,
	sock: net.TCP_Socket,
}

serve_one :: proc(sa: ^Serve_Args) {
	client, _, aerr := net.accept_tcp(sa.sock)
	if aerr != nil {
		return
	}
	io := ec.io_init(client)
	conn := ec.Conn{}
	ec.read_loop(sa.peer, &conn, &io) // blocks until close
	ec.io_destroy(&io)
	ec.conn_destroy(&conn)
	net.close(client)
}

type_target :: proc(allocator: mem.Allocator) -> ec.Ec_Value {
	targets := make([]ec.Ec_Value, 1, allocator)
	targets[0] = ec.text_val("system/type/system/peer", allocator)
	pairs := make([]ec.Ec_Pair, 1, allocator)
	pairs[0] = ec.Ec_Pair{ec.text_val("targets", allocator), ec.Ec_Array(targets)}
	return ec.Ec_Map(pairs)
}

request_params :: proc(allocator: mem.Allocator) -> ec.Entity {
	scope :: proc(incl: string, allocator: mem.Allocator) -> ec.Ec_Value {
		items := make([]ec.Ec_Value, 1, allocator)
		items[0] = ec.text_val(incl, allocator)
		p := make([]ec.Ec_Pair, 1, allocator)
		p[0] = ec.Ec_Pair{ec.text_val("include", allocator), ec.Ec_Array(items)}
		return ec.Ec_Map(p)
	}
	gpairs := make([]ec.Ec_Pair, 3, allocator)
	gpairs[0] = ec.Ec_Pair{ec.text_val("handlers", allocator), scope("system/tree", allocator)}
	gpairs[1] = ec.Ec_Pair{ec.text_val("resources", allocator), scope("system/type/*", allocator)}
	gpairs[2] = ec.Ec_Pair{ec.text_val("operations", allocator), scope("get", allocator)}
	grants := make([]ec.Ec_Value, 1, allocator)
	grants[0] = ec.Ec_Map(gpairs)
	ppairs := make([]ec.Ec_Pair, 1, allocator)
	ppairs[0] = ec.Ec_Pair{ec.text_val("grants", allocator), ec.Ec_Array(grants)}
	e, _ := ec.entity_make("system/capability/request", ec.Ec_Map(ppairs), allocator)
	return e
}

Worker_Arg :: struct {
	session: ^ec.Session,
	remote:  string,
	ok:      ^bool,
	gpa:     mem.Allocator,
}

worker_run :: proc(w: ^Worker_Arg) {
	context.allocator = w.gpa
	uri := strings.concatenate({"/", w.remote, "/system/tree"}, w.gpa)
	defer delete(uri, w.gpa)
	tt := type_target(w.gpa)
	params, _ := ec.empty_params(w.gpa)
	resp, got := ec.session_execute(w.session, uri, "get", params, tt, true, w.gpa)
	if !got {
		return
	}
	defer ec.envelope_destroy(resp, w.gpa)
	if st, _ := ec.entity_uint(resp.root, "status"); st != 200 {
		return
	}
	result, has_result, _ := ec.entity_field_entity(resp.root, "result", w.gpa)
	if !has_result {
		return
	}
	defer ec.entity_destroy(result, w.gpa)
	w.ok^ = result.typ == "system/type"
}

run_smoke :: proc(gpa: mem.Allocator) {
	context.allocator = gpa

	seed1: [32]u8 = 1
	seed2: [32]u8 = 2
	responder, _ := ec.peer_create(ec.Create_Options{seed = seed1})
	defer ec.peer_destroy(&responder)
	initiator, _ := ec.peer_create(ec.Create_Options{seed = seed2})
	defer ec.peer_destroy(&initiator)
	free_all(context.temp_allocator)

	sock, bound_port, ok := ec.transport_listen(0)
	if !ok {
		fmt.println("listen failed")
		fail_count += 1
		return
	}

	sa := Serve_Args{peer = &responder, sock = sock}
	serve_thread := thread.create_and_start_with_poly_data(&sa, proc(sa: ^Serve_Args) {
		serve_one(sa)
	})

	// dial + handshake
	client, dok := ec.transport_dial(bound_port)
	if !dok {
		fmt.println("dial failed")
		fail_count += 1
		return
	}
	io := ec.io_init(client)
	conn := ec.Conn{}
	reader_thread := thread.create_and_start_with_poly_data3(&initiator, &conn, &io, proc(p: ^ec.Peer, c: ^ec.Conn, io: ^ec.Io) {
		ec.read_loop(p, c, io)
	})

	fmt.println("Handshake:")
	session, sok := ec.initiate(&initiator, &io, &conn, gpa)
	if !sok {
		fmt.println("handshake failed")
		fail_count += 1
		return
	}
	defer ec.session_destroy(&session)
	check("session established (initial capability granted)", len(session.capability.hash) == 33)
	check("remote peer_id matches responder", session.remote_peer_id == responder.local_peer)

	remote := responder.local_peer

	// dispatch
	fmt.println("Dispatch:")
	{
		uri := strings.concatenate({"/", remote, "/does/not/exist"}, gpa)
		defer delete(uri, gpa)
		params, _ := ec.empty_params(gpa)
		resp, got := ec.session_execute(&session, uri, "noop", params, nil, false, gpa)
		if got {
			defer ec.envelope_destroy(resp, gpa)
			st, _ := ec.entity_uint(resp.root, "status")
			check("unregistered path -> 404", st == 404)
		} else {
			check("unregistered path -> 404", false)
		}
	}
	{
		uri := strings.concatenate({"/", remote, "/system/tree"}, gpa)
		defer delete(uri, gpa)
		params, _ := ec.empty_params(gpa)
		resp, got := ec.session_execute(&session, uri, "get", params, type_target(gpa), true, gpa)
		if got {
			defer ec.envelope_destroy(resp, gpa)
			st, _ := ec.entity_uint(resp.root, "status")
			check("granted tree get -> 200", st == 200)
			result, hr, _ := ec.entity_field_entity(resp.root, "result", gpa)
			if hr {
				defer ec.entity_destroy(result, gpa)
				check("tree get returns a system/type entity", result.typ == "system/type")
			} else {
				check("tree get returns a system/type entity", false)
			}
		} else {
			check("granted tree get -> 200", false)
		}
	}
	{
		uri := strings.concatenate({"/", remote, "/system/capability"}, gpa)
		defer delete(uri, gpa)
		resp, got := ec.session_execute(&session, uri, "request", request_params(gpa), nil, false, gpa)
		if got {
			defer ec.envelope_destroy(resp, gpa)
			st, _ := ec.entity_uint(resp.root, "status")
			check("capability request -> 200", st == 200)
		} else {
			check("capability request -> 200", false)
		}
	}

	// concurrency: request_id demux (N7)
	fmt.println("Concurrency (request_id demux):")
	{
		N :: 8
		oks: [N]bool
		args: [N]Worker_Arg
		threads: [N]^thread.Thread
		for i in 0 ..< N {
			args[i] = Worker_Arg{session = &session, remote = remote, ok = &oks[i], gpa = gpa}
			threads[i] = thread.create_and_start_with_poly_data(&args[i], proc(w: ^Worker_Arg) {
				worker_run(w)
			})
		}
		for i in 0 ..< N {
			thread.join(threads[i])
			thread.destroy(threads[i])
		}
		correlated := 0
		for o in oks {
			if o {
				correlated += 1
			}
		}
		check(fmt.tprintf("8 interleaved requests each correlated -> %d/8", correlated), correlated == N)
	}

	// teardown
	ec.io_close(&io)
	net.shutdown(client, net.Shutdown_Manner.Both)
	thread.join(reader_thread)
	thread.destroy(reader_thread)
	// wake the responder's reader by shutting the server-side accepted socket:
	// closing the client already EOFs it. join the serve thread.
	thread.join(serve_thread)
	thread.destroy(serve_thread)
	net.close(client)
	ec.io_destroy(&io)
	net.close(sock)
}

main :: proc() {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	tracked := mem.tracking_allocator(&track)

	run_smoke(tracked)

	leaked := false
	if len(track.allocation_map) > 0 {
		fmt.printfln("\n%d leaked allocation(s):", len(track.allocation_map))
		for _, entry in track.allocation_map {
			fmt.printfln("  %v bytes @ %v", entry.size, entry.location)
			leaked = true
		}
	}

	all_pass := fail_count == 0 && !leaked
	fmt.printfln(
		"\nTeardown %s.   ->   SMOKE: %s (%d pass, %d fail%s)",
		"clean" if !leaked else "LEAKED",
		"PASS" if all_pass else "FAIL",
		pass_count,
		fail_count,
		"" if !leaked else ", LEAK",
	)
	if !all_pass {
		os.exit(1)
	}
}
