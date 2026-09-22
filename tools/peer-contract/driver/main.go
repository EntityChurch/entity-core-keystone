// kpc-driver — the keystone peer contract suite's wire driver. One program for every language.
//
// It launches a language's CONTRACT HOST (and its bare host), drives the fixtures specified in
// protocol-generator/shared/peer-contract/FIXTURE-HOST.md over real TCP from three client
// identities, and writes one JSON record per case. It never computes a certification verdict;
// tools/peer-contract/report.py does that from these cases, the requirement registry, the peer's
// local tests and its core conformance report.
//
// Every case states what it observed and what it expected. A case that could not run (the host
// did not start, a session did not authenticate) is recorded as failed with the reason — never
// omitted, because a missing row would read as "not measured" rather than "measured and broken".
//
// Usage:
//
//	kpc-driver -host "<contract host command>" -bare-host "<bare host command>" \
//	           -peer-package <name> -workdir <dir> -out cases.json
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	driverVersion   = "kpc-driver/1"
	contractVersion = "2.0-draft.1"
	hostSeed        = byte(0x41)
	wideSeed        = byte(0x31)
	narrowSeed      = byte(0x32)
	strangerSeed    = byte(0x33)
	frameBudget     = 262144 // 256 KiB — deliberately not a default any peer ships
)

type caseResult struct {
	ID       string `json:"id"`
	Pass     bool   `json:"pass"`
	Observed string `json:"observed"`
	Expected string `json:"expected"`
}

type output struct {
	Driver          string       `json:"driver"`
	ContractVersion string       `json:"contract_version"`
	StartedAt       string       `json:"started_at"`
	HostCmd         string       `json:"host_cmd"`
	BareHostCmd     string       `json:"bare_host_cmd"`
	ReadyRecord     interface{}  `json:"ready_record"`
	Cases           []caseResult `json:"cases"`
	HostStderrTail  string       `json:"host_stderr_tail"`
	SetupError      string       `json:"setup_error,omitempty"`
}

var out output

func record(id string, pass bool, observed, expected string) {
	out.Cases = append(out.Cases, caseResult{ID: id, Pass: pass, Observed: observed, Expected: expected})
	mark := "PASS"
	if !pass {
		mark = "FAIL"
	}
	fmt.Printf("  %s  %-58s %s\n", mark, id, observed)
}

// ---------- identities ----------

type ident struct {
	peerID       string
	identityHash []byte
}

func identityOf(seed byte) ident {
	priv := keyOf(seed)
	pub := priv[32:]
	data := cmap(pair{txt("public_key"), bstr(pub)}, pair{txt("key_type"), txt("ed25519")})
	return ident{peerID: peerIDOf(pub), identityHash: contentHash("system/peer", data)}
}

// ---------- processes ----------

type proc struct {
	cmd    *exec.Cmd
	record map[string]interface{}
	line   string
	stderr *bytes.Buffer
	exited chan error
}

func launch(command string, args []string, env []string, wait time.Duration) (*proc, error) {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	cmd := exec.Command(parts[0], append(parts[1:], args...)...)
	cmd.Env = append(os.Environ(), env...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	p := &proc{cmd: cmd, stderr: &bytes.Buffer{}, exited: make(chan error, 1)}
	cmd.Stderr = p.stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	lines := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		sent := false
		for sc.Scan() {
			if !sent && strings.HasPrefix(sc.Text(), "LISTENING") {
				lines <- sc.Text()
				sent = true
			}
		}
	}()
	go func() { p.exited <- cmd.Wait() }()
	select {
	case l := <-lines:
		p.line = l
		body := strings.TrimSpace(strings.TrimPrefix(l, "LISTENING"))
		var rec map[string]interface{}
		if err := json.Unmarshal([]byte(body), &rec); err == nil {
			p.record = rec
		}
		return p, nil
	case err := <-p.exited:
		p.exited <- err
		return p, fmt.Errorf("exited before LISTENING (%v)", err)
	case <-time.After(wait):
		return p, fmt.Errorf("no LISTENING line within %s", wait)
	}
}

func (p *proc) stop() {
	if p == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.exited:
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
	}
}

func dialAddr(rec map[string]interface{}) string {
	addr, _ := rec["addr"].(string)
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return net.JoinHostPort("127.0.0.1", port)
}

// ---------- request helpers ----------

type client struct {
	s   *session
	err error
}

func (c *client) exec(uri, op string, params []byte, targets []string) (map[string]interface{}, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.s.authedExecute("c", uri, op, params, targets)
}

func anyParams(ps ...pair) []byte { return entity("primitive/any", cmap(ps...)) }

func putOf(typ string, data []byte) []byte {
	return entity("system/tree/put-request", cmap(pair{txt("entity"), entity(typ, data)}))
}

func st(env map[string]interface{}, err error) (int, string) {
	if err != nil {
		return 0, "error: " + err.Error()
	}
	s, c, _ := statusOf(env)
	return s, c
}

func resText(env map[string]interface{}, k string) string {
	v, _ := resultField(env, k).(string)
	return v
}

func resUint(env map[string]interface{}, k string) uint64 {
	v, _ := resultField(env, k).(uint64)
	return v
}

func resBool(env map[string]interface{}, k string) (bool, bool) {
	v, ok := resultField(env, k).(bool)
	return v, ok
}

func resultType(env map[string]interface{}) string {
	_, _, t := statusOf(env)
	return t
}

func obs(env map[string]interface{}, err error) string {
	s, c := st(env, err)
	return fmt.Sprintf("%d %s", s, c)
}

func main() {
	hostCmd := flag.String("host", "", "contract host command")
	bareCmd := flag.String("bare-host", "", "bare host command")
	peerPackage := flag.String("peer-package", "", "the peer's package name")
	workdir := flag.String("workdir", "", "scratch directory (HOME for the hosts)")
	outPath := flag.String("out", "kpc-cases.json", "where to write the case records")
	flag.Parse()

	out = output{Driver: driverVersion, ContractVersion: contractVersion,
		StartedAt: time.Now().UTC().Format(time.RFC3339), HostCmd: *hostCmd, BareHostCmd: *bareCmd}
	defer func() {
		b, _ := json.MarshalIndent(out, "", "  ")
		_ = os.WriteFile(*outPath, append(b, '\n'), 0o644)
		fmt.Printf("kpc-driver: %d cases written to %s\n", len(out.Cases), *outPath)
	}()
	if *hostCmd == "" || *bareCmd == "" || *workdir == "" || *peerPackage == "" {
		out.SetupError = "-host, -bare-host, -peer-package and -workdir are required"
		fmt.Fprintln(os.Stderr, out.SetupError)
		return
	}

	// ---- setup: identity file, seed policy, nonce ----
	home := filepath.Join(*workdir, "home")
	kpdir := filepath.Join(home, ".entity", "peers", "kpc")
	_ = os.MkdirAll(kpdir, 0o700)
	seed := bytes.Repeat([]byte{hostSeed}, 32)
	pem := "-----BEGIN ENTITY PRIVATE KEY-----\n" + b64(seed) + "\n-----END ENTITY PRIVATE KEY-----\n"
	_ = os.WriteFile(filepath.Join(kpdir, "keypair"), []byte(pem), 0o600)
	host := identityOf(hostSeed)
	wide, narrow := identityOf(wideSeed), identityOf(narrowSeed)
	L := host.peerID

	policy := fmt.Sprintf(`{
  "version": 1,
  "entries": [
    {"grantee": %q, "grants": [
      {"handlers": {"include": ["*"]}, "resources": {"include": ["*", "/*/*"]}, "operations": {"include": ["*"]}}
    ]},
    {"grantee": %q, "grants": [
      {"handlers": {"include": ["app/contract/witness", "app/contract/dispatch", "app/contract/authz"]},
       "resources": {"include": ["/%s/app/contract/*"]},
       "operations": {"include": ["echo", "put_as_caller", "check"]}}
    ]},
    {"grantee": "default", "grants": [
      {"handlers": {"include": ["system/tree"]}, "resources": {"include": ["system/type/*", "system/handler/*"]}, "operations": {"include": ["get"]}},
      {"handlers": {"include": ["system/capability"]}, "resources": {"include": []}, "operations": {"include": ["request"]}}
    ]}
  ]
}
`, hex.EncodeToString(wide.identityHash), hex.EncodeToString(narrow.identityHash), L)
	policyPath := filepath.Join(*workdir, "policy.json")
	_ = os.WriteFile(policyPath, []byte(policy), 0o644)
	policySum := sha256.Sum256([]byte(policy))
	readyPath := filepath.Join(*workdir, "ready.json")
	nb := make([]byte, 6)
	_, _ = rand.Read(nb)
	nonce := "n" + hex.EncodeToString(nb)
	env := []string{"HOME=" + home, "KPC_NONCE=" + nonce}
	args := []string{"--port", "0", "--bind", "0.0.0.0", "--name", "kpc", "--seed-policy", policyPath,
		"--max-frame-bytes", fmt.Sprint(frameBudget), "--ready-file", readyPath}

	// ---- run.cli: an unknown flag is refused before anything listens ----
	if p, err := launch(*hostCmd, []string{"--kpc-not-a-flag"}, env, 10*time.Second); err == nil {
		record("run.cli/unknown-flag-refused", false, "started and printed LISTENING", "non-zero exit, no readiness record")
		p.stop()
	} else {
		code := "unknown"
		if p != nil && p.cmd.ProcessState != nil {
			code = fmt.Sprint(p.cmd.ProcessState.ExitCode())
		}
		record("run.cli/unknown-flag-refused", code != "0" && code != "unknown",
			fmt.Sprintf("no readiness record; exit %s", code), "non-zero exit, no readiness record")
		if p != nil {
			p.stop()
		}
	}

	// ---- the contract host ----
	hp, err := launch(*hostCmd, args, env, 60*time.Second)
	if hp != nil {
		defer func() { out.HostStderrTail = tail(hp.stderr.String(), 3000) }()
	}
	if err != nil || hp.record == nil {
		msg := fmt.Sprintf("contract host did not start: %v; line=%q", err, lineOf(hp))
		out.SetupError = msg
		record("run.cli/all-flags-start", false, msg, "LISTENING with a JSON readiness record")
		if hp != nil {
			hp.stop()
		}
		return
	}
	out.ReadyRecord = hp.record
	record("run.cli/all-flags-start", true, "started with --port --bind --name --seed-policy --max-frame-bytes --ready-file", "LISTENING")

	rec := hp.record
	addr := dialAddr(rec)
	{
		missing := []string{}
		for _, k := range []string{"record", "transport", "addr", "peer_id", "posture", "posture_digest", "limits", "validate"} {
			if _, ok := rec[k]; !ok {
				missing = append(missing, k)
			}
		}
		ok := len(missing) == 0 && rec["record"] == "keystone-peer-ready/1" && rec["transport"] == "tcp"
		record("run.ready/line-is-record", ok, fmt.Sprintf("record=%v missing=%v", rec["record"], missing),
			"keystone-peer-ready/1 with every field")
		var fileRec map[string]interface{}
		fb, ferr := os.ReadFile(readyPath)
		if ferr == nil {
			_ = json.Unmarshal(fb, &fileRec)
		}
		record("run.ready/ready-file-matches-line", ferr == nil && reflect.DeepEqual(fileRec, rec),
			fmt.Sprintf("file read err=%v equal=%v", ferr, reflect.DeepEqual(fileRec, rec)), "--ready-file JSON equals the line's JSON")
	}
	record("run.identity/peer-id-from-keypair", rec["peer_id"] == L,
		fmt.Sprintf("peer_id=%v", rec["peer_id"]), "peer id derived from the 0x41 keypair: "+L)
	{
		a, _ := rec["addr"].(string)
		h, _, _ := net.SplitHostPort(a)
		record("run.serve/bind-flag-honored", h == "0.0.0.0" && addr != "",
			"addr="+a, "the listener is bound where --bind said (0.0.0.0)")
	}
	record("run.posture/digest-is-file-sha256",
		rec["posture"] == "file" && rec["posture_digest"] == hex.EncodeToString(policySum[:]),
		fmt.Sprintf("posture=%v digest=%v", rec["posture"], rec["posture_digest"]), "file / sha256 of the policy bytes")
	{
		lim, _ := rec["limits"].(map[string]interface{})
		mfb, _ := lim["max_frame_bytes"].(float64)
		record("run.limits/echoed", uint64(mfb) == frameBudget,
			fmt.Sprintf("max_frame_bytes=%v", lim["max_frame_bytes"]), fmt.Sprint(frameBudget))
	}
	{
		ch, _ := rec["contract_host"].(map[string]interface{})
		pkg, _ := ch["package"].(string)
		dep, _ := ch["depends_on"].(string)
		record("embed.package/contract-host-is-a-separate-package",
			ch != nil && pkg != "" && pkg != dep && dep == *peerPackage,
			fmt.Sprintf("package=%q depends_on=%q", pkg, dep), "its own package, depending on "+*peerPackage)
	}

	dial := func(seed byte) *client {
		s, err := dialSession(addr, seed, 15*time.Second)
		return &client{s: s, err: err}
	}
	W, N, S := dial(wideSeed), dial(narrowSeed), dial(strangerSeed)
	for name, c := range map[string]*client{"wide": W, "narrow": N, "stranger": S} {
		if c.err != nil {
			fmt.Printf("  NOTE session %s did not authenticate: %v\n", name, c.err)
		}
	}
	if W.err == nil {
		// handshake-peer-id-matches: the hello answered for the identity the record names.
		hello := W.s.remotePeerID
		record("run.identity/handshake-peer-id-matches", hello == L, "hello peer_id="+hello, L)
	} else {
		record("run.identity/handshake-peer-id-matches", false, "wide session: "+W.err.Error(), L)
	}

	// ---- run.posture ----
	{
		e, err := N.exec("app/contract/witness", "echo", anyParams(pair{txt("echo"), txt("narrow")}), nil)
		s, _ := st(e, err)
		record("run.posture/narrow-identity-reaches-its-handler", s == 200, obs(e, err), "200")
		e, err = N.exec("app/contract/context", "echo", anyParams(), nil)
		s, _ = st(e, err)
		record("run.posture/narrow-identity-refused-elsewhere", s == 403, obs(e, err), "403")
		e, err = S.exec("app/contract/witness", "echo", anyParams(pair{txt("echo"), txt("x")}), nil)
		s, _ = st(e, err)
		record("run.posture/stranger-refused", s == 403, obs(e, err), "403")
	}

	// ---- install.handler ----
	witnessOK := false
	{
		echo := "e-" + nonce
		e, err := W.exec("app/contract/witness", "echo", anyParams(pair{txt("echo"), txt(echo)}), nil)
		want := nonce + ":app/contract/witness:" + echo
		got := resText(e, "witness")
		witnessOK = got == want
		record("install.handler/witness", witnessOK, obs(e, err)+" witness="+got, want)

		e, err = W.exec("app/contract/never", "echo", anyParams(), nil)
		s, c := st(e, err)
		record("install.handler/uninstalled-404", s == 404 && c == "handler_not_found", obs(e, err), "404 handler_not_found")

		e, err = W.exec("system/tree", "get", emptyParams(), []string{"system/handler/app/contract/witness"})
		s, _ = st(e, err)
		outType := ""
		if ops, ok := resultField(e, "operations").(map[string]interface{}); ok {
			if spec, ok := ops["echo"].(map[string]interface{}); ok {
				outType, _ = spec["output_type"].(string)
			}
		}
		record("install.handler/interface-bound",
			s == 200 && resultType(e) == "system/handler/interface" && outType == "contract/witness-result",
			fmt.Sprintf("%s type=%s echo.output_type=%s", obs(e, err), resultType(e), outType),
			"200 system/handler/interface with echo.output_type")

		e, err = W.exec("app/contract/probe", "install_report", anyParams(), nil)
		rs := func(k string) string { return fmt.Sprintf("%d %s", resUint(e, k+"_status"), resText(e, k+"_code")) }
		record("install.handler/collision-409", rs("collision") == "409 pattern_collision", obs(e, err)+" → "+rs("collision"), "409 pattern_collision")
		record("install.handler/builtin-collision-409", rs("builtin_collision") == "409 pattern_collision", rs("builtin_collision"), "409 pattern_collision")
		record("install.handler/invalid-spec-400", rs("invalid") == "400 invalid_handler_spec", rs("invalid"), "400 invalid_handler_spec")
	}
	record("embed.host_main/composed-host-serves-fixtures", witnessOK && rec["contract_host"] != nil,
		fmt.Sprintf("witness=%v contract_host=%v", witnessOK, rec["contract_host"] != nil),
		"the host run_host(argv, install_fixtures) serves the witness")

	// ---- install.types ----
	{
		e, err := W.exec("system/tree", "get", emptyParams(), []string{"system/type/contract/witness-result"})
		s, _ := st(e, err)
		record("install.types/bound", s == 200 && resultType(e) == "system/type" && resText(e, "name") == "contract/witness-result",
			fmt.Sprintf("%s type=%s name=%s", obs(e, err), resultType(e), resText(e, "name")), "200 system/type name=contract/witness-result")
	}

	// ---- install.remove ----
	{
		pre, perr := W.exec("app/contract/removable", "echo", anyParams(), nil)
		ps, _ := st(pre, perr)
		e, err := W.exec("app/contract/probe", "close_removable", anyParams(), nil)
		first, ok1 := resBool(e, "first")
		second, ok2 := resBool(e, "second")
		record("install.remove/close-idempotent", ps == 200 && ok1 && ok2 && first && !second,
			fmt.Sprintf("before=%d first=%v second=%v (%s)", ps, first, second, obs(e, err)), "reachable before; first close true, second false")
		e, err = W.exec("app/contract/removable", "echo", anyParams(), nil)
		s, _ := st(e, err)
		record("install.remove/closed-404", s == 404, obs(e, err), "404")
		gone := []string{}
		for _, t := range []string{"app/contract/removable", "system/handler/app/contract/removable", "system/capability/grants/app/contract/removable"} {
			e, err := W.exec("system/tree", "get", emptyParams(), []string{t})
			if s, _ := st(e, err); s != 404 {
				gone = append(gone, fmt.Sprintf("%s=%s", t, obs(e, err)))
			}
		}
		record("install.remove/artifacts-gone", len(gone) == 0, fmt.Sprintf("still bound: %v", gone), "handler, interface and grant all 404")
		e, err = W.exec("system/tree", "get", emptyParams(), []string{"system/type/contract/removable-type"})
		s, _ = st(e, err)
		record("install.types/survive-close", s == 200, obs(e, err), "200 — types are not removed on close")
	}

	// ---- install.grant ----
	{
		inner := func(e map[string]interface{}) string {
			return fmt.Sprintf("%d %s", resUint(e, "status"), resText(e, "code"))
		}
		e, err := W.exec("app/contract/granted", "put_inside", anyParams(), nil)
		record("install.grant/inside-scope-allowed", resUint(e, "status") == 200, obs(e, err)+" inner="+inner(e), "inner 200")
		e, err = W.exec("app/contract/granted", "put_outside", anyParams(), nil)
		record("install.grant/outside-scope-refused", resUint(e, "status") == 403, obs(e, err)+" inner="+inner(e), "inner 403")
		e, err = W.exec("app/contract/ungranted", "put_inside", anyParams(), nil)
		record("install.grant/null-scope-refused", resUint(e, "status") == 403, obs(e, err)+" inner="+inner(e), "inner 403")
	}

	// ---- install.consumer + event.context ----
	events := func() []string {
		e, _ := W.exec("app/contract/probe", "events", anyParams(), nil)
		lst, _ := resultField(e, "log").([]interface{})
		o := []string{}
		for _, v := range lst {
			if s, ok := v.(string); ok {
				o = append(o, s)
			}
		}
		return o
	}
	index := func(log []string, prefix string) int {
		for i, l := range log {
			if strings.HasPrefix(l, prefix) {
				return i
			}
		}
		return -1
	}
	wideHex := hex.EncodeToString(wide.identityHash)
	{
		m1 := cmap(pair{txt("n"), uint64v(1)})
		h1 := hex.EncodeToString(contentHash("contract/event-marker", m1))
		e, err := W.exec("system/tree", "put", putOf("contract/event-marker", m1), []string{"app/contract/events/1"})
		p1 := "/" + L + "/app/contract/events/1|"
		log := events()
		ia, ib, ic := index(log, "A|tree|"+p1), index(log, "B|tree|"+p1), index(log, "C|content|"+h1)
		record("install.consumer/registration-order", ia >= 0 && ib > ia,
			fmt.Sprintf("put=%s A@%d B@%d log=%v", obs(e, err), ia, ib, log), "A before B")
		record("install.consumer/content-before-tree", ic >= 0 && ia > ic, fmt.Sprintf("C@%d A@%d", ic, ia), "content event before tree events")
		authorOK := ia >= 0 && strings.HasSuffix(log[ia], "|"+wideHex)
		record("event.context/author-is-remote-caller", authorOK && wideHex != hex.EncodeToString(host.identityHash),
			fmt.Sprintf("A entry=%q", at(log, ia)), "author = the wide caller's identity hash "+wideHex)

		e, err = W.exec("app/contract/probe", "unregister_b", anyParams(), nil)
		removed, _ := resBool(e, "removed")
		m2 := cmap(pair{txt("n"), uint64v(2)})
		_, _ = W.exec("system/tree", "put", putOf("contract/event-marker", m2), []string{"app/contract/events/2"})
		p2 := "/" + L + "/app/contract/events/2|"
		log = events()
		record("install.consumer/unregister-stops-delivery",
			removed && index(log, "A|tree|"+p2) >= 0 && index(log, "B|tree|"+p2) < 0,
			fmt.Sprintf("removed=%v A@%d B@%d", removed, index(log, "A|tree|"+p2), index(log, "B|tree|"+p2)),
			"after unregister_b: A delivered, B not")
	}

	// ---- context.dispatch ----
	{
		e, err := W.exec("app/contract/dispatch", "put_as_caller", anyParams(pair{txt("n"), uint64v(3)}), nil)
		record("context.dispatch/caller-authority-allowed", resUint(e, "status") == 200,
			fmt.Sprintf("%s inner=%d %s", obs(e, err), resUint(e, "status"), resText(e, "code")), "inner 200")
		log := events()
		i := index(log, "A|tree|/"+L+"/app/contract/events/sub|")
		record("event.context/sub-dispatch-write-attributed-to-caller", i >= 0 && strings.HasSuffix(log[i], "|"+wideHex),
			fmt.Sprintf("entry=%q", at(log, i)), "the sub-dispatch's write names the originating caller")
		e, err = N.exec("app/contract/dispatch", "put_as_caller", anyParams(pair{txt("n"), uint64v(4)}), nil)
		s, _ := st(e, err)
		record("context.dispatch/no-escalation-refused", s == 200 && resUint(e, "status") == 403,
			fmt.Sprintf("outer %s inner=%d %s", obs(e, err), resUint(e, "status"), resText(e, "code")),
			"outer 200 (narrow may reach the handler), inner 403 (narrow holds no tree:put)")
	}

	// ---- context.contents / frame_budget ----
	{
		marker := "m-" + nonce
		e, err := W.exec("app/contract/context/sub/x", "echo", anyParams(pair{txt("marker"), txt(marker)}), nil)
		want := map[string]string{"operation": "echo", "pattern": "app/contract/context", "suffix": "sub/x",
			"author": wideHex, "caller_capability": hex.EncodeToString(capHashOf(W)), "marker": marker}
		bad := []string{}
		keys := make([]string, 0, len(want))
		for k := range want {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if got := resText(e, k); got != want[k] {
				bad = append(bad, fmt.Sprintf("%s=%q want %q", k, got, want[k]))
			}
		}
		if resText(e, "handler_grant") == "" {
			bad = append(bad, "handler_grant empty")
		}
		record("context.contents/fields", len(bad) == 0, obs(e, err)+fmt.Sprintf(" mismatches=%v", bad),
			"operation, pattern, suffix, author, caller capability, handler grant, params")
		e, err = W.exec("app/contract/context", "budget", anyParams(), nil)
		record("context.frame_budget/by-value", resUint(e, "frame_budget") == frameBudget,
			fmt.Sprintf("%s frame_budget=%d", obs(e, err), resUint(e, "frame_budget")), fmt.Sprint(frameBudget))
	}

	// ---- embed.data (the in-process data surface is the peer's own store) ----
	{
		item := func(m string) []byte { return cmap(pair{txt("marker"), txt(m)}) }
		itemHash := func(m string) string { return hex.EncodeToString(contentHash("contract/data-item", item(m))) }
		data := func(op string, ps ...pair) (map[string]interface{}, error) {
			return W.exec("app/contract/data", op, anyParams(ps...), nil)
		}
		wireGet := func(path string) (map[string]interface{}, error) {
			return W.exec("system/tree", "get", emptyParams(), []string{path})
		}

		m1 := "put-" + nonce
		e, err := data("put", pair{txt("marker"), txt(m1)})
		acc, _ := resBool(e, "accepted")
		record("embed.data/put-hash-is-content-hash", resText(e, "hash") == itemHash(m1) && acc,
			fmt.Sprintf("%s hash=%s accepted=%v", obs(e, err), resText(e, "hash"), acc), "hash="+itemHash(m1)+" accepted")

		e, err = data("get", pair{txt("hash"), txt(itemHash(m1))})
		found, _ := resBool(e, "found")
		record("embed.data/get-by-hash", found && resText(e, "type") == "contract/data-item" && resText(e, "marker") == m1,
			fmt.Sprintf("%s found=%v type=%s marker=%s", obs(e, err), found, resText(e, "type"), resText(e, "marker")),
			"found contract/data-item marker="+m1)

		e, err = data("get", pair{txt("hash"), txt(itemHash("never-" + nonce))})
		found, fok := resBool(e, "found")
		s, _ := st(e, err)
		record("embed.data/get-absent-not-found", s == 200 && fok && !found,
			fmt.Sprintf("%s found=%v", obs(e, err), found), "200 found=false for a hash nothing stored")

		m2, inProc := "bind-"+nonce, "app/contract/data/in-process"
		e, err = data("bind", pair{txt("path"), txt(inProc)}, pair{txt("marker"), txt(m2)})
		acc, _ = resBool(e, "accepted")
		g, gerr := wireGet(inProc)
		gs, _ := st(g, gerr)
		record("embed.data/bind-visible-on-wire",
			acc && gs == 200 && resultType(g) == "contract/data-item" && resText(g, "marker") == m2,
			fmt.Sprintf("bind %s accepted=%v; wire get %s type=%s marker=%s", obs(e, err), acc, obs(g, gerr), resultType(g), resText(g, "marker")),
			"the wire answers the in-process binding")

		m3, onWire := "wire-"+nonce, "app/contract/data/wire"
		_, perr := W.exec("system/tree", "put", putOf("contract/data-item", item(m3)), []string{onWire})
		e, err = data("get_at", pair{txt("path"), txt(onWire)})
		found, _ = resBool(e, "found")
		record("embed.data/wire-write-visible-in-process",
			perr == nil && found && resText(e, "hash") == itemHash(m3) && resText(e, "marker") == m3,
			fmt.Sprintf("put err=%v; get_at %s found=%v hash=%s marker=%s", perr, obs(e, err), found, resText(e, "hash"), resText(e, "marker")),
			"get_at reads the wire put")

		evPath := "app/contract/events/data"
		evEntry := "A|tree|/" + L + "/" + evPath + "|"
		count := func(log []string) (int, string) {
			n, last := 0, ""
			for _, l := range log {
				if strings.HasPrefix(l, evEntry) {
					n, last = n+1, l
				}
			}
			return n, last
		}
		_, _ = data("bind", pair{txt("path"), txt(evPath)}, pair{txt("marker"), txt("ev-" + nonce)})
		n, last := count(events())
		record("embed.data/bind-carries-context", n == 1 && strings.HasSuffix(last, "|"+wideHex),
			fmt.Sprintf("entries=%d last=%q", n, last), "one tree event naming the caller "+wideHex)

		e, err = data("unbind", pair{txt("path"), txt(inProc)})
		g, gerr = wireGet(inProc)
		gs, _ = st(g, gerr)
		a, aerr := data("get_at", pair{txt("path"), txt(inProc)})
		found, fok = resBool(a, "found")
		record("embed.data/unbind-removes", gs == 404 && fok && !found,
			fmt.Sprintf("unbind %s; wire get %s; get_at %s found=%v", obs(e, err), obs(g, gerr), obs(a, aerr), found),
			"wire 404 and get_at found=false")

		_, _ = data("unbind", pair{txt("path"), txt(evPath)})
		n, last = count(events())
		record("embed.data/unbind-carries-context", n == 2 && strings.HasSuffix(last, "|"+wideHex),
			fmt.Sprintf("entries=%d last=%q", n, last), "a second tree event, naming the caller")

		victim, forged := "victim-"+nonce, "app/contract/data/forged"
		e, err = data("forge", pair{txt("marker"), txt("forger-" + nonce)}, pair{txt("victim_marker"), txt(victim)}, pair{txt("path"), txt(forged)})
		constructible, _ := resBool(e, "constructible")
		pa, _ := resBool(e, "put_accepted")
		ba, _ := resBool(e, "bind_accepted")
		v, verr := data("get", pair{txt("hash"), txt(itemHash(victim))})
		vfound, vok := resBool(v, "found")
		g, gerr = wireGet(forged)
		gs, _ = st(g, gerr)
		s, _ = st(e, err)
		record("embed.data/forged-hash-not-filed", s == 200 && !pa && !ba && vok && !vfound && gs == 404,
			fmt.Sprintf("forge %s constructible=%v put_accepted=%v bind_accepted=%v; get(victim) %s found=%v; wire get %s",
				obs(e, err), constructible, pa, ba, obs(v, verr), vfound, obs(g, gerr)),
			"both refused, nothing readable under the victim hash, the path 404")
	}

	// ---- authority.path_permission (narrow's own token) ----
	{
		check := func(op, path, handler string) (bool, string) {
			e, err := N.exec("app/contract/authz", "check", anyParams(
				pair{txt("operation"), txt(op)}, pair{txt("path"), txt(path)}, pair{txt("handler_pattern"), txt(handler)}), nil)
			v, ok := resBool(e, "allowed")
			return v && ok, fmt.Sprintf("%s allowed=%v", obs(e, err), v)
		}
		a, o := check("echo", "app/contract/witness", "app/contract/witness")
		record("authority.path_permission/accept", a, o, "allowed")
		a, o = check("put", "app/contract/witness", "app/contract/witness")
		record("authority.path_permission/deny-operation", !a && strings.HasPrefix(o, "200"), o, "200, not allowed")
		a, o = check("echo", "app/elsewhere/x", "app/contract/witness")
		record("authority.path_permission/deny-path", !a && strings.HasPrefix(o, "200"), o, "200, not allowed")
		a, o = check("echo", "app/contract/witness", "app/contract/context")
		record("authority.path_permission/deny-handler", !a && strings.HasPrefix(o, "200"), o, "200, not allowed")
	}

	// ---- install.evaluator (MODULE) ----
	{
		register := func(pattern, typ string, data []byte) (map[string]interface{}, error) {
			if _, err := W.exec("system/tree", "put", putOf(typ, data), []string{pattern + "/expr"}); err != nil {
				return nil, err
			}
			if _, err := W.exec("system/handler", "register", registerRequestEntity(pattern, pattern+"/expr"),
				[]string{"system/handler/" + pattern}); err != nil {
				return nil, err
			}
			return W.exec(pattern, "compute", emptyParams(), []string{pattern})
		}
		val := "v-" + nonce
		e, err := register("app/contract/eval", "contract/echo-expression", cmap(pair{txt("value"), txt(val)}))
		record("install.evaluator/fallback-answers",
			resText(e, "evaluated_by") == "contract-evaluator" && resText(e, "value") == val,
			fmt.Sprintf("%s evaluated_by=%q value=%q", obs(e, err), resText(e, "evaluated_by"), resText(e, "value")),
			"200 evaluated_by=contract-evaluator value="+val)
		e, err = register("app/contract/literal", "compute/literal", cmap(pair{txt("value"), uint64v(42)}))
		s, _ := st(e, err)
		record("install.evaluator/literal-floor-first", s == 200 && resText(e, "evaluated_by") == "",
			fmt.Sprintf("%s evaluated_by=%q", obs(e, err), resText(e, "evaluated_by")),
			"200 answered by the built-in compute/literal, not the evaluator")
	}

	// ---- run.limits enforcement ----
	{
		big := func(n int) []byte { return cmap(pair{txt("blob"), bstr(bytes.Repeat([]byte{0x5a}, n))}) }
		c := dial(wideSeed)
		e, err := c.exec("system/tree", "put", putOf("primitive/any", big(frameBudget/4)), []string{"app/contract/scratch/under"})
		s, _ := st(e, err)
		record("run.limits/under-budget-accepted", s == 200, obs(e, err), "200 for a frame well under the budget")
		c2 := dial(wideSeed)
		e, err = c2.exec("system/tree", "put", putOf("primitive/any", big(frameBudget*2)), []string{"app/contract/scratch/over"})
		s, code := st(e, err)
		refused := s == 413 || (err != nil && c2.err == nil)
		record("run.limits/over-budget-refused", refused, fmt.Sprintf("%d %s", s, code),
			"413 payload_too_large, or the connection refused the frame")
		for _, cc := range []*client{c, c2} {
			if cc.s != nil {
				cc.s.close()
			}
		}
	}

	for _, c := range []*client{W, N, S} {
		if c.s != nil {
			c.s.close()
		}
	}

	// ---- embed.host_main: the bare host is the same run_host ----
	{
		bareReady := filepath.Join(*workdir, "bare-ready.json")
		bargs := append([]string{}, args...)
		bargs[len(bargs)-1] = bareReady
		bp, berr := launch(*bareCmd, bargs, []string{"HOME=" + home}, 60*time.Second)
		if berr != nil || bp.record == nil {
			record("embed.host_main/bare-host-record-matches", false, fmt.Sprintf("bare host did not start: %v", berr), "same record")
		} else {
			keys := func(m map[string]interface{}) []string {
				o := []string{}
				for k := range m {
					if k != "contract_host" && k != "addr" {
						o = append(o, k)
					}
				}
				sort.Strings(o)
				return o
			}
			same := reflect.DeepEqual(keys(bp.record), keys(rec))
			for _, k := range []string{"record", "peer_id", "posture", "posture_digest", "limits"} {
				if !reflect.DeepEqual(bp.record[k], rec[k]) {
					same = false
				}
			}
			bw := &client{}
			bw.s, bw.err = dialSession(dialAddr(bp.record), wideSeed, 15*time.Second)
			e, err := bw.exec("app/contract/witness", "echo", anyParams(), nil)
			s, _ := st(e, err)
			record("embed.host_main/bare-host-record-matches", same && bp.record["contract_host"] == nil && s == 404,
				fmt.Sprintf("same fields=%v contract_host=%v witness=%s", same, bp.record["contract_host"] != nil, obs(e, err)),
				"identical record shape and values, no contract_host, and no witness (404)")
			if bw.s != nil {
				bw.s.close()
			}
		}
		bp.stop()
	}

	// ---- run.stop ----
	{
		_ = hp.cmd.Process.Signal(syscall.SIGTERM)
		exited := false
		select {
		case <-hp.exited:
			exited = true
		case <-time.After(5 * time.Second):
		}
		refusedDial := false
		if exited {
			c, err := net.DialTimeout("tcp", addr, time.Second)
			if err != nil {
				refusedDial = true
			} else {
				c.Close()
			}
		}
		record("run.stop/sigterm-releases-port", exited && refusedDial,
			fmt.Sprintf("exited within 5s=%v port refuses=%v", exited, refusedDial), "process gone and port released")
		if !exited {
			_ = hp.cmd.Process.Kill()
		}
	}
}

func at(log []string, i int) string {
	if i < 0 || i >= len(log) {
		return ""
	}
	return log[i]
}

func capHashOf(c *client) []byte {
	if c.s == nil {
		return nil
	}
	return c.s.capHash
}

func lineOf(p *proc) string {
	if p == nil {
		return ""
	}
	return p.line
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func b64(b []byte) string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var o strings.Builder
	for i := 0; i < len(b); i += 3 {
		var chunk [3]byte
		n := copy(chunk[:], b[i:])
		v := uint(chunk[0])<<16 | uint(chunk[1])<<8 | uint(chunk[2])
		for j := 0; j < 4; j++ {
			if j <= n {
				o.WriteByte(alpha[(v>>(18-6*uint(j)))&0x3f])
			} else {
				o.WriteByte('=')
			}
		}
	}
	return o.String()
}

// registerRequestEntity is host-seam-probe's (the oracle's own register shape): the manifest is a
// BARE MAP, never an entity — see that probe for the fault this cost it.
func registerRequestEntity(pattern, exprPath string) []byte {
	opSpec := cmap(pair{txt("input_type"), txt("primitive/any")}, pair{txt("output_type"), txt("primitive/any")})
	star := cmap(pair{txt("include"), arr(txt("*"))})
	scope := arr(cmap(pair{txt("handlers"), star}, pair{txt("operations"), star}, pair{txt("resources"), star}))
	manifest := cmap(
		pair{txt("pattern"), txt(pattern)},
		pair{txt("name"), txt(pattern)},
		pair{txt("operations"), cmap(pair{txt("compute"), opSpec})},
		pair{txt("internal_scope"), scope},
		pair{txt("expression_path"), txt(exprPath)},
	)
	return entity("system/handler/register-request", cmap(pair{txt("manifest"), manifest}, pair{txt("requested_scope"), scope}))
}
