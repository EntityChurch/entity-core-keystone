package peer

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// §5.2 typed scope matching (0.8.1, F40) — ACCEPT-path unit checks.
//
// The oracle carried no F40 vector when this was written, and a rejection-only probe
// would let a uniformly-canonicalizing peer pass anyway, so the accept direction is the
// peer's own to cover. Drives the real matchesScope against the cohort-shared case set
// in protocol-generator/shared/scope-matching/id-scope-vectors.json, so every peer in
// the cohort is measured against one reading of §5.2 rather than 43.
//
// The load-bearing case is id.exclude.pathform: an `exclude` written in path form inside
// an `operations` scope DENIES on the pre-F40 canonicalizing reading and ALLOWS on the
// conformant one — it cannot be passed by accident.

const (
	f40Local  = "12D3KooWLocalPeerIdExampleAAAAAAAAAAAAAAAAAAAA"
	f40Remote = "12D3KooWRemotePeerIdExampleBBBBBBBBBBBBBBBBBBB"
)

const f40Vectors = "../../../shared/scope-matching/id-scope-vectors.json"

type f40Case struct {
	ID        string   `json:"id"`
	ScopeType string   `json:"scope_type"`
	Value     string   `json:"value"`
	Include   []string `json:"include"`
	Exclude   []string `json:"exclude"`
	Expect    bool     `json:"expect"`
}

func f40Sub(s string) string {
	s = strings.ReplaceAll(s, "{local}", f40Local)
	return strings.ReplaceAll(s, "{remote}", f40Remote)
}

func f40SubAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = f40Sub(s)
	}
	return out
}

func TestF40TypedScopeMatching(t *testing.T) {
	raw, err := os.ReadFile(f40Vectors)
	if err != nil {
		t.Fatalf("read shared F40 vectors: %v", err)
	}
	var doc struct {
		Cases []f40Case `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse shared F40 vectors: %v", err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("shared F40 vector file carries no cases")
	}

	for _, c := range doc.Cases {
		kind := kindPath
		if c.ScopeType == "id-scope" {
			kind = kindID
		}
		s := scope{incl: f40SubAll(c.Include), excl: f40SubAll(c.Exclude)}
		if got := matchesScope(f40Local, f40Sub(c.Value), s, kind); got != c.Expect {
			t.Errorf("%s: expected %v, got %v", c.ID, c.Expect, got)
		}
	}
}

// TestF40ExcludeInversion states the discriminating case inline as well as via the
// fixture: the same path-form exclude must ALLOW on an id dimension and DENY on a path
// dimension. Together they prove the fix is a split, not a blanket removal of
// canonicalization.
func TestF40ExcludeInversion(t *testing.T) {
	ops := scope{incl: []string{"*"}, excl: []string{"/*/get"}}
	if !matchesScope(f40Local, "get", ops, kindID) {
		t.Error("id-scope: a path-form exclude must not match a bare identifier")
	}
	handlers := scope{incl: []string{"*"}, excl: []string{"/*/system/tree"}}
	if matchesScope(f40Local, "system/tree", handlers, kindPath) {
		t.Error("path-scope: the /*/ exclude must still canonicalize and bite")
	}
}

// TestSentinelIsPathScopeOnly — §5.4's unmatchable-pattern rule is scoped to
// PATH-SCOPE (0.8.2.24, N2/N3), and this is the discriminating pair.
//
// "A capability carrying an unmatchable PATH-SCOPE pattern is INVALID [MUST] …
// It does NOT reach `operations` or `peers` [MUST]." NEVER_MATCH is a §5.4
// path-canonicalization sentinel; an id-scope pattern is a literal identifier
// that §5.2's id-scope arm forbids putting through the §5.4 transforms at all.
//
// The id-scope case cannot be passed by accident: `*/apply` is an ordinary
// namespaced operation name that path-canonicalizes to the sentinel, so on the
// pre-.24 unscoped reading it DENIED THE WHOLE DIMENSION — `get` included by a
// bare `*` came back false. The path-scope case is the other half and proves
// this is a scope split rather than a removal: the sentinel's own arm still
// bites where the dimension is a path.
func TestSentinelIsPathScopeOnly(t *testing.T) {
	// id-scope: the sentinel MUST NOT be consulted. `*/apply` is a literal here
	// and carves out nothing, so `get` stays included.
	ops := scope{incl: []string{"*"}, excl: []string{"*/apply"}}
	if !matchesScope(f40Local, "get", ops, kindID) {
		t.Error("id-scope: a path-unmatchable exclude must not deny the dimension (0.8.2.24)")
	}
	// The same holds for `peers`, the other id-scope dimension.
	peers := scope{incl: []string{"*"}, excl: []string{"../nope"}}
	if !matchesScope(f40Local, f40Local, peers, kindID) {
		t.Error("id-scope peers: a path-unmatchable exclude must not deny the dimension (0.8.2.24)")
	}
	// path-scope: UNCHANGED. An unmatchable exclude still denies, because there
	// it would otherwise carve out nothing and leave the grant silently wider
	// than its author wrote (0.8.2.21).
	res := scope{incl: []string{"*"}, excl: []string{"../nope"}}
	if matchesScope(f40Local, "system/tree", res, kindPath) {
		t.Error("path-scope: an unmatchable exclude must still deny (0.8.2.21)")
	}
	// And a path-scope exclude that IS matchable still carves out only its own
	// target — the sentinel arm must not have swallowed the ordinary case.
	ok := scope{incl: []string{"*"}, excl: []string{"system/secret"}}
	if !matchesScope(f40Local, "system/tree", ok, kindPath) {
		t.Error("path-scope: an ordinary exclude must not deny an unrelated value")
	}
}

// TestF40IDWildcardsSurvive — bootstrap depends on these: the seed policy grants
// operations ["*"], and a strict string-equality reading would break it.
func TestF40IDWildcardsSurvive(t *testing.T) {
	for _, tc := range []struct {
		value, pattern string
		want           bool
	}{
		{"get", "*", true},
		{"compute/apply", "compute/*", true},
		{"compute", "compute/*", false},
		{"computex/apply", "compute/*", false},
	} {
		s := scope{incl: []string{tc.pattern}}
		if got := matchesScope(f40Local, tc.value, s, kindID); got != tc.want {
			t.Errorf("%q vs %q: expected %v, got %v", tc.value, tc.pattern, tc.want, got)
		}
	}
}
