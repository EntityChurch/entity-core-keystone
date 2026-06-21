// dump-type-registry renders the validate-peer type_system oracle's registry
// (types.RegisterCoreTypes + the connect/tree handler types it reflects in
// runTypeSystem) to a vector set: a canonical `.cbor` build artifact plus a
// `.diag` human source-of-truth in CBOR diagnostic notation (RFC 8949 §8),
// matching the project's test-vectors convention.
//
// This is a DERIVED drift/diff target (S8 golden-file pattern), regenerated
// from the Go oracle — NOT an arch-authored canonical corpus (S5). A generated
// peer renders its own system/type/* entities natively and diffs their
// content_hash against this set (see memory: type-registry-render-design).
//
// Mirrors entity-core-go/cmd/compare-types generateLocalTypes() exactly so the
// emitted set equals what runTypeSystem compares against.
//
// Usage: dump-type-registry <out-dir>
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"entity-core-go/core/ecf"
	"entity-core-go/core/types"
)

// vector is one rendered type. CBOR field order follows the struct (ecf.Encode
// applies canonical key ordering regardless).
type vector struct {
	Name        string `cbor:"name"`
	TreePath    string `cbor:"tree_path"`
	ContentHash string `cbor:"content_hash"`
	Data        []byte `cbor:"data"` // ECF-encoded TypeDefinition payload (the entity data)
}

func buildRegistry() *types.TypeRegistry {
	reg := types.NewTypeRegistry()
	types.RegisterCoreTypes(reg)

	// Connect handler types (as runTypeSystem / compare-types register them).
	reg.ReflectType(types.TypeHello, reflect.TypeOf(types.HelloData{}))
	reg.ReflectType(types.TypeAuthenticate, reflect.TypeOf(types.AuthenticateData{}))
	reg.OverrideField(types.TypeHello, "peer_id", types.FieldSpec{TypeRef: "system/peer-id"})
	reg.OverrideField(types.TypeAuthenticate, "peer_id", types.FieldSpec{TypeRef: "system/peer-id"})

	// Tree handler types.
	reg.ReflectType(types.TypeTreeGetRequest, reflect.TypeOf(types.GetRequestData{}))
	reg.ReflectType(types.TypeTreePutRequest, reflect.TypeOf(types.PutRequestData{}))
	reg.OverrideField(types.TypeTreePutRequest, "entity",
		types.FieldSpec{TypeRef: types.TypeCoreEntity, Optional: true})
	reg.ReflectType(types.TypeTreeListing, reflect.TypeOf(types.ListingData{}))
	reg.OverrideField(types.TypeTreeListing, "entries",
		types.FieldSpec{MapOf: &types.FieldSpec{TypeRef: "system/tree/listing-entry"}})
	reg.OverrideField(types.TypeTreeListing, "path",
		types.FieldSpec{TypeRef: "system/tree/path"})
	return reg
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: dump-type-registry <out-dir>")
		os.Exit(2)
	}
	outDir := os.Args[1]

	reg := buildRegistry()
	all := reg.All()
	vecs := make([]vector, 0, len(all))
	for _, td := range all {
		ent, err := td.ToEntity()
		if err != nil {
			fmt.Fprintf(os.Stderr, "ToEntity %s: %v\n", td.Name, err)
			os.Exit(1)
		}
		raw, err := ecf.Encode(td)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Encode %s: %v\n", td.Name, err)
			os.Exit(1)
		}
		vecs = append(vecs, vector{
			Name:        td.Name,
			TreePath:    td.TreePath(),
			ContentHash: ent.ContentHash.String(),
			Data:        raw,
		})
	}
	sort.Slice(vecs, func(i, j int) bool { return vecs[i].Name < vecs[j].Name })

	// Canonical .cbor artifact: the whole vector array, ECF-encoded.
	cborBytes, err := ecf.Encode(vecs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode vector array: %v\n", err)
		os.Exit(1)
	}
	cborPath := filepath.Join(outDir, "type-registry-vectors-v1.cbor")
	if err := os.WriteFile(cborPath, cborBytes, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write cbor: %v\n", err)
		os.Exit(1)
	}

	// .diag human source-of-truth (RFC 8949 §8 diagnostic notation).
	diagPath := filepath.Join(outDir, "type-registry-vectors-v1.diag")
	if err := os.WriteFile(diagPath, []byte(renderDiag(vecs)), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write diag: %v\n", err)
		os.Exit(1)
	}

	// Readable shapes.json — the TypeDefinition structs, sorted by name. This is
	// the authoring reference a peer developer reads to declare each type's field
	// shape in their language (NOT served; the peer renders natively).
	all2 := buildRegistry().All()
	sort.Slice(all2, func(i, j int) bool { return all2[i].Name < all2[j].Name })
	shapesPath := filepath.Join(outDir, "type-registry-shapes.json")
	sb, err := json.MarshalIndent(all2, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal shapes: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(shapesPath, append(sb, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write shapes: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "dumped %d types -> %s, %s, %s\n", len(vecs), cborPath, diagPath, shapesPath)
}

func renderDiag(vecs []vector) string {
	var b strings.Builder
	b.WriteString("/\n")
	b.WriteString("  Type-registry render vectors — v1 (DERIVED drift/diff target)\n")
	b.WriteString("  Source:  entity-core-go types.RegisterCoreTypes + connect/tree handler\n")
	b.WriteString("           types (== validate-peer runTypeSystem registry).\n")
	b.WriteString("  Status:  NOT an arch-authored canonical corpus (S5). Regenerate from\n")
	b.WriteString("           the Go oracle when entity-core-go moves. The sibling\n")
	b.WriteString("           `type-registry-vectors-v1.cbor` is the canonical-ECF build\n")
	b.WriteString("           artifact (array of {name, tree_path, content_hash, data}).\n")
	b.WriteString("  Use:     a peer renders its own system/type/<name> entities natively\n")
	b.WriteString("           and diffs each content_hash against this set (S8 golden-file).\n")
	b.WriteString("  Format:  CBOR diagnostic notation, RFC 8949 §8. `data` is the\n")
	b.WriteString("           ECF-encoded TypeDefinition payload (entity data).\n")
	b.WriteString(fmt.Sprintf("  Count:   %d types.\n", len(vecs)))
	b.WriteString("/\n\n[\n")
	for i, v := range vecs {
		comma := ","
		if i == len(vecs)-1 {
			comma = ""
		}
		b.WriteString(fmt.Sprintf(
			"  { \"name\": %q, \"tree_path\": %q, \"content_hash\": %q, \"data\": h'%s' }%s\n",
			v.Name, v.TreePath, v.ContentHash, hex.EncodeToString(v.Data), comma))
	}
	b.WriteString("]\n")
	return b.String()
}
