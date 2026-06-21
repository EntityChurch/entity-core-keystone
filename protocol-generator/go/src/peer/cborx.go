package peer

import "github.com/entity-core/entity-core-protocol-go/internal/cbor"

// cborx.go — small constructors for building cbor.Value trees at peer call
// sites without ceremony. These complement the codec's own constructors.

// strList builds a CBOR array of text values.
func strList(ss ...string) cbor.Value {
	arr := make([]cbor.Value, len(ss))
	for i, s := range ss {
		arr[i] = cbor.Text(s)
	}
	return cbor.Value{Kind: cbor.KindArray, Array: arr}
}

// valList builds a CBOR array from already-built Values.
func valList(vs ...cbor.Value) cbor.Value {
	return cbor.Value{Kind: cbor.KindArray, Array: append([]cbor.Value(nil), vs...)}
}

// asList returns v's elements if v is an array, else nil.
func asList(v cbor.Value) []cbor.Value {
	if v.Kind == cbor.KindArray {
		return v.Array
	}
	return nil
}

// textElems returns the text elements of an array Value (skipping non-text).
func textElems(v cbor.Value) []string {
	var out []string
	for _, el := range asList(v) {
		if el.Kind == cbor.KindText {
			out = append(out, el.Text)
		}
	}
	return out
}

// emptyMap is the canonical empty map Value.
func emptyMap() cbor.Value { return cbor.NewMap() }
