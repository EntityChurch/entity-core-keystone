// Keystone-local interim dev oracle. Consumes the entity-core-go reference
// encoder via a relative replace (sibling repo under entity-systems/).
// Build/run in a container per S1 — see ./README.md. Not published.
module entity-core-keystone/c-abi-oracle

go 1.25.0

require entity-core-go/core v0.0.0

require (
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
)

replace entity-core-go/core => ../../../../../entity-core-go/core
