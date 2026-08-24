# entity-core-protocol-tcl — package auto-load index (the .asd/Cargo.toml analogue).
#
# `package require entity::core` sources the umbrella loader, which pulls in the whole
# module graph (codec + protocol + transport); every module self-guards re-sourcing.
# Regenerate with `tclsh tools/mkindex.tcl`.
#
# NOTE: the crypto C-extension shim (libentitycorecrypto.so) is a compiled artifact,
# loaded SEPARATELY by the application (`load <shim> Entitycorecrypto`) before a peer
# signs/verifies — it is not a pure-Tcl package and is intentionally not indexed here.
package ifneeded entity::core 0.1 [list source [file join $dir entity_core.tcl]]
