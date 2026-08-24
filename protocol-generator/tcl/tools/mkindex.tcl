# entity-core-protocol-tcl — regenerate src/pkgIndex.tcl (the S5 package_command).
#
# The peer is a single logical package `entity::core` whose umbrella loader
# (src/entity_core.tcl) sources the whole self-guarding module graph, so the index is
# one `package ifneeded` line rather than a per-file `pkg_mkIndex` scan (a per-file
# scan would need every module to `package provide`, which the umbrella model does not
# — the graph is loaded as a unit). This regenerator rewrites that line so the version
# stays in one place.
#
# Usage (from the peer root): tclsh tools/mkindex.tcl

set here [file dirname [file normalize [info script]]]
set root [file dirname $here]
set version 0.1

set out [open [file join $root src pkgIndex.tcl] w]
puts $out {# entity-core-protocol-tcl — package auto-load index (the .asd/Cargo.toml analogue).
#
# `package require entity::core` sources the umbrella loader, which pulls in the whole
# module graph (codec + protocol + transport); every module self-guards re-sourcing.
# Regenerate with `tclsh tools/mkindex.tcl`.
#
# NOTE: the crypto C-extension shim (libentitycorecrypto.so) is a compiled artifact,
# loaded SEPARATELY by the application (`load <shim> Entitycorecrypto`) before a peer
# signs/verifies — it is not a pure-Tcl package and is intentionally not indexed here.}
puts $out "package ifneeded entity::core $version \[list source \[file join \$dir entity_core.tcl\]\]"
close $out
puts "wrote src/pkgIndex.tcl (entity::core $version)"
