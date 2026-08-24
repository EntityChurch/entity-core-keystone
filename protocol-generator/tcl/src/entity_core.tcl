# entity-core-protocol-tcl — umbrella loader (the .asd/Cargo.toml analogue).
#
# `source`s the full peer (codec + protocol + transport). The crypto C-extension
# shim (libentitycorecrypto.so) is loaded SEPARATELY by the caller (`load <shim>
# Entitycorecrypto`) since it is a compiled artifact outside the pure-Tcl tree — see
# the Makefile / run-s3.sh. Every module self-guards against re-sourcing, so the
# diamond dependency graph loads each file exactly once.

package require Tcl 8.6-
if {[info exists ::_entity_core_loaded([info script])]} return; set ::_entity_core_loaded([info script]) 1

set _ecdir [file dirname [info script]]
source [file join $_ecdir transport.tcl]   ;# pulls in handlers -> peer -> the whole graph
unset _ecdir

package provide entity::core 0.1
