% pack.pl — SWI-Prolog pack metadata for entity-core-protocol-prolog.
%
% The SWI `pack` system is the Prolog analogue of CL's ASDF `.asd` / Ruby's
% gemspec / Cargo.toml: this file is read by `pack_install/1`, `pack_property/2`,
% and `attach_packs/0` to describe the pack. Source lives under prolog/ (the
% module set ec_*.pl); the C-ABI floor (libentitycore_codec + the SWI foreign
% shim c/ec_codec_pl.c → ec_codec_pl.so) is BUILT, not shipped as source — see
% run-s2.sh and README §FFI floor.
%
% VERSION-STRING NOTE (A-PL-019 — the SWI analogue of CL A-CL-010 / Ruby
% A-RUBY-010). SWI's pack version grammar (`prolog_pack:is_version/1`) is STRICTER
% than SemVer AND stricter than RubyGems: a version must be purely dotted-NUMERIC
% (`split_string(V,".","",P), maplist(number_string,_,P)`), so EVERY component
% must parse as a number. It rejects `0.1.0-pre`, `0.1.0pre`, `0.1.0_pre`,
% `0.1.0-alpha.1`, `0.1.0-1` — all INVALID; only `0.1.0` is VALID (verified
% in-container, swipl 9.2.9). So the parseable `version(...)` below carries the
% bare dotted **0.1.0**, and the **0.1.0-pre** pre-release LINE lives in
% CHANGELOG.md + README.md (NOT in this file). A future promotion to 0.1.0 needs
% no change here — only the docs drop the `-pre`. This is the THIRD cohort
% ecosystem (after ASDF and RubyGems) whose version grammar disagrees with the
% SemVer dash; SWI is the strictest of the three (no pre-release channel at all).

name(entity_core_protocol).
title('Entity Core Protocol (V7) — SWI-Prolog peer: convergent logic layer over a C-ABI byte-floor').
version('0.1.0').        % SWI pack version is dotted-NUMERIC only (A-PL-019) — the `-pre` line lives in CHANGELOG/README
author('Entity Core Protocol contributors', 'noreply@entity-systems.invalid').
home('https://github.com/entity-systems/entity-core-keystone').

% download/0 deliberately UNSET: the pack is not yet published to a SWI pack
% registry (operator decides; /entity-rosetta never publishes — see PHASE-S5.md
% §Operator-handoff). A published pack sets download(URL) to the release tarball
% / git archive at the reviewed tag.

% requires/1 — runtime prerequisites. The crypto/codec floor is sourced over the
% C-ABI (libentitycore_codec), loaded via the SWI foreign shim with
% use_foreign_library/1 (a base-install builtin; no `library(ffi)` pack). The
% SWI libraries this peer uses (crypto, socket, thread, dcg/basics) all ship
% INSIDE the SWI distribution — no pack dependency to declare. The only external
% requirement is the SWI version line.
requires(prolog:version('9.2.0')).        % SWI-Prolog 9.2.x stable line (pinned 9.2.9; A-PL-008)

% provides/1 — the public module surface this pack exposes.
provides(ec_codec).        % the deterministic codec/crypto surface over the C-ABI floor
provides(ec_peer).         % peer assembly + §6.5 dispatch + the four MUST handlers
provides(ec_capability).   % §5 verification core (the relational chain walk)
provides(ec_transport).    % L4 TCP transport + §6.11 request_id demux
provides(ec_store).        % §3.9 store as the clause database
provides(ec_identity).     % peer_id / signature surface
provides(ec_types).        % §9.5 53-type registry (render-from-model)

% keywords — for pack search / discoverability.
keywords([entity, protocol, cbor, ed25519, capability, logic, ffi, conformance]).
