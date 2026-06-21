/*
 * transport.h — L4 TCP transport: listener/dialer, per-connection reader threads, §6.11
 * request_id demux, §4.8 inbound-concurrent-with-outbound dispatch, the §6.13(b) reentry
 * seam. Plus the initiator dialer/handshake that drives the loopback smoke.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef EC_TRANSPORT_H
#define EC_TRANSPORT_H

#include "peer_internal.h"

/* ── per-connection IO (transport-private; opaque to other modules) ──────────── */
typedef struct ec_io ec_io;

/* Build an Io over an already-connected socket fd (sets TCP_NODELAY, §7b). Takes the
 * fd. On EC_OK *out is owned by the caller (free via ec_io_free after the reader joins). */
ec_status ec_io_new(int fd, ec_io **out);
void ec_io_free(ec_io *io);
/* Force a blocked recv() to return + mark closed (idempotent). */
void ec_io_close(ec_io *io);

/*
 * The §6.13(b)/§6.11 outbound primitive over a live connection: write `request` (an
 * EXECUTE envelope) and await its correlated EXECUTE_RESPONSE by request_id (the reader
 * routes it back). Used by the §7a dispatch-outbound reentry seam to originate back to
 * the caller over the SAME inbound connection. Returns the response envelope (+1 ref;
 * caller frees with ec_env_free) or NULL if the connection closed before a reply. Does
 * NOT take ownership of `request`.
 */
ec_envelope *ec_io_outbound(ec_io *io, ec_envelope *request);

/* ── server side ─────────────────────────────────────────────────────────────── */

typedef struct ec_listener ec_listener;

/* Bind 127.0.0.1:port (0 = auto) + spawn the accept loop. *out_port = bound port. */
ec_status ec_listener_start(ec_peer *peer, int port, ec_listener **out, int *out_port);
void ec_listener_stop(ec_listener *l);

/* ── client side: dialer + initiator handshake ───────────────────────────────── */

/* A dialed, authenticated session (§4.4): the minted cap token + granter + sig. */
typedef struct ec_session ec_session;

/* Dial host:port, start the reader thread, drive the §4.1 handshake. +1 refs held
 * inside; free with ec_session_close. *out set on EC_OK. */
ec_status ec_session_dial(ec_peer *initiator, const char *host, int port, ec_session **out);
void ec_session_close(ec_session *s);

const char *ec_session_remote_peer(const ec_session *s);   /* borrow */
bool ec_session_has_capability(const ec_session *s);

/*
 * Build, sign, and send an authenticated EXECUTE; await its correlated response
 * (request_id demux, N7). `resource` is an owned value map (CONSUMED) or NULL.
 * On EC_OK *out_resp is the response envelope (+1 ref; caller frees with ec_env_free),
 * or NULL if the connection closed before a reply.
 */
ec_status ec_session_execute(ec_session *s, const char *uri, const char *operation,
                             ec_entity *params, ec_value *resource, ec_envelope **out_resp);

/* response helpers */
uint64_t ec_response_status(const ec_envelope *resp);
ec_entity *ec_response_result(const ec_envelope *resp);     /* +1 ref or NULL */

#endif /* EC_TRANSPORT_H */
