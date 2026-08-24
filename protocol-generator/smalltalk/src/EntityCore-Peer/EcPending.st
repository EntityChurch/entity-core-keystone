"entity-core-protocol-smalltalk — the §6.11 request_id demux pending table (EntityCore-Peer).

A handler that ORIGINATES an outbound EXECUTE sends it, then re-enters the serve pump (keeps
serving other inbound frames) until the correlated reply — matched by `request_id` — arrives.
On a single-event-loop substrate there is no separate thread: the correlation is a table
keyed by request_id, each pending record holding a done flag + the parked reply root entity
(the correlation-map tax the non-actor/non-CSP peers pay — profile request_demux).

CRITICAL (the cohort''s A-FT-025 lesson): each concurrent reentry MUST get its OWN pending
record keyed by its OWN request_id — a shared/aliased slot cross-talks every reply to one
awaiter (§6.11(b)). Keying the Dictionary by the request_id String makes distinct request_ids
structurally distinct records here (no stale-index hazard as in the Forth array model).

EcPending is the table; EcPendingRecord is one awaited outbound.

LIVE-IMAGE NOTE: EcPendingRecord resolves at send-time."

| pkg rec table |
pkg := 'EntityCore-Peer'.

rec := ((Object << #EcPendingRecord) slots: { #requestId. #done. #replyRoot };
	package: pkg; install).
rec class compile: 'for: aRequestId  ^ self new setRequestId: aRequestId'.
rec compile: 'setRequestId: aRequestId
	requestId := aRequestId. done := false. replyRoot := nil. ^ self'.
rec compile: 'requestId  ^ requestId'.
rec compile: 'isDone  ^ done'.
rec compile: 'replyRoot  ^ replyRoot'.
rec compile: 'deliver: aRootEntity  replyRoot := aRootEntity. done := true'.

table := ((Object << #EcPending) slots: { #records }; package: pkg; install).
table class compile: 'new  ^ super new initTable'.
table compile: 'initTable  records := Dictionary new. ^ self'.
table compile: 'reset  records := Dictionary new'.

"open: — register a new pending record for a request_id (a distinct record per id)."
table compile: 'open: aRequestId
	| r |
	r := EcPendingRecord for: aRequestId.
	records at: aRequestId put: r.
	^ r'.

"deliverReplyFor:root: — correlate an inbound EXECUTE_RESPONSE root to its pending record by
 request_id (§6.11 demux). Silently ignores an uncorrelated reply."
table compile: 'deliverReplyFor: aRequestId root: aRootEntity
	| r |
	r := records at: aRequestId ifAbsent: [ ^ self ].
	r deliver: aRootEntity'.

"close: — drop a completed pending record."
table compile: 'close: aRequestId  records removeKey: aRequestId ifAbsent: [ ]'.
table compile: 'size  ^ records size'.

'EntityCore-Peer:EcPending installed'
