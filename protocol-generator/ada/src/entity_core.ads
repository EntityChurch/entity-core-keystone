--  Entity_Core — root library unit for entity-core-protocol-ada.
--
--  The core protocol peer (V7 Layers 0-4) in Ada. This S2 deliverable is the
--  CODEC layer only: canonical ECF (CBOR), content_hash, peer_id, Ed25519
--  sign/verify, and the value model. Peer machinery (tasks, protected-object
--  store, dispatch) enters at S3.
--
--  Idiom: strong typing (distinct named types, not bare byte arrays),
--  design-by-contract aspects (Pre/Post/Type_Invariant), and exceptions for
--  the error model (profile [error_model]).
package Entity_Core is
   pragma Pure;
end Entity_Core;
