--  Entity_Core.Codec — parent of the canonical-ECF codec layer.
--
--  Children:
--    .Value   — the ECF value model (discriminated variant; A-ADA-009)
--    .Varint  — multicodec LEB128 (N1)
--    .Base58  — Bitcoin-alphabet encode/decode
--    .Cbor    — canonical ECF encode/decode (the heart; N2/N3)
--    .Hash    — content_hash construction
--    .Peer_Id — peer_id format/parse (§1.5 canonical form; A-ADA-001)
package Entity_Core.Codec is
   pragma Pure;
end Entity_Core.Codec;
