%% entity-core-protocol-oz — peerid.oz
%% peer_id wire form (§1.5 canonical-form table): Base58( varint(key_type) ‖
%% varint(hash_type) ‖ digest ). Construction is table-driven and never assumes
%% widths (corpus peer_id.3 pins the multi-byte varint path). Which
%% (key_type, hash_type) pair the peer's own identity uses is a §1.5-table
%% decision made in identity.oz (S3), not here.
functor
import
   Varint at 'varint.ozf'
   Base58 at 'base58.ozf'
export
   Format Parse
define
   %% {Format KeyType HashType DigestBytes} -> base58 char list
   fun {Format KeyType HashType Digest}
      {Base58.encode {Append {Varint.encode KeyType}
                      {Append {Varint.encode HashType} Digest}}}
   end

   %% {Parse Base58Chars ?KeyType ?HashType ?Digest}
   proc {Parse Chars ?KeyType ?HashType ?Digest}
      Bytes = {Base58.decode Chars}
      R1 R2
   in
      {Varint.decode Bytes ?KeyType ?R1}
      {Varint.decode R1 ?HashType ?R2}
      Digest = R2
   end
end
