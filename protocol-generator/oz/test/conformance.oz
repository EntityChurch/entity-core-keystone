%% entity-core-protocol-oz — S2 codec conformance (71-vector pinned corpus).
%% Decodes the corpus WITH OUR OWN decoder (bootstrapping), then per vector:
%%   encode_equal  -> re-encode / construct and byte-compare vs `canonical`
%%   decode_reject -> DecodeCanonical(canonical) MUST raise
%% Class B (content_hash / signature) crosses the entity-codec-daemon.
%% Usage: ozengine build/conformance.ozf <corpus.cbor> <daemon-path>
functor
import
   System Application Open
   Util at 'util.ozf'
   Cbor at 'cbor.ozf'
   Varint at 'varint.ozf'
   Peerid at 'peerid.ozf'
   Crypto at 'crypto.ozf'
define
   proc {ReadFile Path ?Bytes}
      F = {New Open.file init(name:Path flags:[read])}
      fun {Go}
         Xs M
      in
         {F read(list:?Xs size:65536 len:?M)}
         if M == 0 then nil else {Append Xs {Go}} end
      end
   in
      Bytes = {Go}
      {F close}
   end

   Pass = {NewCell 0}
   Fail = {NewCell 0}
   Fails = {NewCell nil}

   proc {Ok} Pass := @Pass + 1 end
   proc {Bad Id Why}
      Fail := @Fail + 1
      Fails := (Id#Why)|@Fails
   end

   fun {TextOf V} case V of text(L) then L else nil end end
   fun {BytesOf V} case V of bytes(L) then L else nil end end
   fun {IntOf V} case V of int(N) then N else 0 end end

   fun {CatOf Id}
      case Id of nil then nil
      [] C|Cr then if C == &. then nil else C|{CatOf Cr} end
      end
   end

   fun {GotPeerId Input}
      KT = {IntOf {Cbor.mapGet Input "key_type"}}
      HT = {IntOf {Cbor.mapGet Input "hash_type"}}
      DG = {BytesOf {Cbor.mapGet Input "digest"}}
   in
      {Cbor.encode text({Peerid.format KT HT DG})}
   end

   fun {GotContentHash Input}
      TypeV = {Cbor.mapGet Input "type"}
      DataV = {Cbor.mapGet Input "data"}
      FC = case {Cbor.mapGet Input "format_code"} of int(N) then N else 0 end
      Entity = map([text({Util.vsToBytes "type"})#TypeV
                    text({Util.vsToBytes "data"})#DataV])
      Digest = if FC == 1 then {Crypto.sha384 {Cbor.encode Entity}}
               else {Crypto.sha256 {Cbor.encode Entity}} end
   in
      {Append {Varint.encode FC} Digest}
   end

   fun {GotSignature Input}
      Seed = {BytesOf {Cbor.mapGet Input "seed"}}
      EntV = {Cbor.mapGet Input "entity"}
   in
      {Crypto.ed25519Sign Seed {Cbor.encode EntV}}
   end

   proc {ProcessVec Vec}
      Id = {TextOf {Cbor.mapGet Vec "id"}}
      Kind = {TextOf {Cbor.mapGet Vec "kind"}}
      Canon = {BytesOf {Cbor.mapGet Vec "canonical"}}
      Input = {Cbor.mapGet Vec "input"}
      Cat = {CatOf Id}
   in
      if Kind == "decode_reject" then
         try
            _ = {Cbor.decodeCanonical Canon}
            {Bad Id "expected decode reject, but decoded"}
         catch error(entityCore(...) ...) then {Ok}
         end
      else
         try
            Got = if Cat == "peer_id" then {GotPeerId Input}
                  elseif Cat == "content_hash" then {GotContentHash Input}
                  elseif Cat == "signature" then {GotSignature Input}
                  else {Cbor.encode Input}
                  end
         in
            if Got == Canon then {Ok}
            else {Bad Id "encode mismatch want="#{Util.hexOfBytes Canon}#" got="#{Util.hexOfBytes Got}}
            end
         catch error(entityCore(kind:K detail:D) ...) then
            {Bad Id "unexpected reject "#K#"/"#{Value.toVirtualString D 3 3}}
         end
      end
   end

   Args = {Application.getArgs plain}
in
   case Args of [CorpusPath DaemonPath] then
      Corpus Top
   in
      {Crypto.init DaemonPath}
      Corpus = {ReadFile CorpusPath}
      Top = {Cbor.decodeCanonical Corpus}
      case Top of arr(Vecs) then
         {ForAll Vecs ProcessVec}
         {System.showInfo ""}
         {System.showInfo "=== conformance: "#{Length Vecs}#" vectors — "#@Pass#" pass / "#@Fail#" fail ==="}
         {ForAll {Reverse @Fails}
          proc {$ IW} {System.showInfo "  FAIL "#IW.1#": "#IW.2} end}
         if @Fail > 0 then {Application.exit 1} else {Application.exit 0} end
      else
         {System.showInfo "FATAL: corpus top-level is not an array"}
         {Application.exit 2}
      end
   else
      {System.showInfo "usage: conformance <corpus.cbor> <daemon>"}
      {Application.exit 2}
   end
end
