with Ada.Calendar;
with Ada.Strings.Fixed;
with Interfaces;
with Entity_Core.Crypto;
with Entity_Core.Protocol.Cbor_Util;
with Entity_Core.Protocol.Identity;
with Entity_Core.Errors;

package body Entity_Core.Protocol.Capability is

   use Entity_Core.Codec.Value;
   use Entity_Core.Protocol.Cbor_Util;
   package Env_Pkg renames Entity_Core.Protocol.Envelope;

   Base58_Alphabet : constant String :=
     "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

   --  §6.2 CAP-6a: the temporal fields whose representability is checked on a
   --  RECEIVED token, before any range comparison.
   type Key_Access is access constant String;
   Key_Expires_At : aliased constant String := "expires_at";
   Key_Not_Before : aliased constant String := "not_before";
   Key_Created_At : aliased constant String := "created_at";
   Temporal_Keys : constant array (1 .. 3) of Key_Access :=
     (Key_Expires_At'Access, Key_Not_Before'Access, Key_Created_At'Access);

   --  Which §5.2 matcher a grant dimension uses (0.8.1, F40). Id_Scope is
   --  Operations/Peers (system/capability/id-scope); Path_Scope is
   --  Handlers/Resources (system/capability/path-scope).
   type Scope_Kind is (Id_Scope, Path_Scope);

   --  Resolve a hash to an entity: prefer Env.included, then the store.
   function Resolve
     (Store : access Entity_Core.Protocol.Store.Safe_Store;
      Env   : Env_Pkg.Protocol_Envelope;
      H     : Byte_Array;
      Found : out Boolean) return Materialized_Entity
   is
      E : Materialized_Entity := Env_Pkg.Included_Get (Env, H, Found);
   begin
      if Found then
         return E;
      end if;
      if Store /= null then
         E := Store.Get_By_Hash (H, Found);
      end if;
      return E;
   end Resolve;

   ----------------
   -- Starts_With --
   ----------------
   function Starts_With (Prefix, S : String) return Boolean is
   begin
      return S'Length >= Prefix'Length
        and then S (S'First .. S'First + Prefix'Length - 1) = Prefix;
   end Starts_With;

   -------------------
   -- Normalize_Uri --
   -------------------
   function Normalize_Uri (Uri : String) return String is
   begin
      if Starts_With ("entity://", Uri) then
         return "/" & Uri (Uri'First + 9 .. Uri'Last);
      end if;
      return Uri;
   end Normalize_Uri;

   ------------------
   -- Canonicalize --
   ------------------
   function Canonicalize (Local_Peer : String; Path : String) return String is
   begin
      if Starts_With ("./", Path) or else Starts_With ("../", Path) then
         raise Constraint_Error with "canonicalize: reserved directory-relative path";
      end if;
      if Starts_With ("*/", Path) then
         raise Constraint_Error with "canonicalize: ambiguous bare peer wildcard";
      end if;
      if Starts_With ("/", Path) then
         return Path;
      end if;
      return "/" & Local_Peer & "/" & Path;
   end Canonicalize;

   -----------------
   -- Is_Peer_Id --
   -----------------
   function Is_Peer_Id (Seg : String) return Boolean is
   begin
      if Seg'Length < 46 then
         return False;
      end if;
      for C of Seg loop
         if Ada.Strings.Fixed.Index (Base58_Alphabet, String'(1 => C)) = 0 then
            return False;
         end if;
      end loop;
      return True;
   end Is_Peer_Id;

   -------------------
   -- First_Segment --
   -------------------
   function First_Segment (Uri : String) return String is
      U : constant String := (if Starts_With ("/", Uri)
                              then Uri (Uri'First + 1 .. Uri'Last) else Uri);
      I : constant Natural := Ada.Strings.Fixed.Index (U, "/");
   begin
      if I = 0 then
         return U;
      end if;
      return U (U'First .. I - 1);
   end First_Segment;

   -------------------
   -- Extract_Peer --
   -------------------
   function Extract_Peer (Local_Peer : String; Uri : String) return String is
      First : constant String := First_Segment (Normalize_Uri (Uri));
   begin
      if Is_Peer_Id (First) then
         return First;
      end if;
      return Local_Peer;
   end Extract_Peer;

   ----------------------
   -- Matches_Pattern --
   ----------------------
   function Matches_Pattern (Path : String; Pattern : String) return Boolean is
   begin
      if Pattern = "*" then
         return True;
      end if;
      if Starts_With ("/*/", Pattern) then
         declare
            Remainder : constant String := Pattern (Pattern'First + 3 .. Pattern'Last);
            I : Natural := 0;
         begin
            if Path'Length < 1 then
               return False;
            end if;
            --  index of first '/' after position 1
            for K in Path'First + 1 .. Path'Last loop
               if Path (K) = '/' then
                  I := K;
                  exit;
               end if;
            end loop;
            return I /= 0
              and then Matches_Pattern (Path (I + 1 .. Path'Last), Remainder);
         end;
      end if;
      if Pattern'Length >= 2
        and then Pattern (Pattern'Last - 1 .. Pattern'Last) = "/*"
      then
         return Starts_With (Pattern (Pattern'First .. Pattern'Last - 1), Path);
      end if;
      return Path = Pattern;
   end Matches_Pattern;

   ---------------------------------------------------------------------------
   --  Scope / grant model. We read scopes directly off the cbor maps; no
   --  intermediate record allocation (Ada value semantics on the slices).
   ---------------------------------------------------------------------------

   --  True iff any pattern in array Patterns (canonicalized on Frame) matches V.
   function Covered_Frame (Frame : String; Patterns : Ecf_Value; V : String) return Boolean is
   begin
      if Kind (Patterns) /= K_Array then
         return False;
      end if;
      for I in 1 .. Array_Length (Patterns) loop
         declare
            P : constant Ecf_Value := Array_Element (Patterns, I);
         begin
            if Kind (P) = K_Text
              and then Matches_Pattern (V, Canonicalize (Frame, As_Text (P)))
            then
               return True;
            end if;
         end;
      end loop;
      return False;
   end Covered_Frame;

   --  §5.2 id-scope match (0.8.1, F40) — Operations and Peers. Literal comparison
   --  with exactly two wildcard forms: bare "*" and a trailing slash-star
   --  segment-prefix. None of the §5.4 path transforms apply, so a pattern carrying
   --  path syntax is matched as a literal string: a non-match, never a fault.
   function Matches_Id_Pattern (Value : String; Pattern : String) return Boolean is
   begin
      if Pattern = "*" then
         return True;
      end if;
      if Pattern'Length >= 2
        and then Pattern (Pattern'Last - 1 .. Pattern'Last) = "/*"
      then
         declare
            Prefix : constant String :=
              Pattern (Pattern'First .. Pattern'Last - 1);
         begin
            return Value'Length >= Prefix'Length
              and then Value (Value'First .. Value'First + Prefix'Length - 1)
                       = Prefix;
         end;
      end if;
      return Value = Pattern;
   end Matches_Id_Pattern;

   --  Any id-scope pattern in Patterns covering Value — no canonicalization.
   function Covered_Id (Patterns : Ecf_Value; Value : String) return Boolean is
   begin
      if Kind (Patterns) /= K_Array then
         return False;
      end if;
      for I in 1 .. Array_Length (Patterns) loop
         declare
            P : constant Ecf_Value := Array_Element (Patterns, I);
         begin
            if Kind (P) = K_Text and then Matches_Id_Pattern (Value, As_Text (P))
            then
               return True;
            end if;
         end;
      end loop;
      return False;
   end Covered_Id;

   --  Scope match (§5.2), typed by scope kind (0.8.1, F40). Kind is named at every
   --  call site — there is no default — so a new one cannot inherit the wrong matcher
   --  silently, which is exactly the F40 defect.
   function Matches_Scope (Local_Peer : String; Value : String; Scope : Ecf_Value;
                           Kind_Of : Scope_Kind)
                           return Boolean is
      Incl : constant Ecf_Value := Field (Scope, "include");
      Excl : constant Ecf_Value := Field (Scope, "exclude");
   begin
      if Kind_Of = Id_Scope then
         return Covered_Id (Incl, Value) and then not Covered_Id (Excl, Value);
      end if;
      declare
         CV : constant String := Canonicalize (Local_Peer, Value);
      begin
         return Covered_Frame (Local_Peer, Incl, CV)
           and then not Covered_Frame (Local_Peer, Excl, CV);
      end;
   end Matches_Scope;

   --  §PR-8 resource scope: caller targets canonicalize on Local; the grant's
   --  own patterns canonicalize on Granter_Peer.
   function Check_Resource_Scope
     (Local_Peer, Granter_Peer : String; Resource : Ecf_Value; Scope : Ecf_Value)
      return Boolean is
      Found    : Boolean;
      Targets  : constant Value_Vector := Text_List (Resource, "targets", Found);
      Caller_Excl : constant Ecf_Value := Field (Resource, "exclude");
      Incl     : constant Ecf_Value := Field (Scope, "include");
      Excl     : constant Ecf_Value := Field (Scope, "exclude");
   begin
      if not Found or else Targets'Length = 0 then
         return False;
      end if;
      for T of Targets loop
         if Kind (T) = K_Text then
            declare
               CT : constant String := Canonicalize (Local_Peer, As_Text (T));
            begin
               if Kind (Caller_Excl) = K_Array
                 and then Covered_Frame (Local_Peer, Caller_Excl, CT)
               then
                  null;  --  caller excluded → vacuously ok
               elsif not Covered_Frame (Granter_Peer, Incl, CT) then
                  return False;
               elsif Covered_Frame (Granter_Peer, Excl, CT) then
                  return False;
               end if;
            end;
         end if;
      end loop;
      return True;
   end Check_Resource_Scope;

   --------------------
   -- Find_Signature --
   --------------------
   function Find_Signature
     (Env : Env_Pkg.Protocol_Envelope; H : Byte_Array; Found : out Boolean)
      return Materialized_Entity is
   begin
      for It of Env.Included loop
         if Type_Name (It.Ent) = "system/signature" then
            declare
               Tg_Found : Boolean;
               Tg : constant Byte_Array := Byte_Field (It.Ent, "target", Tg_Found);
            begin
               if Tg_Found and then Octets_Equal (Tg, H) then
                  Found := True;
                  return It.Ent;
               end if;
            end;
         end if;
      end loop;
      Found := False;
      return Make ("primitive/any", Empty_Map);
   end Find_Signature;

   -----------------------------
   -- Resolve_Granter_Peer_Id --
   -----------------------------
   function Resolve_Granter_Peer_Id
     (Store : access Entity_Core.Protocol.Store.Safe_Store;
      Env   : Env_Pkg.Protocol_Envelope;
      Cap   : Materialized_Entity) return String is
      Gh_Found, G_Found, Pk_Found : Boolean;
      Gh : constant Byte_Array := Byte_Field (Cap, "granter", Gh_Found);
   begin
      if not Gh_Found then
         return "";
      end if;
      declare
         G : constant Materialized_Entity := Resolve (Store, Env, Gh, G_Found);
      begin
         if not G_Found then
            return "";
         end if;
         declare
            Pk : constant Byte_Array := Byte_Field (G, "public_key", Pk_Found);
         begin
            if not Pk_Found or else Pk'Length /= 32 then
               return "";
            end if;
            return Entity_Core.Protocol.Identity.Peer_Id_Of_Public
              (Entity_Core.Crypto.Public_Bytes (Pk));
         end;
      end;
   end Resolve_Granter_Peer_Id;

   ------------------------
   -- Chain_Exceeds_Depth --
   ------------------------
   function Chain_Exceeds_Depth
     (Store : access Entity_Core.Protocol.Store.Safe_Store;
      Cap   : Materialized_Entity;
      Env   : Env_Pkg.Protocol_Envelope) return Boolean
   is
      Current : Materialized_Entity := Cap;
      Depth   : Natural := 0;
   begin
      loop
         if Depth > Max_Chain_Depth then
            return True;
         end if;
         declare
            Ph_Found, P_Found : Boolean;
            Ph : constant Byte_Array := Byte_Field (Current, "parent", Ph_Found);
         begin
            if not Ph_Found then
               return False;  --  root reached within bound
            end if;
            declare
               Parent : constant Materialized_Entity := Resolve (Store, Env, Ph, P_Found);
            begin
               if not P_Found then
                  return False;  --  unreachable — not a depth problem (stays 403)
               end if;
               Current := Parent;
               Depth   := Depth + 1;
            end;
         end;
      end loop;
   end Chain_Exceeds_Depth;

   -----------------
   -- Now_Seconds --
   -----------------
   --  Unix-epoch-ish millis are compared as Unsigned_64; we only need monotone
   --  ordering vs created_at/expires_at, so seconds-since-2000 * 1000 suffices
   --  (the cohort uses wall-clock millis; the comparison is what matters, and
   --  the smoke path carries no TTL caps so this is never gating there).
   function Now_Ms return Interfaces.Unsigned_64 is
      use Ada.Calendar;
      Epoch : constant Time := Time_Of (1970, 1, 1, 0.0);
      D : constant Duration := Clock - Epoch;
   begin
      return Interfaces.Unsigned_64 (Duration'Max (0.0, D) * 1000.0);
   exception
      when others =>
         return 0;
   end Now_Ms;

   ---------------------------------------------------------------------------
   --  §6.2 CAP-6a: unrepresentable temporal fields on INGEST.
   --
   --  True when every CAP-6a temporal field on a RECEIVED token is either absent
   --  (legal) or representable as Unsigned_64.
   --
   --  This is the reader-side half of CAP-6 and it is where a peer fails OPEN.
   --  Uint_Field reports Found => False BOTH when a field is ABSENT and when it
   --  is PRESENT but not K_Uint -- a negative integer (K_Nint) or a bignum -- so
   --  a token carrying expires_at:-1 silently skipped the expiry check and was
   --  honored with 200. §6.2 CAP-6a is explicit: such a token "is malformed. A
   --  verifier MUST refuse it and MUST NOT treat the unrepresentable field as
   --  absent." An absent expires_at stays legal and is NOT rejected here.
   --
   --  Refusal must be the §5.2 capability_denied disposition (a status-bearing
   --  response), never a decode-layer silent drop or a transport close.
   ---------------------------------------------------------------------------
   function Temporal_Fields_Representable (Tok : Materialized_Entity)
                                           return Boolean is
      D : constant Ecf_Value := Data (Tok);
      Got : Boolean;
      Result : Ecf_Value;
   begin
      for Key of Temporal_Keys loop
         Map_Get (D, Key.all, Got, Result);
         if Got and then Kind (Result) /= K_Uint then
            return False;  --  present but not a Unsigned_64 => malformed
         end if;
      end loop;
      return True;
   end Temporal_Fields_Representable;

   ---------------------------------------------------------------------------
   --  Chain collection + per-link verification (§5.5 / §5.6).
   ---------------------------------------------------------------------------

   --  Grants array of a token, or a null value.
   function Grants_Of (Token : Materialized_Entity) return Ecf_Value is
      G : constant Ecf_Value := Field (Data (Token), "grants");
   begin
      return G;
   end Grants_Of;

   --  Scope-subset on one scope dimension (child ⊆ parent), canonicalizing on
   --  the given frames.
   function Scope_Subset (Child_Peer, Parent_Peer : String; Child, Parent : Ecf_Value)
                          return Boolean is
      C_Incl : constant Ecf_Value := Field (Child, "include");
      P_Incl : constant Ecf_Value := Field (Parent, "include");
      C_Excl : constant Ecf_Value := Field (Child, "exclude");
      P_Excl : constant Ecf_Value := Field (Parent, "exclude");
   begin
      if Kind (C_Incl) = K_Array then
         for I in 1 .. Array_Length (C_Incl) loop
            declare
               CP : constant Ecf_Value := Array_Element (C_Incl, I);
               CC : constant String :=
                 (if Kind (CP) = K_Text then Canonicalize (Child_Peer, As_Text (CP)) else "");
               Any_Match : Boolean := False;
            begin
               if Kind (P_Incl) = K_Array then
                  for J in 1 .. Array_Length (P_Incl) loop
                     declare
                        PP : constant Ecf_Value := Array_Element (P_Incl, J);
                     begin
                        if Kind (PP) = K_Text
                          and then Matches_Pattern (CC, Canonicalize (Parent_Peer, As_Text (PP)))
                        then
                           Any_Match := True;
                           exit;
                        end if;
                     end;
                  end loop;
               end if;
               if not Any_Match then
                  return False;
               end if;
            end;
         end loop;
      end if;
      --  parent excludes must be reflected by child excludes
      if Kind (P_Excl) = K_Array then
         for I in 1 .. Array_Length (P_Excl) loop
            declare
               PE : constant Ecf_Value := Array_Element (P_Excl, I);
               CPE : constant String :=
                 (if Kind (PE) = K_Text then Canonicalize (Parent_Peer, As_Text (PE)) else "");
               Any_Match : Boolean := False;
            begin
               if Kind (C_Excl) = K_Array then
                  for J in 1 .. Array_Length (C_Excl) loop
                     declare
                        CE : constant Ecf_Value := Array_Element (C_Excl, J);
                     begin
                        if Kind (CE) = K_Text
                          and then Matches_Pattern (CPE, Canonicalize (Child_Peer, As_Text (CE)))
                        then
                           Any_Match := True;
                           exit;
                        end if;
                     end;
                  end loop;
               end if;
               if not Any_Match then
                  return False;
               end if;
            end;
         end loop;
      end if;
      return True;
   end Scope_Subset;

   --  Default peers-scope = {include:[local]} when a grant omits peers.
   function Peers_Or_Default (Local_Peer : String; Grant : Ecf_Value) return Ecf_Value is
      P : constant Ecf_Value := Field (Grant, "peers");
   begin
      if Kind (P) = K_Map then
         return P;
      end if;
      return Map_Of ((1 => (Key => K ("include"), Value => Text_Array1 (Local_Peer))));
   end Peers_Or_Default;

   function Grant_Subset
     (Local_Peer, Child_Peer, Parent_Peer : String; Child, Parent : Ecf_Value)
      return Boolean is
   begin
      if not Scope_Subset (Local_Peer, Local_Peer,
                           Field (Child, "handlers"), Field (Parent, "handlers"))
      then
         return False;
      end if;
      if not Scope_Subset (Local_Peer, Local_Peer,
                           Field (Child, "operations"), Field (Parent, "operations"))
      then
         return False;
      end if;
      if not Scope_Subset (Child_Peer, Parent_Peer,
                           Field (Child, "resources"), Field (Parent, "resources"))
      then
         return False;
      end if;
      return Scope_Subset (Local_Peer, Local_Peer,
                           Peers_Or_Default (Local_Peer, Child),
                           Peers_Or_Default (Local_Peer, Parent));
   end Grant_Subset;

   --  Every child grant must be a subset of SOME parent grant.
   function Is_Attenuated
     (Local_Peer, Child_Peer, Parent_Peer : String; Child, Parent : Materialized_Entity)
      return Boolean is
      Cg : constant Ecf_Value := Grants_Of (Child);
      Pg : constant Ecf_Value := Grants_Of (Parent);
   begin
      if Kind (Cg) = K_Array then
         for I in 1 .. Array_Length (Cg) loop
            declare
               C : constant Ecf_Value := Array_Element (Cg, I);
               Any_Match : Boolean := False;
            begin
               if Kind (Pg) = K_Array then
                  for J in 1 .. Array_Length (Pg) loop
                     if Grant_Subset (Local_Peer, Child_Peer, Parent_Peer,
                                      C, Array_Element (Pg, J))
                     then
                        Any_Match := True;
                        exit;
                     end if;
                  end loop;
               end if;
               if not Any_Match then
                  return False;
               end if;
            end;
         end loop;
      end if;
      --  TTL attenuation (§5.6): a child must not outlive a finite parent.
      declare
         Pe_Found, Ce_Found : Boolean;
         Pe : constant Interfaces.Unsigned_64 :=
           Uint_Field (Data (Parent), "expires_at", Pe_Found);
         Ce : constant Interfaces.Unsigned_64 :=
           Uint_Field (Data (Child), "expires_at", Ce_Found);
         use type Interfaces.Unsigned_64;
      begin
         if Pe_Found and then not Ce_Found then
            return False;       --  child infinite, parent finite
         end if;
         if Pe_Found then
            return Ce <= Pe;
         end if;
      end;
      return True;
   end Is_Attenuated;

   --  §6.2 mint-bound: every Requested grant ⊆ SOME Authorized grant. Same
   --  frame on both sides (Local_Peer) — the caller presents its own cap.
   function Grants_Are_Subset
     (Local_Peer : String; Requested, Authorized : Ecf_Value) return Boolean is
   begin
      if Kind (Requested) /= K_Array then
         return True;   --  nothing requested → vacuously attenuated
      end if;
      for I in 1 .. Array_Length (Requested) loop
         declare
            C : constant Ecf_Value := Array_Element (Requested, I);
            Any_Match : Boolean := False;
         begin
            if Kind (Authorized) = K_Array then
               for J in 1 .. Array_Length (Authorized) loop
                  if Grant_Subset (Local_Peer, Local_Peer, Local_Peer,
                                   C, Array_Element (Authorized, J))
                  then
                     Any_Match := True;
                     exit;
                  end if;
               end loop;
            end if;
            if not Any_Match then
               return False;
            end if;
         end;
      end loop;
      return True;
   end Grants_Are_Subset;

   --  Per-link granter frame (§PR-8): the link's resource patterns canonicalize
   --  on its granter's peer_id. Multi-sig root (no granter) → Local_Peer.
   --  Unresolvable → "" (caller denies).
   function Link_Granter_Peer
     (Store : access Entity_Core.Protocol.Store.Safe_Store;
      Env   : Env_Pkg.Protocol_Envelope;
      Local_Peer : String; Cap : Materialized_Entity) return String is
      Gh_Found : Boolean;
   begin
      --  Multi-sig root (no granter pointer) canonicalizes on the local frame;
      --  a single-granter link derives its frame from the granter's peer_id.
      declare
         Ignore : constant Byte_Array := Byte_Field (Cap, "granter", Gh_Found);
         pragma Unreferenced (Ignore);
      begin
         if not Gh_Found then
            return Local_Peer;
         end if;
      end;
      return Resolve_Granter_Peer_Id (Store, Env, Cap);
   end Link_Granter_Peer;

   ----------------------------
   -- §3.6 / §5.5 multi-signature root (K-of-N quorum, root-only) --
   ------------------------------------------------------------------
   --  A multi-sig cap carries `granter` as a MAP {signers, threshold} instead of
   --  a single granter hash — the root is authorized by a quorum. §3.6 M3
   --  (structure): root-only, 2 <= threshold <= N, N >= 2, distinct signers.
   --  §5.5 M6: the local peer is one of the signers. §5.5 M4: at least `threshold`
   --  DISTINCT signers each carry a valid signature over the root content hash.

   function Is_Multisig (Cap : Materialized_Entity) return Boolean is
   begin
      return Kind (Field (Data (Cap), "granter")) = K_Map;
   end Is_Multisig;

   function Find_Signature_By
     (Env : Env_Pkg.Protocol_Envelope; Target, Signer : Byte_Array;
      Found : out Boolean) return Materialized_Entity is
   begin
      for It of Env.Included loop
         if Type_Name (It.Ent) = "system/signature" then
            declare
               Tf, Sf : Boolean;
               Tg : constant Byte_Array := Byte_Field (It.Ent, "target", Tf);
               Sg : constant Byte_Array := Byte_Field (It.Ent, "signer", Sf);
            begin
               if Tf and then Sf and then Octets_Equal (Tg, Target)
                 and then Octets_Equal (Sg, Signer)
               then
                  Found := True;
                  return It.Ent;
               end if;
            end;
         end if;
      end loop;
      Found := False;
      return Make ("primitive/any", Empty_Map);
   end Find_Signature_By;

   function Multisig_Root_Ok
     (Local_Peer : String;
      Store      : access Entity_Core.Protocol.Store.Safe_Store;
      Env        : Env_Pkg.Protocol_Envelope;
      Root       : Materialized_Entity) return Boolean
   is
      use type Interfaces.Unsigned_64;
      Granter : constant Ecf_Value := Field (Data (Root), "granter");
   begin
      if Kind (Granter) /= K_Map then
         return False;
      end if;
      declare
         Signers   : constant Ecf_Value := Field (Granter, "signers");
         Thr_V     : constant Ecf_Value := Field (Granter, "threshold");
         Parent_Found : Boolean;
         Par : constant Byte_Array := Byte_Field (Root, "parent", Parent_Found);
         pragma Unreferenced (Par);
      begin
         if Kind (Signers) /= K_Array or else Kind (Thr_V) /= K_Uint then
            return False;
         end if;
         declare
            Threshold : constant Interfaces.Unsigned_64 := As_Uint (Thr_V);
            N         : constant Natural := Array_Length (Signers);
         begin
            --  M3: root-only, quorum shape, distinct 33-byte signers.
            if Parent_Found then
               return False;  --  multi-sig is root-only
            end if;
            if N < 2 or else Threshold < 2
              or else Interfaces.Unsigned_64 (N) < Threshold
            then
               return False;
            end if;
            for I in 1 .. N loop
               if Kind (Array_Element (Signers, I)) /= K_Bytes then
                  return False;
               end if;
               declare
                  Si : constant Byte_Array := As_Bytes (Array_Element (Signers, I));
               begin
                  if Si'Length /= 33 then
                     return False;
                  end if;
                  for J in I + 1 .. N loop
                     if Kind (Array_Element (Signers, J)) = K_Bytes
                       and then Octets_Equal (Si, As_Bytes (Array_Element (Signers, J)))
                     then
                        return False;  --  duplicate signer
                     end if;
                  end loop;
               end;
            end loop;

            --  M6: the local peer MUST be a quorum member.
            declare
               Local_In : Boolean := False;
            begin
               for I in 1 .. N loop
                  declare
                     Sf : Boolean;
                     S  : constant Materialized_Entity :=
                       Resolve (Store, Env, As_Bytes (Array_Element (Signers, I)), Sf);
                  begin
                     if Sf then
                        declare
                           Pkf : Boolean;
                           Pk  : constant Byte_Array := Byte_Field (S, "public_key", Pkf);
                        begin
                           if Pkf and then Pk'Length = 32
                             and then Entity_Core.Protocol.Identity.Peer_Id_Of_Public
                                        (Entity_Core.Crypto.Public_Bytes (Pk)) = Local_Peer
                           then
                              Local_In := True;
                           end if;
                        end;
                     end if;
                  end;
                  exit when Local_In;
               end loop;
               if not Local_In then
                  return False;
               end if;
            end;

            --  M4: count DISTINCT signers with a valid signature over the root hash.
            declare
               Valid     : Natural := 0;
               Root_Hash : constant Byte_Array := Hash (Root);
            begin
               for I in 1 .. N loop
                  declare
                     Sf, Sgn_Found : Boolean;
                     Sh  : constant Byte_Array := As_Bytes (Array_Element (Signers, I));
                     S   : constant Materialized_Entity := Resolve (Store, Env, Sh, Sf);
                     Sgn : constant Materialized_Entity :=
                       Find_Signature_By (Env, Root_Hash, Sh, Sgn_Found);
                  begin
                     if Sf and then Sgn_Found
                       and then Entity_Core.Protocol.Identity.Verify_Signature (Sgn, S)
                     then
                        Valid := Valid + 1;
                     end if;
                  end;
               end loop;
               return Interfaces.Unsigned_64 (Valid) >= Threshold;
            end;
         end;
      end;
   end Multisig_Root_Ok;

   ----------------------------
   -- Verify_Capability_Chain --
   ----------------------------
   function Verify_Capability_Chain
     (Local_Peer : String;
      Store      : access Entity_Core.Protocol.Store.Safe_Store;
      Cap        : Materialized_Entity;
      Env        : Env_Pkg.Protocol_Envelope) return Verdict
   is
      --  Collect the chain (cap .. root) up to the depth bound.
      type Chain_Array is array (1 .. Max_Chain_Depth + 1) of Materialized_Entity;
      Chain : Chain_Array;
      N     : Natural := 0;
      Current : Materialized_Entity := Cap;
      Good  : Boolean := True;
   begin
      loop
         exit when N >= Chain'Last;
         N := N + 1;
         Chain (N) := Current;
         declare
            Ph_Found, P_Found : Boolean;
            Ph : constant Byte_Array := Byte_Field (Current, "parent", Ph_Found);
         begin
            exit when not Ph_Found;
            declare
               Parent : constant Materialized_Entity := Resolve (Store, Env, Ph, P_Found);
            begin
               if not P_Found then
                  return Deny;     --  unreachable parent → 403
               end if;
               Current := Parent;
            end;
         end;
      end loop;

      --  Root must be self-issued by Local_Peer (single-sig), or pass the §3.6
      --  K-of-N quorum (multi-sig root: granter is a {signers, threshold} map).
      declare
         Root : constant Materialized_Entity := Chain (N);
      begin
         if Is_Multisig (Root) then
            if not Multisig_Root_Ok (Local_Peer, Store, Env, Root) then
               return Deny;
            end if;
         else
            declare
               Rg_Found, G_Found, Pk_Found : Boolean;
               Rgh : constant Byte_Array := Byte_Field (Root, "granter", Rg_Found);
               Root_Ok : Boolean := False;
            begin
               if Rg_Found then
                  declare
                     G : constant Materialized_Entity := Resolve (Store, Env, Rgh, G_Found);
                  begin
                     if G_Found then
                        declare
                           Pk : constant Byte_Array := Byte_Field (G, "public_key", Pk_Found);
                        begin
                           Root_Ok := Pk_Found and then Pk'Length = 32
                             and then Entity_Core.Protocol.Identity.Peer_Id_Of_Public
                                        (Entity_Core.Crypto.Public_Bytes (Pk)) = Local_Peer;
                        end;
                     end if;
                  end;
               end if;
               if not Root_Ok then
                  return Deny;
               end if;
            end;
         end if;
      end;

      --  Per-link checks.
      for I in 1 .. N loop
         exit when not Good;
         declare
            Cur : constant Materialized_Entity := Chain (I);
            Gh_Found, Sgn_Found, Granter_Found : Boolean;
            Gh : constant Byte_Array := Byte_Field (Cur, "granter", Gh_Found);
         begin
            --  signature: signer == granter, verify against granter identity
            if Gh_Found then
               declare
                  Sgn : constant Materialized_Entity :=
                    Find_Signature (Env, Hash (Cur), Sgn_Found);
                  Granter : constant Materialized_Entity :=
                    Resolve (Store, Env, Gh, Granter_Found);
               begin
                  if Sgn_Found and then Granter_Found then
                     declare
                        Sf : Boolean;
                        Signer : constant Byte_Array := Byte_Field (Sgn, "signer", Sf);
                     begin
                        if not (Sf and then Octets_Equal (Signer, Gh)
                                and then Entity_Core.Protocol.Identity.Verify_Signature
                                           (Sgn, Granter))
                        then
                           Good := False;
                        end if;
                     end;
                  else
                     Good := False;
                  end if;
               end;
            elsif not Is_Multisig (Cur) then
               --  A §3.6 multi-sig root has no single granter — it is authorized
               --  by the quorum verified above (root-only); grantee + temporal
               --  checks below still apply.
               Good := False;
            end if;

            --  grantee resolution → 401 carve-out
            declare
               Ge_Found, Gr_Found : Boolean;
               Geh : constant Byte_Array := Byte_Field (Cur, "grantee", Ge_Found);
            begin
               if Ge_Found then
                  declare
                     Dummy : Materialized_Entity := Resolve (Store, Env, Geh, Gr_Found);
                     pragma Unreferenced (Dummy);
                  begin
                     if not Gr_Found then
                        raise Entity_Core.Errors.Unresolvable_Grantee;
                     end if;
                  end;
               else
                  raise Entity_Core.Errors.Unresolvable_Grantee;
               end if;
            end;

            --  temporal validity
            declare
               use type Interfaces.Unsigned_64;
               Nb_Found, Ex_Found : Boolean;
               T_Now : constant Interfaces.Unsigned_64 := Now_Ms;
               Nb : constant Interfaces.Unsigned_64 :=
                 Uint_Field (Data (Cur), "not_before", Nb_Found);
               Ex : constant Interfaces.Unsigned_64 :=
                 Uint_Field (Data (Cur), "expires_at", Ex_Found);
            begin
               --  CAP-6a FIRST: a present-but-unrepresentable expires_at /
               --  not_before / created_at is MALFORMED and must be refused
               --  outright. This has to run BEFORE the two range checks below,
               --  because those use Uint_Field, which cannot tell "absent" from
               --  "present but not K_Uint" -- so on its own it would skip the
               --  check and honor the token (fail-open).
               if not Temporal_Fields_Representable (Cur) then
                  Good := False;
               end if;
               if Nb_Found and then T_Now < Nb then
                  Good := False;
               end if;
               if Ex_Found and then Ex < T_Now then
                  Good := False;
               end if;
            end;

            --  delegation link (attenuation)
            if I < N then
               declare
                  Parent : constant Materialized_Entity := Chain (I + 1);
                  Child_Peer  : constant String := Link_Granter_Peer (Store, Env, Local_Peer, Cur);
                  Parent_Peer : constant String := Link_Granter_Peer (Store, Env, Local_Peer, Parent);
                  Pg_Found, Cg_Found : Boolean;
                  Pg : constant Byte_Array := Byte_Field (Parent, "grantee", Pg_Found);
                  Cg : constant Byte_Array := Byte_Field (Cur, "granter", Cg_Found);
               begin
                  if Child_Peer = "" or else Parent_Peer = "" then
                     Good := False;
                  elsif not (Pg_Found and then Cg_Found and then Octets_Equal (Pg, Cg)
                             and then Is_Attenuated (Local_Peer, Child_Peer, Parent_Peer,
                                                     Cur, Parent))
                  then
                     Good := False;
                  end if;
               end;
            end if;
         end;
      end loop;

      return (if Good then Allow else Deny);
   end Verify_Capability_Chain;

   ---------------
   -- Is_Revoked --
   ---------------
   function Is_Revoked
     (Local_Peer : String;
      Store      : access Entity_Core.Protocol.Store.Safe_Store;
      Cap        : Materialized_Entity) return Boolean is
      F1 : Boolean;
      M  : Materialized_Entity;
      pragma Unreferenced (M);
   begin
      if Store = null then
         return False;
      end if;
      M := Store.Get_At
        ("/" & Local_Peer & "/system/capability/revocations/" & Hex (Hash (Cap)), F1);
      return F1;
   end Is_Revoked;

   ----------------------
   -- Check_Permission --
   ----------------------
   function Check_Permission
     (Local_Peer      : String;
      Granter_Peer    : String;
      Exec            : Materialized_Entity;
      Token           : Materialized_Entity;
      Handler_Pattern : String) return Verdict
   is
      Operation : constant String := Text (Exec, "operation");
      Uri       : constant String := Text (Exec, "uri");
      Target_Peer : constant String := Extract_Peer (Local_Peer, Uri);
      Resource  : constant Ecf_Value := Field (Data (Exec), "resource");
      Grants    : constant Ecf_Value := Grants_Of (Token);
   begin
      if Kind (Grants) /= K_Array then
         return Deny;
      end if;
      for I in 1 .. Array_Length (Grants) loop
         declare
            G  : constant Ecf_Value := Array_Element (Grants, I);
            Ok : Boolean :=
              Matches_Scope (Local_Peer, Operation, Field (G, "operations"), Id_Scope)
              and then Matches_Scope (Local_Peer, Handler_Pattern, Field (G, "handlers"), Path_Scope);
         begin
            if Ok then
               Ok := Matches_Scope (Local_Peer, Target_Peer,
                                    Peers_Or_Default (Local_Peer, G),
                                    Id_Scope);
            end if;
            if Ok and then Kind (Resource) = K_Map then
               Ok := Check_Resource_Scope (Local_Peer, Granter_Peer, Resource,
                                           Field (G, "resources"));
            end if;
            if Ok then
               return Allow;
            end if;
         end;
      end loop;
      return Deny;
   end Check_Permission;

   --------------------
   -- Verify_Request --
   --------------------
   function Verify_Request
     (Local_Peer : String;
      Store      : access Entity_Core.Protocol.Store.Safe_Store;
      Env        : Env_Pkg.Protocol_Envelope) return Request_Verdict
   is
      Exec : constant Materialized_Entity := Env.Root;
      Sgn_Found : Boolean;
      Sgn : constant Materialized_Entity := Find_Signature (Env, Hash (Exec), Sgn_Found);
   begin
      if not Sgn_Found then
         return Authn_Fail;
      end if;
      declare
         Signer_Found, Author_H_Found : Boolean;
         Signer   : constant Byte_Array := Byte_Field (Sgn, "signer", Signer_Found);
         Author_H : constant Byte_Array := Byte_Field (Exec, "author", Author_H_Found);
      begin
         if not (Signer_Found and then Author_H_Found
                 and then Octets_Equal (Signer, Author_H))
         then
            return Authn_Fail;
         end if;
         declare
            Author_Found : Boolean;
            Author : constant Materialized_Entity :=
              Env_Pkg.Included_Get (Env, Author_H, Author_Found);
         begin
            if not Author_Found then
               return Authn_Fail;
            end if;
            if not Entity_Core.Protocol.Identity.Verify_Signature (Sgn, Author) then
               return Authn_Fail;
            end if;
         end;

         --  capability
         declare
            Ch_Found, Cap_Found : Boolean;
            Ch : constant Byte_Array := Byte_Field (Exec, "capability", Ch_Found);
         begin
            if not Ch_Found then
               return Authz_Deny;
            end if;
            declare
               Cap : constant Materialized_Entity :=
                 Env_Pkg.Included_Get (Env, Ch, Cap_Found);
            begin
               if not Cap_Found then
                  return Authz_Deny;
               end if;
               --  §4.10 chain-depth PRE-CHECK (structural) — BEFORE the authz walk.
               if Chain_Exceeds_Depth (Store, Cap, Env) then
                  return Chain_Too_Deep;
               end if;
               if Verify_Capability_Chain (Local_Peer, Store, Cap, Env) = Deny then
                  return Authz_Deny;
               end if;
               declare
                  Ge_Found : Boolean;
                  Grantee : constant Byte_Array := Byte_Field (Cap, "grantee", Ge_Found);
               begin
                  if not (Ge_Found and then Octets_Equal (Grantee, Author_H)) then
                     return Authz_Deny;
                  end if;
               end;
               if Is_Revoked (Local_Peer, Store, Cap) then
                  return Authz_Deny;
               end if;
               return Allow;
            end;
         end;
      end;
   end Verify_Request;

end Entity_Core.Protocol.Capability;
