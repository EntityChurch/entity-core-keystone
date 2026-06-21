with Ada.Calendar;
with Ada.Text_IO;
with Ada.Exceptions;
with Ada.Environment_Variables;
with Interfaces;
with Entity_Core.Codec.Value;
with Entity_Core.Codec.Peer_Id;
with Entity_Core.Protocol.Entity;
with Entity_Core.Protocol.Cbor_Util;
with Entity_Core.Protocol.Wire;
with Entity_Core.Protocol.Capability;
with Entity_Core.Protocol.Type_Registry;
with Entity_Core.Errors;

package body Entity_Core.Protocol.Handlers is

   use Entity_Core.Codec.Value;
   use Entity_Core.Protocol.Entity;
   use Entity_Core.Protocol.Cbor_Util;
   package Env_Pkg renames Entity_Core.Protocol.Envelope;
   package Cap renames Entity_Core.Protocol.Capability;
   package Id_Pkg renames Entity_Core.Protocol.Identity;
   package Wire renames Entity_Core.Protocol.Wire;

   use type Interfaces.Unsigned_64;
   use type Interfaces.Unsigned_8;
   use type Cap.Verdict;

   Debug_Dispatch : constant Boolean :=
     Ada.Environment_Variables.Exists ("ADA_DBG_DISPATCH");

   --  Process-global monotonic counter mixed into each issued handshake nonce
   --  (F12 per-connection uniqueness). A protected object → race-free across
   --  the per-connection reader tasks.
   protected Nonce_Counter is
      procedure Next (V : out Interfaces.Unsigned_64);
   private
      Seq : Interfaces.Unsigned_64 := 0;
   end Nonce_Counter;

   protected body Nonce_Counter is
      procedure Next (V : out Interfaces.Unsigned_64) is
      begin
         Seq := Seq + 1;
         V := Seq;
      end Next;
   end Nonce_Counter;

   function Next_Nonce_Seq return Interfaces.Unsigned_64 is
      V : Interfaces.Unsigned_64;
   begin
      Nonce_Counter.Next (V);
      return V * 2654435761;   --  spread the low bits across the word
   end Next_Nonce_Seq;

   --  Handler-interface operation lists (§6.2 N3).
   type Str_Acc is access constant String;
   type Op_List is array (Positive range <>) of Str_Acc;
   No_Ops : constant Op_List (1 .. 0) := (others => null);

   Op_Hello        : aliased constant String := "hello";
   Op_Authenticate : aliased constant String := "authenticate";
   Op_Get          : aliased constant String := "get";
   Op_Put          : aliased constant String := "put";
   Op_Request      : aliased constant String := "request";
   Op_Delegate     : aliased constant String := "delegate";
   Op_Revoke       : aliased constant String := "revoke";
   Op_Configure    : aliased constant String := "configure";
   Op_Register     : aliased constant String := "register";
   Op_Unregister   : aliased constant String := "unregister";

   Connect_Ops : constant Op_List :=
     (Op_Hello'Access, Op_Authenticate'Access);
   Tree_Ops    : constant Op_List := (Op_Get'Access, Op_Put'Access);
   Cap_Ops     : constant Op_List :=
     (Op_Request'Access, Op_Delegate'Access, Op_Revoke'Access,
      Op_Configure'Access);
   Handler_Ops : constant Op_List :=
     (Op_Register'Access, Op_Unregister'Access, Op_Get'Access);
   use type Entity_Core.Protocol.Store.String_Ptr;

   ---------------------------------------------------------------------------
   --  Outcome — a handler result: a status, a result entity, and optionally
   --  included entities to carry on the response (§4.4 cap grant etc.).
   ---------------------------------------------------------------------------
   type Outcome is record
      Status   : Interfaces.Unsigned_64 := 200;
      Result   : Materialized_Entity;
      Env      : Env_Pkg.Protocol_Envelope;     --  included carriers (root unused)
      Has_Inc  : Boolean := False;
   end record;

   function Ok (Result : Materialized_Entity) return Outcome is
   begin
      return O : Outcome do
         O.Status := 200;
         O.Result := Result;
      end return;
   end Ok;

   function Ok_Inc (Result : Materialized_Entity; Inc : Env_Pkg.Protocol_Envelope)
                    return Outcome is
   begin
      return O : Outcome do
         O.Status := 200;
         O.Result := Result;
         O.Env := Inc;
         O.Has_Inc := True;
      end return;
   end Ok_Inc;

   function Err (Status : Interfaces.Unsigned_64; Code : String; Message : String := "")
                 return Outcome is
   begin
      return O : Outcome do
         O.Status := Status;
         O.Result := Wire.Error_Result (Code, Message);
      end return;
   end Err;

   ---------------------------------------------------------------------------
   --  Small helpers.
   ---------------------------------------------------------------------------
   function Now_Ms return Interfaces.Unsigned_64 is
      use Ada.Calendar;
      Epoch : constant Time := Time_Of (1970, 1, 1, 0.0);
      D : constant Duration := Clock - Epoch;
   begin
      return Interfaces.Unsigned_64 (Duration'Max (0.0, D) * 1000.0);
   exception
      when others => return 0;
   end Now_Ms;

   --  The params of an EXECUTE is the wire form of an ENTITY ({type, data,
   --  content_hash}), not a bare data map (Go `Params: ecf.Encode(authEntity)`).
   --  Materialize it so its data fields + content_hash (the §3.5 PoP signature
   --  target) are reachable. Found is False if params is absent / not an entity.
   function Params_Entity (Exec : Materialized_Entity; Found : out Boolean)
                           return Materialized_Entity is
      P : constant Ecf_Value := Field (Data (Exec), "params", Found);
   begin
      if Found and then Kind (P) = K_Map and then Has (P, "type") then
         begin
            return Of_Cbor (P);
         exception
            when others =>
               Found := False;
               return Make ("primitive/any", Empty_Map);
         end;
      end if;
      Found := False;
      return Make ("primitive/any", Empty_Map);
   end Params_Entity;

   --  Single resource target (first of resource.targets), or "" if absent.
   function Exec_Resource_Target (Exec : Materialized_Entity) return String is
      R : constant Ecf_Value := Field (Data (Exec), "resource");
      Found : Boolean;
   begin
      if Kind (R) /= K_Map then
         return "";
      end if;
      declare
         Targets : constant Value_Vector := Text_List (R, "targets", Found);
      begin
         if Found and then Targets'Length >= 1
           and then Kind (Targets (1)) = K_Text
         then
            return As_Text (Targets (1));
         end if;
         return "";
      end;
   end Exec_Resource_Target;

   ---------------------------------------------------------------------------
   --  Grant / scope builders (§4.4 / §5.4).
   ---------------------------------------------------------------------------

   function S1 (A : String) return Ecf_Value is (Text_Array1 (A));

   function S2 (A, B : String) return Ecf_Value is
      V : constant Value_Vector (1 .. 2) := (Make_Text (A), Make_Text (B));
   begin
      return Make_Array (V);
   end S2;

   function S0 return Ecf_Value is
      V : Value_Vector (1 .. 0);
   begin
      return Make_Array (V);
   end S0;

   --  A grant cbor-map. Peers null → omit (defaults to local at check time).
   function Grant (Handlers, Resources, Operations : Ecf_Value;
                   With_Peers : Boolean := False; Peers : Ecf_Value := Make_Null)
                   return Ecf_Value is
   begin
      if With_Peers then
         return Map_Of (((Key => K ("handlers"),
                          Value => Map_Of ((1 => (Key => K ("include"), Value => Handlers)))),
                         (Key => K ("resources"),
                          Value => Map_Of ((1 => (Key => K ("include"), Value => Resources)))),
                         (Key => K ("operations"),
                          Value => Map_Of ((1 => (Key => K ("include"), Value => Operations)))),
                         (Key => K ("peers"),
                          Value => Map_Of ((1 => (Key => K ("include"), Value => Peers))))));
      end if;
      return Map_Of (((Key => K ("handlers"),
                       Value => Map_Of ((1 => (Key => K ("include"), Value => Handlers)))),
                      (Key => K ("resources"),
                       Value => Map_Of ((1 => (Key => K ("include"), Value => Resources)))),
                      (Key => K ("operations"),
                       Value => Map_Of ((1 => (Key => K ("include"), Value => Operations))))));
   end Grant;

   --  The §4.4 discovery floor: every authenticated identity gets at least this.
   function Discovery_Floor return Ecf_Value is
      G1 : constant Ecf_Value :=
        Grant (S1 ("system/tree"),
               S2 ("system/type/*", "system/handler/*"), S1 ("get"));
      G2 : constant Ecf_Value :=
        Grant (S1 ("system/capability"), S0, S1 ("request"));
      V : constant Value_Vector (1 .. 2) := (G1, G2);
   begin
      return Make_Array (V);
   end Discovery_Floor;

   --  Wide-open admin scope — the degenerate [default → *] (--debug-open-grants).
   function Open_Grants_Scope return Ecf_Value is
      G : constant Ecf_Value :=
        Grant (S1 ("*"), S2 ("*", "/*/*"), S1 ("*"), With_Peers => True, Peers => S1 ("*"));
      V : constant Value_Vector (1 .. 1) := (1 => G);
   begin
      return Make_Array (V);
   end Open_Grants_Scope;

   --  Full owner authority over /{peer}/* (§6.9a).
   function Owner_Grants (Peer : Peer_Access) return Ecf_Value is
      G : constant Ecf_Value :=
        Grant (S1 ("*"), S1 ("*"), S1 ("*"), With_Peers => True, Peers => S1 (Local_Peer (Peer)));
      V : constant Value_Vector (1 .. 1) := (1 => G);
   begin
      return Make_Array (V);
   end Owner_Grants;

   ---------------------------------------------------------------------------
   --  Token mint (§4.4 / §6.9a). Returns the token entity + its signature.
   ---------------------------------------------------------------------------
   procedure Mint_Token
     (Peer        : Peer_Access;
      Grantee_Hash : Byte_Array;
      Grants      : Ecf_Value;     --  the grants ARRAY
      Parent      : Byte_Array;    --  empty => omit
      Token       : out Materialized_Entity;
      Signature   : out Materialized_Entity)
   is
      Has_Parent : constant Boolean := Parent'Length > 0;
      Base : constant Cbor_Util.Kv_List :=
        ((Key => K ("granter"),    Value => Make_Bytes (Id_Pkg.Identity_Hash (Peer.Id))),
         (Key => K ("grantee"),    Value => Make_Bytes (Grantee_Hash)),
         (Key => K ("grants"),     Value => Grants),
         (Key => K ("created_at"), Value => Make_Uint (Now_Ms)));
      All_Kv : Cbor_Util.Kv_List (1 .. Base'Length + (if Has_Parent then 1 else 0));
   begin
      All_Kv (1 .. Base'Length) := Base;
      if Has_Parent then
         All_Kv (All_Kv'Last) := (Key => K ("parent"), Value => Make_Bytes (Parent));
      end if;
      Token := Make ("system/capability/token", Map_Of (All_Kv));
      Signature := Id_Pkg.Sign (Peer.Id, Token);
   end Mint_Token;

   --  Build the included carrier for a minted cap (token + granter peer + sig).
   function Cap_Included
     (Peer : Peer_Access; Token, Signature : Materialized_Entity)
      return Env_Pkg.Protocol_Envelope is
      E : Env_Pkg.Protocol_Envelope;
   begin
      Env_Pkg.Add (E, Token);
      Env_Pkg.Add (E, Id_Pkg.Peer_Entity (Peer.Id));
      Env_Pkg.Add (E, Signature);
      return E;
   end Cap_Included;

   ---------------------------------------------------------------------------
   --  §6.9a authenticate-time seed-grant derivation (dual-form lookup → floor).
   ---------------------------------------------------------------------------
   function Derive_Seed_Grants
     (Peer : Peer_Access; Remote_Peer : Materialized_Entity; Remote_Pid : String)
      return Ecf_Value is
      Base : constant String := "/" & Local_Peer (Peer) & "/system/capability/policy/";
      Found : Boolean;
      Entry_E : Materialized_Entity :=
        Peer.St.Get_At (Base & Hex (Hash (Remote_Peer)), Found);
   begin
      if not Found then
         Entry_E := Peer.St.Get_At (Base & Remote_Pid, Found);
      end if;
      if not Found then
         Entry_E := Peer.St.Get_At (Base & "default", Found);
      end if;
      if not Found then
         return Discovery_Floor;
      end if;
      --  The matched policy entry's grants UNION the discovery floor. For a
      --  token-shaped entry verify its signature first; a policy-entry carries
      --  grants directly.
      declare
         Policy_Grants : Ecf_Value := Make_Null;
      begin
         if Type_Name (Entry_E) = "system/capability/token" then
            declare
               Sig_Found : Boolean;
               Sgn : constant Materialized_Entity :=
                 Peer.St.Get_At
                   ("/" & Local_Peer (Peer) & "/system/signature/" & Hex (Hash (Entry_E)),
                    Sig_Found);
            begin
               if Sig_Found
                 and then Id_Pkg.Verify_Signature (Sgn, Id_Pkg.Peer_Entity (Peer.Id))
               then
                  Policy_Grants := Field (Data (Entry_E), "grants");
               end if;
            end;
         elsif Type_Name (Entry_E) = "system/capability/policy-entry" then
            Policy_Grants := Field (Data (Entry_E), "grants");
         end if;

         if Kind (Policy_Grants) /= K_Array or else Array_Length (Policy_Grants) = 0 then
            return Discovery_Floor;
         end if;
         --  Concatenate floor ++ policy.
         declare
            Floor : constant Ecf_Value := Discovery_Floor;
            Total : constant Natural := Array_Length (Floor) + Array_Length (Policy_Grants);
            V     : Value_Vector (1 .. Total);
            Idx   : Positive := 1;
         begin
            for I in 1 .. Array_Length (Floor) loop
               V (Idx) := Array_Element (Floor, I);
               Idx := Idx + 1;
            end loop;
            for I in 1 .. Array_Length (Policy_Grants) loop
               V (Idx) := Array_Element (Policy_Grants, I);
               Idx := Idx + 1;
            end loop;
            return Make_Array (V);
         end;
      end;
   end Derive_Seed_Grants;

   ---------------------------------------------------------------------------
   --  §4.1/§4.6 — the connect handler (hello / authenticate).
   ---------------------------------------------------------------------------
   function Handle_Hello
     (Peer : Peer_Access; Conn : in out Conn_State; Exec : Materialized_Entity)
      return Outcome is
      P_Found : Boolean;
      Params  : constant Materialized_Entity := Params_Entity (Exec, P_Found);
      Initiator : constant String := Text (Params, "peer_id");
      Nonce : Byte_Array (1 .. Nonce_Length);
   begin
      if Conn.Established then
         return Err (409, "connection_already_established");
      end if;
      --  §4.7 AGILITY-UNKNOWN-1: a peer_id carrying an unsupported key_type
      --  (only ed25519 = 16#01# is supported) MUST be rejected at handshake
      --  with 400 unsupported_key_type — earliest natural surface is hello.
      if Initiator'Length > 0 then
         declare
            C : constant Entity_Core.Codec.Peer_Id.Components :=
              Entity_Core.Codec.Peer_Id.Parse (Initiator);
         begin
            if C.Key_Type /= 1 then
               return Err (400, "unsupported_key_type");
            end if;
         exception
            when others => null;   --  unparseable peer_id → let authenticate gate it
         end;
      end if;
      --  §4.5 NEGOTIATE-FORMAT-1 / NEGOTIATE-KEYTYPE-1: an advertised set that
      --  is non-empty and DISJOINT from our floor MUST be rejected (the floor
      --  is ecfv1-sha256 / ed25519). An absent/empty set passes through.
      declare
         HF : constant Ecf_Value := Field (Data (Params), "hash_formats");
         KT : constant Ecf_Value := Field (Data (Params), "key_types");
         function List_Has (V : Ecf_Value; S : String) return Boolean is
         begin
            if Kind (V) /= K_Array then
               return True;   --  absent/empty → no constraint
            end if;
            if Array_Length (V) = 0 then
               return True;
            end if;
            for I in 1 .. Array_Length (V) loop
               declare
                  E : constant Ecf_Value := Array_Element (V, I);
               begin
                  if Kind (E) = K_Text and then As_Text (E) = S then
                     return True;
                  end if;
               end;
            end loop;
            return False;
         end List_Has;
      begin
         if not List_Has (HF, "ecfv1-sha256") then
            return Err (400, "incompatible_hash_format");
         end if;
         if not List_Has (KT, "ed25519") then
            return Err (400, "unsupported_key_type");
         end if;
      end;
      --  Issue a per-connection nonce (§4.6 SHOULD ≥32-byte). F12 replay
      --  protection REQUIRES it be unique per connection: a clock-only seed
      --  collides across near-simultaneous connections (two hellos in the same
      --  millisecond → identical nonce → a captured authenticate replays). Mix
      --  the clock with a process-global monotonic counter so no two issued
      --  nonces ever coincide.
      declare
         T : Interfaces.Unsigned_64 := Now_Ms xor Next_Nonce_Seq;
      begin
         for I in Nonce'Range loop
            T := T * 6364136223846793005 + 1442695040888963407;
            Nonce (I) := Octet (Interfaces.Shift_Right (T, 56) and 16#FF#);
         end loop;
      end;
      Conn.Issued_Nonce := Nonce;
      Conn.Has_Nonce := True;
      if Initiator'Length <= Max_Pid then
         Conn.Hello_Pid (1 .. Initiator'Length) := Initiator;
         Conn.Hello_Pid_Len := Initiator'Length;
      end if;
      return Ok (Make ("system/protocol/connect/hello",
        Map_Of (((Key => K ("peer_id"),      Value => Make_Text (Local_Peer (Peer))),
                 (Key => K ("nonce"),        Value => Make_Bytes (Nonce)),
                 (Key => K ("protocols"),    Value => Text_Array1 ("entity-core/1.0")),
                 (Key => K ("timestamp"),    Value => Make_Uint (Now_Ms)),
                 (Key => K ("hash_formats"), Value => Text_Array1 ("ecfv1-sha256")),
                 (Key => K ("key_types"),    Value => Text_Array1 ("ed25519"))))));
   end Handle_Hello;

   function Handle_Authenticate
     (Peer : Peer_Access; Conn : in out Conn_State;
      Exec : Materialized_Entity; Env : Env_Pkg.Protocol_Envelope) return Outcome is
      Auth_Found : Boolean;
      --  params is the wire form of the authenticate ENTITY; materialize it so
      --  its data fields + content_hash (the PoP signature target) are reachable.
      Auth_Entity : constant Materialized_Entity := Params_Entity (Exec, Auth_Found);
   begin
      if Conn.Established then
         return Err (409, "connection_already_established");
      end if;
      if not Conn.Has_Nonce then
         return Err (401, "invalid_nonce");           --  authenticate before hello
      end if;
      if not Auth_Found then
         return Err (401, "authentication_failed");
      end if;
      --  §4.6 hardening: key_type / pubkey length / peer_id key_type.
      declare
         Kt : constant String := Text (Auth_Entity, "key_type");
         Pub_Found, Nonce_Found : Boolean;
         Pub : constant Byte_Array := Byte_Field (Auth_Entity, "public_key", Pub_Found);
         Echoed : constant Byte_Array := Byte_Field (Auth_Entity, "nonce", Nonce_Found);
         Claimed : constant String := Text (Auth_Entity, "peer_id");
      begin
         if Kt /= "" and then Kt /= "ed25519" then
            return Err (400, "unsupported_key_type");
         end if;
         if Pub_Found and then Pub'Length /= 32 then
            return Err (400, "unsupported_key_type");
         end if;
         --  step 1: nonce echo
         if not (Nonce_Found and then Octets_Equal (Echoed, Conn.Issued_Nonce)) then
            return Err (401, "invalid_nonce");
         end if;
         if not Pub_Found then
            return Err (401, "authentication_failed");
         end if;
         --  step 2: proof of possession — verify the §3.5 signature over the
         --  authenticate entity's content_hash with the presented public key.
         declare
            Sgn_Found : Boolean;
            Sgn : constant Materialized_Entity :=
              Cap.Find_Signature (Env, Hash (Auth_Entity), Sgn_Found);
            Sig_Ok : Boolean := False;
         begin
            if Sgn_Found then
               declare
                  Sb_Found : Boolean;
                  Sb : constant Byte_Array := Byte_Field (Sgn, "signature", Sb_Found);
               begin
                  if Sb_Found and then Sb'Length = Entity_Core.Crypto.Signature_Length then
                     Sig_Ok := Entity_Core.Crypto.Verify
                       (Public_Key => Entity_Core.Crypto.Public_Bytes (Pub),
                        Signature  => Entity_Core.Crypto.Signature_Bytes (Sb),
                        Message    => Hash (Auth_Entity));
                  end if;
               end;
            end if;
            if not Sig_Ok then
               return Err (401, "authentication_failed");
            end if;
         end;
         --  step 3: identity binding — claimed peer_id == derive(public_key).
         if Claimed /= Id_Pkg.Peer_Id_Of_Public (Entity_Core.Crypto.Public_Bytes (Pub)) then
            return Err (401, "identity_mismatch");
         end if;
         if Conn.Hello_Pid_Len > 0
           and then Conn.Hello_Pid (1 .. Conn.Hello_Pid_Len) /= Claimed
         then
            return Err (401, "identity_mismatch");
         end if;
         --  success: mint the §4.4 / §6.9a initial capability for the remote.
         declare
            Remote_Peer : constant Materialized_Entity :=
              Id_Pkg.Peer_Entity_Of_Public (Entity_Core.Crypto.Public_Bytes (Pub));
            Grants : constant Ecf_Value := Derive_Seed_Grants (Peer, Remote_Peer, Claimed);
            Token, Sig : Materialized_Entity;
         begin
            Mint_Token (Peer, Hash (Remote_Peer), Grants, Empty_Bytes, Token, Sig);
            Conn.Established := True;
            return Ok_Inc
              (Make ("system/capability/grant",
                     Map_Of ((1 => (Key => K ("token"), Value => Make_Bytes (Hash (Token)))))),
               Cap_Included (Peer, Token, Sig));
         end;
      end;
   end Handle_Authenticate;

   ---------------------------------------------------------------------------
   --  §6.3 — the tree handler (get / put).
   ---------------------------------------------------------------------------
   function Build_Listing (Peer : Peer_Access; Path : String) return Outcome is
      Rows : Entity_Core.Protocol.Store.List_Rows := Peer.St.Listing (Path);
   begin
      declare
         Pairs : Pair_Vector (1 .. Rows'Length);
         Idx   : Natural := 0;
      begin
         for R of Rows loop
            --  §9.5a CORE-TREE-DELETE-1 / §6.3: omit deletion-markered leaves
            --  from the listing (a tombstoned path is logically absent).
            declare
               Is_Marker : Boolean := False;
            begin
               if R.Hash_Hex /= null then
                  declare
                     Found : Boolean;
                     Leaf  : constant Materialized_Entity :=
                       Peer.St.Get_At (Path & R.Segment.all, Found);
                  begin
                     Is_Marker := Found
                       and then Type_Name (Leaf) = "system/deletion-marker";
                  end;
               end if;
               if not Is_Marker then
                  Idx := Idx + 1;
                  declare
                     Le_Data : Ecf_Value;
                  begin
                     if R.Hash_Hex /= null then
                        Le_Data := Map_Of
                          (((Key => K ("has_children"), Value => Make_Bool (R.Has_Children)),
                            (Key => K ("hash"), Value => Make_Bytes (Unhex (R.Hash_Hex.all)))));
                     else
                        Le_Data := Map_Of
                          ((1 => (Key => K ("has_children"), Value => Make_Bool (R.Has_Children))));
                     end if;
                     declare
                        Le : constant Materialized_Entity :=
                          Make ("system/tree/listing-entry", Le_Data);
                     begin
                        Pairs (Idx) := (Key => Make_Text (R.Segment.all), Value => To_Cbor (Le));
                     end;
                  end;
               end if;
            end;
         end loop;
         declare
            Result : constant Materialized_Entity :=
              Make ("system/tree/listing",
                Map_Of (((Key => K ("path"),    Value => Make_Text (Path)),
                         (Key => K ("entries"), Value => Make_Map (Pairs (1 .. Idx))),
                         (Key => K ("count"),   Value => Make_Uint (Interfaces.Unsigned_64 (Idx))),
                         (Key => K ("offset"),  Value => Make_Uint (0)))));
         begin
            Entity_Core.Protocol.Store.Free_Rows (Rows);
            return Ok (Result);
         end;
      end;
   end Build_Listing;

   function Handle_Tree_Get
     (Peer : Peer_Access; Exec : Materialized_Entity) return Outcome is
      Target : constant String := Exec_Resource_Target (Exec);
   begin
      if Target = "" then
         return Build_Listing (Peer, "/" & Local_Peer (Peer) & "/");
      end if;
      if Target (Target'Last) = '/' then
         return Build_Listing (Peer, Cap.Canonicalize (Local_Peer (Peer), Target));
      end if;
      declare
         Path : constant String := Cap.Canonicalize (Local_Peer (Peer), Target);
         Found : Boolean;
         E : constant Materialized_Entity := Peer.St.Get_At (Path, Found);
      begin
         if not Found then
            return Err (404, "not_found", Path);
         end if;
         return Ok (E);
      end;
   end Handle_Tree_Get;

   --  §1.4 / §5.4 path validation for a CALLER-supplied (peer-relative) tree
   --  path. Reject: leading '/', empty segments ("//"), NUL byte, "." / ".."
   --  segments. Accept multi-segment + Unicode. (The validator's flex bundle.)
   function Valid_Tree_Path (P : String) return Boolean is
   begin
      if P'Length = 0 then
         return False;
      end if;
      --  A leading '/' is valid only for an ABSOLUTE path whose first segment
      --  is a peer-id ("/<peer-id>/..."); a leading '/' on any other content
      --  is a malformed peer-relative path (§1.4).
      if P (P'First) = '/' then
         declare
            Slash2 : Natural := 0;
         begin
            for I in P'First + 1 .. P'Last loop
               if P (I) = '/' then
                  Slash2 := I;
                  exit;
               end if;
            end loop;
            if Slash2 = 0 then
               return False;
            end if;
            if not Cap.Is_Peer_Id (P (P'First + 1 .. Slash2 - 1)) then
               return False;
            end if;
         end;
      end if;
      declare
         First_Seg : constant Integer :=
           (if P (P'First) = '/' then P'First + 1 else P'First);
         Seg_Start : Integer := First_Seg;
      begin
         for I in First_Seg .. P'Last loop
            if Character'Pos (P (I)) = 0 then
               return False;   --  NUL byte
            end if;
            if P (I) = '/' then
               declare
                  Seg : constant String := P (Seg_Start .. I - 1);
               begin
                  if Seg'Length = 0 or else Seg = "." or else Seg = ".." then
                     return False;   --  empty / dot / dotdot segment
                  end if;
               end;
               Seg_Start := I + 1;
            end if;
         end loop;
         --  trailing segment (a put target never ends in '/').
         declare
            Seg : constant String := P (Seg_Start .. P'Last);
         begin
            if Seg = "." or else Seg = ".." then
               return False;
            end if;
         end;
      end;
      return True;
   end Valid_Tree_Path;

   function Handle_Tree_Put
     (Peer : Peer_Access; Exec : Materialized_Entity) return Outcome is
      Target : constant String := Exec_Resource_Target (Exec);
   begin
      if Target = "" then
         return Err (400, "ambiguous_resource", "tree: missing resource target");
      end if;
      if not Valid_Tree_Path (Target) then
         return Err (400, "invalid_path", "tree: malformed resource path");
      end if;
      declare
         Path : constant String := Cap.Canonicalize (Local_Peer (Peer), Target);
         --  §6.5: params is the put-request ENTITY ({type, data:{entity,...}});
         --  the entity to bind lives at params.data.entity.
         Params : constant Ecf_Value := Field (Data (Exec), "params");
         Req_Data : constant Ecf_Value := Field (Params, "data");
         Ent_Found : Boolean;
         Ent_V : constant Ecf_Value := Field (Req_Data, "entity", Ent_Found);
         --  §3.9 compare-and-swap: an expected_hash gates the write.
         Exp_Found : Boolean;
         Exp_H : constant Byte_Array := Bytes_Field (Req_Data, "expected_hash", Exp_Found);
         Cur_Found : Boolean;
         Cur_E : constant Materialized_Entity := Peer.St.Get_At (Path, Cur_Found);
      begin
         --  CAS precondition (§3.9 / v7.50 CAS-create).
         if Exp_Found and then Exp_H'Length > 0 then
            declare
               Exp_Zero : Boolean := True;
            begin
               for B of Exp_H loop
                  if B /= Octet'(0) then
                     Exp_Zero := False;
                     exit;
                  end if;
               end loop;
               if Exp_Zero then
                  --  CAS-create: succeed only if the path is currently unbound.
                  if Cur_Found then
                     return Err (409, "hash_mismatch", "CAS-create: path already bound");
                  end if;
               else
                  --  CAS-update: current binding MUST equal expected_hash.
                  if not Cur_Found
                    or else not Octets_Equal (Hash (Cur_E), Exp_H)
                  then
                     return Err (409, "hash_mismatch", "CAS: expected_hash mismatch");
                  end if;
               end if;
            end;
         end if;

         --  No entity in the request → §6.3 removal (unbind the path).
         if not Ent_Found or else Kind (Ent_V) /= K_Map or else not Has (Ent_V, "type") then
            if Cur_Found then
               Peer.St.Unbind (Path);
            end if;
            return Ok (Make ("system/hash",
              Map_Of ((1 => (Key => K ("hash"), Value => Make_Bytes (Empty_Bytes))))));
         end if;
         declare
            Ent : constant Materialized_Entity := Of_Cbor (Ent_V);
         begin
            Peer.St.Bind (Path, Ent);
            return Ok (Make ("system/hash",
              Map_Of ((1 => (Key => K ("hash"), Value => Make_Bytes (Hash (Ent)))))));
         end;
      end;
   end Handle_Tree_Put;

   ---------------------------------------------------------------------------
   --  §6.2 — the capability handler (request — the smoke-reachable op).
   ---------------------------------------------------------------------------
   --  §6.5: params is the request ENTITY ({type, data:{grants,...}}); the
   --  requested grants live at params.data.grants.
   function Req_Grants (Params : Ecf_Value) return Ecf_Value is
      G : constant Ecf_Value := Field (Field (Params, "data"), "grants");
   begin
      if Kind (G) = K_Array then
         return G;
      end if;
      return S0;
   end Req_Grants;

   function Handle_Cap_Request
     (Peer : Peer_Access; Exec : Materialized_Entity;
      Caller_Cap : Materialized_Entity; Has_Caller_Cap : Boolean) return Outcome is
      Params : constant Ecf_Value := Field (Data (Exec), "params");
      Author_Found : Boolean;
      Author : constant Byte_Array := Byte_Field (Exec, "author", Author_Found);
   begin
      if not Author_Found then
         return Err (403, "capability_denied");
      end if;
      pragma Unreferenced (Has_Caller_Cap);
      declare
         Requested : constant Ecf_Value := Req_Grants (Params);
         Authorized : constant Ecf_Value := Field (Data (Caller_Cap), "grants");
         Token, Sig : Materialized_Entity;
      begin
         --  §6.2 / §5.6 mint-bound: the issued grant MUST NOT exceed the
         --  PRESENTED caller capability's authority. A request widening past
         --  the presented (narrow) cap is refused (403).
         if Kind (Authorized) = K_Array
           and then not Cap.Grants_Are_Subset (Local_Peer (Peer), Requested, Authorized)
         then
            return Err (403, "scope_exceeds_authority",
                        "requested grant exceeds the presented capability");
         end if;
         Mint_Token (Peer, Author, Requested, Empty_Bytes, Token, Sig);
         return Ok_Inc
           (Make ("system/capability/grant",
                  Map_Of ((1 => (Key => K ("token"), Value => Make_Bytes (Hash (Token)))))),
            Cap_Included (Peer, Token, Sig));
      end;
   end Handle_Cap_Request;

   ---------------------------------------------------------------------------
   --  §6.2/§4 configure — bind a policy-entry at
   --  system/capability/policy/{peer_pattern}. peer_pattern MUST be exactly
   --  "default" or 66 hex chars (closeout F8); a partial prefix → 400.
   ---------------------------------------------------------------------------
   function Is_Hex_66 (S : String) return Boolean is
   begin
      if S'Length /= 66 then
         return False;
      end if;
      for C of S loop
         if not ((C in '0' .. '9') or (C in 'a' .. 'f') or (C in 'A' .. 'F')) then
            return False;
         end if;
      end loop;
      return True;
   end Is_Hex_66;

   function Handle_Cap_Configure
     (Peer : Peer_Access; Exec : Materialized_Entity) return Outcome is
      Params  : constant Ecf_Value := Field (Data (Exec), "params");
      P_Data  : constant Ecf_Value := Field (Params, "data");
      Pattern : constant String := Text_Field (P_Data, "peer_pattern");
   begin
      --  §6.2/§4 + v7.65 §3.6 rule 3: peer_pattern is exactly "default", a
      --  66-hex identity hash, OR a Base58 peer_id wire-handle (lazy-canon
      --  mint for an as-yet-uncontacted peer). A partial prefix (e.g. "00abc*")
      --  is rejected — it has no operator-reasonable meaning.
      if Pattern /= "default"
        and then not Is_Hex_66 (Pattern)
        and then not Cap.Is_Peer_Id (Pattern)
      then
         return Err (400, "invalid_params",
                     "peer_pattern must be ""default"", 66 hex chars, or a peer_id");
      end if;
      declare
         Entry_E : constant Materialized_Entity :=
           Make ("system/capability/policy-entry", P_Data);
      begin
         Peer.St.Bind
           ("/" & Local_Peer (Peer) & "/system/capability/policy/" & Pattern, Entry_E);
         return Ok (Make ("system/capability/policy-entry", P_Data));
      end;
   end Handle_Cap_Configure;

   ---------------------------------------------------------------------------
   --  §5/§6 revoke — write a revocation marker at
   --  system/capability/revocations/{token_hex} with a handler-set revoked_at.
   --  A zero token is refused (400).
   ---------------------------------------------------------------------------
   function Handle_Cap_Revoke
     (Peer : Peer_Access; Exec : Materialized_Entity) return Outcome is
      Params  : constant Ecf_Value := Field (Data (Exec), "params");
      P_Data  : constant Ecf_Value := Field (Params, "data");
      Tok_Found : Boolean;
      Token_H : constant Byte_Array := Bytes_Field (P_Data, "token", Tok_Found);
      Reason  : constant String := Text_Field (P_Data, "reason");
      All_Zero : Boolean := True;
   begin
      if not Tok_Found or else Token_H'Length = 0 then
         return Err (400, "invalid_params", "revoke requires a token");
      end if;
      for B of Token_H loop
         if B /= Octet'(0) then
            All_Zero := False;
            exit;
         end if;
      end loop;
      if All_Zero then
         return Err (400, "invalid_params", "revoke token is the zero hash");
      end if;
      declare
         Marker : constant Materialized_Entity :=
           Make ("system/capability/revocation",
             Map_Of (((Key => K ("token"),      Value => Make_Bytes (Token_H)),
                      (Key => K ("reason"),     Value => Make_Text (Reason)),
                      (Key => K ("revoked_at"), Value => Make_Uint (Now_Ms)))));
      begin
         Peer.St.Bind
           ("/" & Local_Peer (Peer) & "/system/capability/revocations/" & Hex (Token_H),
            Marker);
         return Ok (Marker);
      end;
   end Handle_Cap_Revoke;

   ---------------------------------------------------------------------------
   --  §10.1 core dynamic-register gate — system/handler:register binds a
   --  handler + interface (+ a self-minted grant) at the requested pattern;
   --  unregister removes them.
   ---------------------------------------------------------------------------
   --  Strip a leading "system/handler/" from a resource target → the pattern.
   function Pattern_Of_Target (Target : String) return String is
      Prefix : constant String := "system/handler/";
   begin
      if Target'Length > Prefix'Length
        and then Target (Target'First .. Target'First + Prefix'Length - 1) = Prefix
      then
         return Target (Target'First + Prefix'Length .. Target'Last);
      end if;
      return Target;
   end Pattern_Of_Target;

   function Handle_Handler_Register
     (Peer : Peer_Access; Exec : Materialized_Entity) return Outcome is
      Params   : constant Ecf_Value := Field (Data (Exec), "params");
      P_Data   : constant Ecf_Value := Field (Params, "data");
      --  §3.12 register-request: params.data.manifest carries the pattern.
      Manifest_V : constant Ecf_Value := Field (P_Data, "manifest");
      Pattern  : constant String := Text_Field (Manifest_V, "pattern");
   begin
      if Pattern = "" then
         return Err (400, "invalid_params", "register requires manifest.pattern");
      end if;
      declare
         --  Interface entity (TypeHandlerInterface) at system/handler/<pattern>.
         Iface : constant Materialized_Entity :=
           Make ("system/handler/interface",
             Map_Of (((Key => K ("pattern"), Value => Make_Text (Pattern)),
                      (Key => K ("name"),    Value => Make_Text (Pattern)),
                      (Key => K ("operations"),
                       Value => (if Has (Manifest_V, "operations")
                                 then Field (Manifest_V, "operations") else Empty_Map)))));
         Hand_E : constant Materialized_Entity :=
           Make ("system/handler",
             Map_Of ((1 => (Key => K ("interface"),
                            Value => Make_Text ("system/handler/" & Pattern)))));
         Token, Sig : Materialized_Entity;
      begin
         Mint_Token (Peer, Id_Pkg.Identity_Hash (Peer.Id),
                     (if Has (P_Data, "requested_scope")
                      then Field (P_Data, "requested_scope") else S0),
                     Empty_Bytes, Token, Sig);
         Peer.St.Bind ("/" & Local_Peer (Peer) & "/" & Pattern, Hand_E);
         Peer.St.Bind
           ("/" & Local_Peer (Peer) & "/system/handler/" & Pattern, Iface);
         Peer.St.Bind
           ("/" & Local_Peer (Peer) & "/system/capability/grants/" & Pattern, Token);
         --  §3.4 invariant-pointer signature path: system/signature/<grant_hash>.
         Peer.St.Bind
           ("/" & Local_Peer (Peer) & "/system/signature/" & Hex (Hash (Token)), Sig);
         return Ok (Make ("system/handler/register-result",
           Map_Of (((Key => K ("pattern"), Value => Make_Text (Pattern)),
                    (Key => K ("handler"),
                     Value => Make_Text ("/" & Local_Peer (Peer) & "/" & Pattern))))));
      end;
   exception
      when others =>
         return Err (500, "internal_error");
   end Handle_Handler_Register;

   function Handle_Handler_Unregister
     (Peer : Peer_Access; Exec : Materialized_Entity) return Outcome is
      --  §3.2: pattern is in the resource target; params is empty.
      Target  : constant String := Exec_Resource_Target (Exec);
      Pattern : constant String := Pattern_Of_Target (Target);
   begin
      if Pattern = "" then
         return Err (400, "invalid_params", "unregister requires a pattern");
      end if;
      --  Locate the grant so we can also remove its invariant-path signature
      --  (writer/unregister symmetry — no half-removed state).
      declare
         G_Found : Boolean;
         Grant_E : constant Materialized_Entity :=
           Peer.St.Get_At
             ("/" & Local_Peer (Peer) & "/system/capability/grants/" & Pattern, G_Found);
      begin
         if G_Found then
            Peer.St.Unbind
              ("/" & Local_Peer (Peer) & "/system/signature/" & Hex (Hash (Grant_E)));
         end if;
      end;
      Peer.St.Unbind ("/" & Local_Peer (Peer) & "/" & Pattern);
      Peer.St.Unbind ("/" & Local_Peer (Peer) & "/system/handler/" & Pattern);
      Peer.St.Unbind ("/" & Local_Peer (Peer) & "/system/capability/grants/" & Pattern);
      return Ok (Make ("system/handler/register-result",
        Map_Of ((1 => (Key => K ("pattern"), Value => Make_Text (Pattern))))));
   end Handle_Handler_Unregister;

   ---------------------------------------------------------------------------
   --  §7a conformance handlers (built only under Validate).
   ---------------------------------------------------------------------------
   function Handle_Echo (Exec : Materialized_Entity) return Outcome is
      Params_Found : Boolean;
      Params : constant Materialized_Entity := Entity_Field (Exec, "params", Params_Found);
   begin
      if not Params_Found then
         return Err (400, "invalid_params", "echo requires a params entity");
      end if;
      return Ok (Params);
   end Handle_Echo;

   ---------------------------------------------------------------------------
   --  §7a.2a / §6.11 dispatch-outbound — the reentry probe. The validator
   --  hands us a target URI + operation + value-bytes + a validator-rooted
   --  reentry capability (in-band, nested in params.data). We ORIGINATE an
   --  outbound EXECUTE back to the validator over the SAME inbound connection
   --  (Conn.Outbound), authed with that cap, and return {status, result} where
   --  result is the downstream result entity VERBATIM (generic relay — the
   --  2026-06-13 matrix ruling #2). No unwrap of the value: we forward the
   --  {value: X} bytes as-is and return what comes back.
   ---------------------------------------------------------------------------
   function Handle_Dispatch_Outbound
     (Peer : Peer_Access; Conn : Conn_State; Exec : Materialized_Entity)
      return Outcome
   is
      Params  : constant Ecf_Value := Field (Data (Exec), "params");
      P_Data  : constant Ecf_Value := Field (Params, "data");
      Target    : constant String := Text_Field (P_Data, "target");
      Operation : constant String := Text_Field (P_Data, "operation");
      Value_V   : constant Ecf_Value := Field (P_Data, "value");
      Cap_V     : constant Ecf_Value := Field (P_Data, "reentry_capability");
      Granter_V : constant Ecf_Value := Field (P_Data, "reentry_granter");
      Sig_V     : constant Ecf_Value := Field (P_Data, "reentry_cap_signature");
   begin
      if Conn.Outbound = null then
         return Err (501, "no_reentry_channel",
                     "dispatch-outbound requires a connection reentry seam");
      end if;
      if Target = "" or else Operation = ""
        or else Kind (Cap_V) /= K_Map or else Kind (Granter_V) /= K_Map
        or else Kind (Sig_V) /= K_Map
      then
         return Err (400, "invalid_params",
                     "dispatch-outbound requires target/operation/reentry-cap");
      end if;
      declare
         --  Materialize the in-band reentry-authority entities.
         Cap_E     : constant Materialized_Entity := Of_Cbor (Cap_V);
         Granter_E : constant Materialized_Entity := Of_Cbor (Granter_V);
         Sig_E     : constant Materialized_Entity := Of_Cbor (Sig_V);
         --  The outbound params is a primitive/any entity whose data is the
         --  forwarded {value: X} map (relay-verbatim).
         Out_Params : constant Materialized_Entity :=
           Make ("primitive/any",
             (if Kind (Value_V) = K_Map then Value_V else Empty_Map));
         Rid : constant String := "ada-reentry-" & Hex (Hash (Exec));
         Out_Exec : constant Materialized_Entity :=
           Wire.Make_Execute
             (Rid, Target, Operation, Out_Params,
              Author     => Id_Pkg.Identity_Hash (Peer.Id),
              Capability => Hash (Cap_E));
         Out_Sig  : constant Materialized_Entity := Id_Pkg.Sign (Peer.Id, Out_Exec);
         Out_Env  : Env_Pkg.Protocol_Envelope := Env_Pkg.Of_Root (Out_Exec);
         Ok_Out   : Boolean;
      begin
         --  §5.8 authority chain travels in `included`: the reentry cap, its
         --  granter (the validator), its signature, plus our identity + the
         --  EXECUTE signature so the validator-as-B can verify the §3.5 PoP.
         Env_Pkg.Add (Out_Env, Cap_E);
         Env_Pkg.Add (Out_Env, Granter_E);
         Env_Pkg.Add (Out_Env, Sig_E);
         Env_Pkg.Add (Out_Env, Id_Pkg.Peer_Entity (Peer.Id));
         Env_Pkg.Add (Out_Env, Out_Sig);
         declare
            Reply : constant Env_Pkg.Protocol_Envelope :=
              Conn.Outbound (Conn.Outbound_Ctx, Out_Env, Rid, Ok_Out);
         begin
            if not Ok_Out then
               return Err (502, "reentry_failed", "no downstream reply");
            end if;
            declare
               Found  : Boolean;
               Status : constant Interfaces.Unsigned_64 := Wire.Response_Status (Reply);
               Result : constant Materialized_Entity := Wire.Response_Result (Reply, Found);
               --  Return {status, result} — result is the downstream result
               --  entity verbatim (the relay-faithful inner result).
               Inner : constant Materialized_Entity :=
                 Make ("primitive/any",
                   Map_Of (((Key => K ("status"), Value => Make_Uint (Status)),
                            (Key => K ("result"),
                             Value => (if Found then To_Cbor (Result) else Make_Null)))));
            begin
               return Ok (Inner);
            end;
         end;
      end;
   exception
      when others =>
         return Err (500, "internal_error", "dispatch-outbound failed");
   end Handle_Dispatch_Outbound;

   ---------------------------------------------------------------------------
   --  §6.6 backward resolution — longest prefix bound to a system/handler.
   ---------------------------------------------------------------------------
   function Resolve_Handler (Peer : Peer_Access; Path : String) return String is
      --  Walk from the full path back to the first segment.
      Last : Natural := Path'Last;
   begin
      loop
         declare
            Prefix : constant String := Path (Path'First .. Last);
            Found : Boolean;
            E : constant Materialized_Entity := Peer.St.Get_At (Prefix, Found);
         begin
            if Found and then Type_Name (E) = "system/handler" then
               return Prefix;
            end if;
         end;
         exit when Last <= Path'First;
         --  back up to the previous '/'
         declare
            Cut : Natural := 0;
         begin
            for I in reverse Path'First .. Last - 1 loop
               if Path (I) = '/' then
                  Cut := I;
                  exit;
               end if;
            end loop;
            exit when Cut = 0;
            Last := Cut - 1;
         end;
      end loop;
      return "";
   end Resolve_Handler;

   --  Strip the /{local}/ prefix from a resolved pattern.
   function Strip_Local (Peer : Peer_Access; Pattern : String) return String is
      Prefix : constant String := "/" & Local_Peer (Peer) & "/";
   begin
      if Pattern'Length >= Prefix'Length
        and then Pattern (Pattern'First .. Pattern'First + Prefix'Length - 1) = Prefix
      then
         return Pattern (Pattern'First + Prefix'Length .. Pattern'Last);
      end if;
      return Pattern;
   end Strip_Local;

   ---------------------------------------------------------------------------
   --  §6.5 signature ingestion — bind included signatures into the tree so the
   --  chain walk can resolve them.
   ---------------------------------------------------------------------------
   procedure Ingest_Signatures (Peer : Peer_Access; Env : Env_Pkg.Protocol_Envelope) is
   begin
      for It of Env.Included loop
         if Type_Name (It.Ent) = "system/signature" then
            Peer.St.Put_Entity (It.Ent);
            declare
               Signer_Found : Boolean;
               Signer_H : constant Byte_Array := Byte_Field (It.Ent, "signer", Signer_Found);
            begin
               if Signer_Found then
                  declare
                     Sp_Found : Boolean;
                     Signer_Peer : constant Materialized_Entity :=
                       Env_Pkg.Included_Get (Env, Signer_H, Sp_Found);
                  begin
                     if Sp_Found then
                        Peer.St.Put_Entity (Signer_Peer);
                        declare
                           Tg_Found, Pk_Found : Boolean;
                           Tg : constant Byte_Array := Byte_Field (It.Ent, "target", Tg_Found);
                           Pk : constant Byte_Array := Byte_Field (Signer_Peer, "public_key", Pk_Found);
                        begin
                           if Tg_Found and then Pk_Found and then Pk'Length = 32 then
                              declare
                                 Pid : constant String := Id_Pkg.Peer_Id_Of_Public
                                   (Entity_Core.Crypto.Public_Bytes (Pk));
                              begin
                                 Peer.St.Bind
                                   ("/" & Pid & "/system/signature/" & Hex (Tg), It.Ent);
                              end;
                           end if;
                        end;
                     end if;
                  end;
               end if;
            end;
         end if;
      end loop;
   end Ingest_Signatures;

   ---------------------------------------------------------------------------
   --  The §6.5 dispatch chain inner.
   ---------------------------------------------------------------------------
   function Dispatch_Inner
     (Peer : Peer_Access; Conn : in out Conn_State; Env : Env_Pkg.Protocol_Envelope)
      return Outcome
   is
      Exec : constant Materialized_Entity := Env.Root;
      Uri  : constant String := Text (Exec, "uri");
      Operation : constant String := Text (Exec, "operation");
   begin
      --  The connect handler is reachable WITHOUT a capability (§4.1).
      if Uri = "system/protocol/connect" then
         if Operation = "hello" then
            return Handle_Hello (Peer, Conn, Exec);
         elsif Operation = "authenticate" then
            return Handle_Authenticate (Peer, Conn, Exec, Env);
         else
            return Err (501, "unsupported_operation", Operation);
         end if;
      end if;

      --  Everything else is capability-gated (§6.5).
      Ingest_Signatures (Peer, Env);
      declare
         V : constant Cap.Request_Verdict :=
           Cap.Verify_Request (Local_Peer (Peer), Peer.St, Env);
      begin
         case V is
            when Cap.Authn_Fail     => return Err (401, "authentication_failed");
            when Cap.Authz_Deny     => return Err (403, "capability_denied");
            when Cap.Chain_Too_Deep => return Err (400, "chain_depth_exceeded");
            when Cap.Allow          => null;
         end case;
      end;

      declare
         Path : constant String :=
           Cap.Canonicalize (Local_Peer (Peer), Cap.Normalize_Uri (Uri));
      begin
         --  §1.4: inbound dispatch must target the local peer.
         if Cap.Extract_Peer (Local_Peer (Peer), Path) /= Local_Peer (Peer) then
            return Err (404, "handler_not_found", "not local peer");
         end if;
         declare
            Pattern : constant String := Resolve_Handler (Peer, Path);
         begin
            if Pattern = "" then
               return Err (404, "handler_not_found", Path);
            end if;
            --  Caller cap presence + permission gate.
            declare
               Cap_H_Found, Caller_Cap_Found : Boolean;
               Cap_H : constant Byte_Array := Byte_Field (Exec, "capability", Cap_H_Found);
               Caller_Cap : constant Materialized_Entity :=
                 (if Cap_H_Found then Env_Pkg.Included_Get (Env, Cap_H, Caller_Cap_Found)
                  else Make ("primitive/any", Empty_Map));
            begin
               if not Cap_H_Found then
                  return Err (403, "capability_denied");
               end if;
               if not Caller_Cap_Found then
                  return Err (403, "capability_denied");
               end if;
               declare
                  Granter : String := Cap.Resolve_Granter_Peer_Id (Peer.St, Env, Caller_Cap);
               begin
                  if Granter = "" then
                     Granter := Local_Peer (Peer);
                  end if;
                  if Cap.Check_Permission
                       (Local_Peer (Peer), Granter, Exec, Caller_Cap, Pattern) = Cap.Deny
                  then
                     return Err (403, "capability_denied");
                  end if;
                  --  route to the handler (single-dispatch ladder on pattern).
                  declare
                     Stripped : constant String := Strip_Local (Peer, Pattern);
                  begin
                     if Stripped = "system/tree" then
                        if Operation = "get" then
                           return Handle_Tree_Get (Peer, Exec);
                        elsif Operation = "put" then
                           return Handle_Tree_Put (Peer, Exec);
                        else
                           return Err (501, "unsupported_operation", Operation);
                        end if;
                     elsif Stripped = "system/capability" then
                        if Operation = "request" then
                           return Handle_Cap_Request (Peer, Exec, Caller_Cap, True);
                        elsif Operation = "configure" then
                           return Handle_Cap_Configure (Peer, Exec);
                        elsif Operation = "revoke" then
                           return Handle_Cap_Revoke (Peer, Exec);
                        else
                           --  delegate (same-peer-only, closeout F1) and any
                           --  other op: 501 for a remote caller.
                           return Err (501, "unsupported_operation", Operation);
                        end if;
                     elsif Stripped = "system/handler" then
                        if Operation = "register" then
                           return Handle_Handler_Register (Peer, Exec);
                        elsif Operation = "unregister" then
                           return Handle_Handler_Unregister (Peer, Exec);
                        elsif Operation = "get" then
                           return Handle_Tree_Get (Peer, Exec);
                        else
                           return Err (501, "unsupported_operation", Operation);
                        end if;
                     elsif Stripped = "system/validate/echo" then
                        if Operation = "echo" then
                           return Handle_Echo (Exec);
                        else
                           return Err (501, "unsupported_operation", Operation);
                        end if;
                     elsif Stripped = "system/validate/dispatch-outbound" then
                        if Operation = "dispatch" then
                           return Handle_Dispatch_Outbound (Peer, Conn, Exec);
                        else
                           return Err (501, "unsupported_operation", Operation);
                        end if;
                     else
                        return Err (501, "no_handler_body", Pattern);
                     end if;
                  end;
               end;
            end;
         end;
      end;
   end Dispatch_Inner;

   --------------
   -- Dispatch --
   --------------
   function Dispatch
     (Peer : Peer_Access;
      Conn : in out Conn_State;
      Env  : Env_Pkg.Protocol_Envelope;
      Is_Response : out Boolean)
      return Env_Pkg.Protocol_Envelope
   is
      Exec : constant Materialized_Entity := Env.Root;
      Request_Id : constant String := Text (Exec, "request_id");
   begin
      if Type_Name (Exec) /= "system/protocol/execute" then
         Is_Response := False;
         return Env_Pkg.Of_Root (Exec);   --  unused
      end if;
      Is_Response := True;
      declare
         O : Outcome;
      begin
         begin
            O := Dispatch_Inner (Peer, Conn, Env);
         exception
            when Entity_Core.Errors.Unresolvable_Grantee =>
               O := Err (401, "unresolvable_grantee");
            when Entity_Core.Errors.Payload_Too_Large =>
               O := Err (413, "payload_too_large");
            when E : others =>
               if Debug_Dispatch then
                  Ada.Text_IO.Put_Line
                    (Ada.Text_IO.Standard_Error,
                     "DBG exception uri=" & Text (Exec, "uri") & " op="
                     & Text (Exec, "operation") & " => "
                     & Ada.Exceptions.Exception_Information (E));
               end if;
               O := Err (500, "internal_error");
         end;
         if Debug_Dispatch and then O.Status /= 200 then
            Ada.Text_IO.Put_Line
              (Ada.Text_IO.Standard_Error,
               "DBG status" & O.Status'Image & " uri=" & Text (Exec, "uri")
               & " op=" & Text (Exec, "operation"));
         end if;
         declare
            Resp : Env_Pkg.Protocol_Envelope :=
              Env_Pkg.Of_Root (Wire.Make_Response (Request_Id, O.Status, O.Result));
         begin
            if O.Has_Inc then
               for It of O.Env.Included loop
                  Env_Pkg.Add (Resp, It.Ent);
               end loop;
            end if;
            return Resp;
         end;
      end;
   end Dispatch;

   ---------------------------------------------------------------------------
   --  Bootstrap (§6.9 / §6.9a).
   ---------------------------------------------------------------------------
   --  Build a system/handler/interface `operations` map: { op => {} } for each
   --  op name (§6.2 N3 — the interface advertises its operation set; the empty
   --  operation-spec is conformant, input/output types are optional).
   function Ops_Map (Ops : Op_List) return Ecf_Value is
   begin
      if Ops'Length = 0 then
         return Empty_Map;
      end if;
      declare
         Kv : Cbor_Util.Kv_List (1 .. Ops'Length);
      begin
         for I in Ops'Range loop
            Kv (I - Ops'First + 1) :=
              (Key => K (Ops (I).all), Value => Empty_Map);
         end loop;
         return Map_Of (Kv);
      end;
   end Ops_Map;

   procedure Bootstrap_Handler_Entities
     (Peer : Peer_Access; Pattern : String; Name : String;
      Ops : Op_List := No_Ops) is
      Iface : constant Materialized_Entity :=
        Make ("system/handler/interface",
          Map_Of (((Key => K ("pattern"), Value => Make_Text (Pattern)),
                   (Key => K ("name"),    Value => Make_Text (Name)),
                   (Key => K ("operations"), Value => Ops_Map (Ops)))));
      Hand : constant Materialized_Entity :=
        Make ("system/handler",
          Map_Of ((1 => (Key => K ("interface"),
                         Value => Make_Text ("system/handler/" & Pattern)))));
      Token, Sig : Materialized_Entity;
   begin
      Peer.St.Bind ("/" & Local_Peer (Peer) & "/" & Pattern, Hand);
      Peer.St.Bind ("/" & Local_Peer (Peer) & "/system/handler/" & Pattern, Iface);
      Mint_Token (Peer, Id_Pkg.Identity_Hash (Peer.Id), S0, Empty_Bytes, Token, Sig);
      Peer.St.Bind ("/" & Local_Peer (Peer) & "/system/capability/grants/" & Pattern, Token);
   end Bootstrap_Handler_Entities;

   ------------
   -- Create --
   ------------
   procedure Create
     (Peer        : out Peer_Access;
      Seed        : Entity_Core.Crypto.Seed_Bytes;
      Open_Grants : Boolean := False;
      Validate    : Boolean := False)
   is
      P : constant Peer_Access := new Peer_Type;
      Pid : constant String := Id_Pkg.Peer_Id (Id_Pkg.Of_Seed (Seed));
   begin
      P.Id := Id_Pkg.Of_Seed (Seed);
      P.St := new Entity_Core.Protocol.Store.Safe_Store;
      P.Local_Len := Pid'Length;
      P.Local_Buf (1 .. Pid'Length) := Pid;
      P.Open_Grants := Open_Grants;
      P.Validate := Validate;

      --  local identity entity in the store (root-granter resolution).
      P.St.Put_Entity (Id_Pkg.Peer_Entity (P.Id));

      --  bootstrap the MUST handler instances.
      Bootstrap_Handler_Entities (P, "system/tree", "Tree", Tree_Ops);
      Bootstrap_Handler_Entities (P, "system/handler", "Handlers", Handler_Ops);
      Bootstrap_Handler_Entities (P, "system/type", "Types");
      Bootstrap_Handler_Entities (P, "system/capability", "Capability", Cap_Ops);
      Bootstrap_Handler_Entities (P, "system/protocol/connect", "Connect", Connect_Ops);

      --  §9.5 core-type floor — publish the 53 canonical type definitions at
      --  system/type/<name> (byte-identical to the v7.75 oracle).
      Entity_Core.Protocol.Type_Registry.Publish (P.St, Pid);

      --  §6.9a peer-authority bootstrap: self-owner cap + default policy entry.
      declare
         Policy_Base : constant String :=
           "/" & Pid & "/system/capability/policy/";
         Owner_Token, Owner_Sig : Materialized_Entity;
         Default_Grants : constant Ecf_Value :=
           (if Open_Grants then Open_Grants_Scope else Discovery_Floor);
         Default_Entry : constant Materialized_Entity :=
           Make ("system/capability/policy-entry",
             Map_Of (((Key => K ("peer_pattern"), Value => Make_Text ("default")),
                      (Key => K ("grants"), Value => Default_Grants))));
      begin
         Mint_Token (P, Id_Pkg.Identity_Hash (P.Id), Owner_Grants (P), Empty_Bytes,
                     Owner_Token, Owner_Sig);
         P.St.Bind (Policy_Base & Hex (Id_Pkg.Identity_Hash (P.Id)), Owner_Token);
         P.St.Bind ("/" & Pid & "/system/signature/" & Hex (Hash (Owner_Token)), Owner_Sig);
         P.St.Bind (Policy_Base & "default", Default_Entry);
      end;

      --  §7a conformance handlers — only under --validate.
      if Validate then
         Bootstrap_Handler_Entities (P, "system/validate/echo", "validate-echo");
         Bootstrap_Handler_Entities (P, "system/validate/dispatch-outbound",
                                     "validate-dispatch-outbound");
      end if;

      Peer := P;
   end Create;

   ----------------
   -- Local_Peer --
   ----------------
   function Local_Peer (Peer : Peer_Access) return String is
     (Peer.Local_Buf (1 .. Peer.Local_Len));

   --------------
   -- Identity --
   --------------
   function Identity (Peer : Peer_Access) return Id_Pkg.Peer_Identity is (Peer.Id);

   -----------
   -- Store --
   -----------
   function Store (Peer : Peer_Access)
                   return access Entity_Core.Protocol.Store.Safe_Store is
     (Peer.St);

end Entity_Core.Protocol.Handlers;
