--  run_peer_tests — the S3 peer-machinery units for the 0.8.2.20..25 rules.
--
--  `run_tests` covers the CODEC. This covers the PEER: §3.3's effective-targets
--  ladder, §6.3's check_path_permission and listing filter, §5.4's sentinel as
--  scoped at 0.8.2.24, §5.5a's typed subset, and §4.11's pre-admission refusal
--  classification. None of it is reachable from the codec runner, and the pinned
--  778-check set has no vector on any of it.
--
--  ONE PROCEDURE RATHER THAN A FRAMEWORK, matching `run_tests`: Check(Name, Cond),
--  a PASS/FAIL count, and a non-zero exit when any check fails. THE COUNT IS
--  PRINTED AND ASSERTED NON-ZERO — a gate that examined zero things prints the
--  same word as one that examined forty.

with Ada.Command_Line;
with Ada.Text_IO;          use Ada.Text_IO;
with Ada.Exceptions;
with Interfaces;           use Interfaces;

with Entity_Core.Bytes;                     use Entity_Core.Bytes;
with Entity_Core.Codec.Value;               use Entity_Core.Codec.Value;
with Entity_Core.Crypto;
with Entity_Core.Errors;
with Entity_Core.Protocol.Cbor_Util;        use Entity_Core.Protocol.Cbor_Util;
with Entity_Core.Protocol.Entity;           use Entity_Core.Protocol.Entity;
with Entity_Core.Protocol.Envelope;
with Entity_Core.Protocol.Identity;
with Entity_Core.Protocol.Capability;
with Entity_Core.Protocol.Handlers;
with Entity_Core.Protocol.Wire;
use type Entity_Core.Protocol.Wire.Pre_Admission_Cause;

procedure Run_Peer_Tests is

   package Cap renames Entity_Core.Protocol.Capability;
   package Hand renames Entity_Core.Protocol.Handlers;
   package Wire renames Entity_Core.Protocol.Wire;
   package Env_Pkg renames Entity_Core.Protocol.Envelope;

   Passed  : Natural := 0;
   Failed  : Natural := 0;
   Checked : Natural := 0;

   procedure Check (Name : String; Cond : Boolean) is
   begin
      Checked := Checked + 1;
      if Cond then
         Passed := Passed + 1;
      else
         Failed := Failed + 1;
         Put_Line ("  FAIL: " & Name);
      end if;
   end Check;

   --  A peer with the discovery floor (NOT open grants): the §6.3 path check is
   --  only observable where the caller's grant is narrower than the request.
   Peer : Hand.Peer_Access;
   Seed : constant Entity_Core.Crypto.Seed_Bytes := (others => 16#5A#);

   function Local return String is (Hand.Local_Peer (Peer));

   --  A scope map {include:[...], exclude:[...]}; Excl empty => omit the key.
   function Scope_Of (Incl, Excl : Value_Vector) return Ecf_Value is
   begin
      if Excl'Length = 0 then
         return Map_Of ((1 => (Key => K ("include"), Value => Array_Of (Incl))));
      end if;
      return Map_Of (((Key => K ("include"), Value => Array_Of (Incl)),
                      (Key => K ("exclude"), Value => Array_Of (Excl))));
   end Scope_Of;

   function T1 (S : String) return Value_Vector is (1 => Make_Text (S));
   function T2 (A, B : String) return Value_Vector is (Make_Text (A), Make_Text (B));
   No_Strings : constant Value_Vector (1 .. 0) := (others => Make_Null);

   --  A SELF-ISSUED ROOT capability whose four dimensions are set independently.
   --
   --  granter == grantee == this peer's identity hash, which is what §5.5's root
   --  arm requires ("root must be self-issued by Local_Peer") and what makes the
   --  token usable through the REAL dispatch chain rather than through a handler
   --  called directly. Driving the chain is the whole point: it is what makes the
   --  RULE G ordering claim an ordering claim, and it is what proves the §6.3
   --  check runs on the authority the dispatch check resolved.
   function Token_Of
     (Handlers, Operations, Resources : Ecf_Value) return Materialized_Entity
   is
      Idh : constant Byte_Array :=
        Byte_Array (Entity_Core.Protocol.Identity.Identity_Hash (Hand.Identity (Peer)));
   begin
      return Make ("system/capability/token",
        Map_Of (((Key => K ("granter"),  Value => Make_Bytes (Idh)),
                 (Key => K ("grantee"),  Value => Make_Bytes (Idh)),
                 (Key => K ("created_at"), Value => Make_Uint (1_700_000_000_000)),
                 (Key => K ("grants"),
                  Value => Array_Of
                    ((1 => Map_Of
                        (((Key => K ("handlers"),   Value => Handlers),
                          (Key => K ("operations"), Value => Operations),
                          (Key => K ("resources"),  Value => Resources)))))))));
   end Token_Of;

   function Wide_Token return Materialized_Entity is
     (Token_Of (Scope_Of (T1 ("*"), No_Strings),
                Scope_Of (T1 ("*"), No_Strings),
                Scope_Of (T1 ("*"), No_Strings)));

   --  A resource map {targets:[...]} (+ exclude when Excl is non-empty).
   function Resource_Of (Targets, Excl : Value_Vector) return Ecf_Value is
   begin
      if Excl'Length = 0 then
         return Map_Of ((1 => (Key => K ("targets"), Value => Array_Of (Targets))));
      end if;
      return Map_Of (((Key => K ("targets"), Value => Array_Of (Targets)),
                      (Key => K ("exclude"), Value => Array_Of (Excl))));
   end Resource_Of;

   function Exec_Of (Operation : String; Resource : Ecf_Value;
                     Params : Materialized_Entity := Wire.Empty_Params)
                     return Materialized_Entity is
     (Wire.Make_Execute ("r1", "system/tree", Operation, Params,
                         Resource => Resource));

   --  Drive the REAL dispatch chain, which is what makes the RULE G ordering
   --  claim an ordering claim: a test that called the tree handler directly has
   --  resolved the operation itself and cannot see a handler that validates the
   --  resource first.
   function Drive (Operation : String; Resource : Ecf_Value;
                   Token : Materialized_Entity;
                   With_Cap : Boolean := True;
                   Params : Materialized_Entity := Wire.Empty_Params)
                   return Materialized_Entity
   is
      Id   : constant Entity_Core.Protocol.Identity.Peer_Identity := Hand.Identity (Peer);
      Idh  : constant Byte_Array :=
        Byte_Array (Entity_Core.Protocol.Identity.Identity_Hash (Id));
      Conn : Hand.Conn_State;
      --  A FULLY SIGNED request: §5.2 demands a system/signature over the EXECUTE
      --  whose signer binds to `author`, and a chain whose root is self-issued by
      --  this peer. Anything less is refused at the verdict and every ladder
      --  assertion below would be reading a 401 rather than the handler.
      Exec : constant Materialized_Entity :=
        (if With_Cap
         then Wire.Make_Execute ("r1", "system/tree", Operation, Params,
                                 Author => Idh, Capability => Hash (Token),
                                 Resource => Resource)
         else Exec_Of (Operation, Resource, Params));
      E : Env_Pkg.Protocol_Envelope := Env_Pkg.Of_Root (Exec);
      Is_Resp : Boolean;
   begin
      if With_Cap then
         Env_Pkg.Add (E, Token);
         Env_Pkg.Add (E, Entity_Core.Protocol.Identity.Peer_Entity (Id));
         Env_Pkg.Add (E, Entity_Core.Protocol.Identity.Sign (Id, Token));
         Env_Pkg.Add (E, Entity_Core.Protocol.Identity.Sign (Id, Exec));
      end if;
      declare
         Resp : constant Env_Pkg.Protocol_Envelope :=
           Hand.Dispatch (Peer, Conn, E, Is_Resp);
         Found : Boolean;
         Res : constant Materialized_Entity := Wire.Response_Result (Resp, Found);
      begin
         --  The status is carried back on the response root; the caller reads
         --  both off the two accessors below.
         return Make ("test/probe",
           Map_Of (((Key => K ("status"),
                     Value => Make_Uint (Wire.Response_Status (Resp))),
                    (Key => K ("code"),
                     Value => Make_Text (if Found then Text (Res, "code") else "")),
                    (Key => K ("type"), Value => Make_Text (Type_Name (Res))),
                    (Key => K ("result"), Value => To_Cbor (Res)))));
      end;
   end Drive;

   function Status_Of (P : Materialized_Entity) return Unsigned_64 is
      F : Boolean;
   begin
      return Uint_Field (Data (P), "status", F);
   end Status_Of;

   function Code_Of (P : Materialized_Entity) return String is (Text (P, "code"));

begin
   Hand.Create (Peer, Seed, Open_Grants => False, Validate => False);
   Hand.Store (Peer).Bind ("/" & Local & "/app/a",
                           Make ("primitive/any",
                             Map_Of ((1 => (Key => K ("v"), Value => Make_Uint (1))))));
   Hand.Store (Peer).Bind ("/" & Local & "/app/b",
                           Make ("primitive/any",
                             Map_Of ((1 => (Key => K ("v"), Value => Make_Uint (2))))));

   ---------------------------------------------------------------------------
   Put_Line ("-- effective_targets: the two-empties discriminator (N11, 0.8.2.25) --");
   ---------------------------------------------------------------------------
   --  N11 makes the discriminator a [MUST]: "that projection MUST NOT be lossy
   --  about its own emptiness". This peer carries it as the Has_Resource
   --  out-parameter beside the survivors.
   declare
      Had : Boolean;
      V0 : constant Value_Vector :=
        Cap.Effective_Targets (Local, Exec_Of ("get", Make_Null), Had);
   begin
      Check ("absent resource reports absent", not Had and then V0'Length = 0);
   end;
   declare
      Had : Boolean;
      --  PINS THE SHIPPED ANSWER to an open question rather than endorsing it: a
      --  `resource` MAP with no `targets` key reads ABSENT on every 0.8.2.25 peer,
      --  while §3.2 says `targets` "MUST contain at least one entry" (i.e.
      --  malformed, not absent). No disposition is pinned and nothing in the
      --  check set drives it, so the behaviour is HELD, not changed.
      V : constant Value_Vector := Cap.Effective_Targets
        (Local, Exec_Of ("get",
           Map_Of ((1 => (Key => K ("exclude"), Value => Array_Of (T1 ("a")))))), Had);
   begin
      Check ("resource with no targets key reads absent", not Had and then V'Length = 0);
   end;
   declare
      Had : Boolean;
      V : constant Value_Vector := Cap.Effective_Targets
        (Local, Exec_Of ("get", Resource_Of (T1 ("a"), T1 ("a"))), Had);
   begin
      Check ("present-but-self-excluded is PRESENT with an empty list",
             Had and then V'Length = 0);
   end;
   declare
      Had : Boolean;
      --  0.8.2.21: effective_targets yields RAW survivors, not canonical forms —
      --  the value flows on to the store lookup, which canonicalizes for itself.
      V : constant Value_Vector := Cap.Effective_Targets
        (Local, Exec_Of ("get", Resource_Of (T2 ("app/x", "app/y"), T1 ("app/y"))), Had);
   begin
      Check ("survivors keep the caller's own spelling",
             Had and then V'Length = 1 and then As_Text (V (V'First)) = "app/x");
   end;
   declare
      Had : Boolean;
      --  §5.4's table rules the CALLER-exclude arm separately from the GRANT arm
      --  and in the opposite direction: Canonicalize answers the sentinel,
      --  Matches_Pattern answers False, and the target SURVIVES.
      V : constant Value_Vector := Cap.Effective_Targets
        (Local, Exec_Of ("get", Resource_Of (T1 ("app/a"), T1 ("../nope"))), Had);
   begin
      Check ("an unmatchable caller exclude is fail-OPEN: the target survives",
             Had and then V'Length = 1);
   end;

   ---------------------------------------------------------------------------
   Put_Line ("-- RULE G: operation resolution precedes resource validation --");
   ---------------------------------------------------------------------------
   --  "Resolve the operation first; only then run the §3.3 ladder." A peer that
   --  validates the resource first answers a RESOURCE fault for an OPERATION
   --  fault on every unknown operation (entity-system-conformance X9 / F52).
   --  ON THIS SUBSTRATE THE ORDERING IS STRUCTURAL: Dispatch_Inner's per-pattern
   --  ladder tests Operation and reaches Handle_Tree_Get/Put only for a known
   --  one, so the resource ladder cannot run ahead of it. Asserted anyway,
   --  because "it cannot happen" is a claim about today's dispatcher.
   declare
      No_Res  : constant Materialized_Entity :=
        Drive ("bogusop", Make_Null, Wide_Token);
      With_Res : constant Materialized_Entity :=
        Drive ("bogusop", Resource_Of (T1 ("app/a"), No_Strings), Wide_Token);
      Known   : constant Materialized_Entity :=
        Drive ("get", Resource_Of (T1 ("app/a"), No_Strings), Wide_Token);
   begin
      Check ("unknown op WITHOUT a resource is 501 unsupported_operation",
             Status_Of (No_Res) = 501 and then Code_Of (No_Res) = "unsupported_operation");
      --  THE CONTROL that makes this an ORDERING claim rather than a
      --  missing-501 claim: on the peers that had the defect these two differed.
      Check ("unknown op WITH a resource is the SAME 501",
             Status_Of (With_Res) = 501
               and then Code_Of (With_Res) = "unsupported_operation");
      --  ...or the two above are satisfied by a dispatcher that answers 501 to
      --  everything.
      Check ("a KNOWN operation still routes", Status_Of (Known) = 200);
   end;

   ---------------------------------------------------------------------------
   Put_Line ("-- the ladder, get (resource-OPTIONAL, BROAD-RESULT) --");
   ---------------------------------------------------------------------------
   --  EXTENSION-TREE §2.2a (v4.11) declares `get` resource-OPTIONAL and
   --  BROAD-RESULT: absent-case answer "the root listing", self-excluded case
   --  "400 path_required".
   declare
      R : constant Materialized_Entity := Drive ("get", Make_Null, Wide_Token);
   begin
      Check ("absent resource serves the root listing",
             Status_Of (R) = 200 and then Text (R, "type") = "system/tree/listing");
   end;
   declare
      --  THE TWO EMPTIES ARE DISTINCT, and this is the case that says so.
      --  Collapsing them serves the ROOT LISTING to a request that named one
      --  excluded path — wider than the request, which §3.3 forbids.
      R : constant Materialized_Entity :=
        Drive ("get", Resource_Of (T1 ("app/a"), T1 ("app/a")), Wide_Token);
   begin
      Check ("present-but-self-excluded is 400 path_required",
             Status_Of (R) = 400 and then Code_Of (R) = "path_required");
   end;
   declare
      Many : constant Materialized_Entity :=
        Drive ("get", Resource_Of (T2 ("app/a", "app/b"), No_Strings), Wide_Token);
      --  ...and the exclude is what makes the COUNT an effective-set count rather
      --  than a raw targets count: two targets, one excluded, ONE survivor.
      One  : constant Materialized_Entity :=
        Drive ("get", Resource_Of (T2 ("app/a", "app/b"), T1 ("app/b")), Wide_Token);
   begin
      Check ("more than one effective target is 400 ambiguous_resource",
             Status_Of (Many) = 400 and then Code_Of (Many) = "ambiguous_resource");
      Check ("one survivor of two targets proceeds", Status_Of (One) = 200);
   end;
   declare
      --  THE MUST 0.8.2.20 NAMES: a handler that counts the effective list and
      --  then indexes targets(1) has implemented the arithmetic completely and is
      --  still reading a path no authorization covered. targets(1) is EXCLUDED
      --  here and the single survivor is targets(2), so the two readings return
      --  DIFFERENT entities.
      R : constant Materialized_Entity :=
        Drive ("get", Resource_Of (T2 ("app/a", "app/b"), T1 ("app/a")), Wide_Token);
      Res : constant Materialized_Entity := Of_Cbor (Entity_Core.Protocol.Cbor_Util.Field (Data (R), "result"));
      F : Boolean;
   begin
      Check ("the selection is the SURVIVOR, never targets(1)",
             Status_Of (R) = 200 and then Uint_Field (Data (Res), "v", F) = 2);
   end;
   declare
      --  0.8.2.20: a resource-requiring operation takes a CONCRETE path. A
      --  trailing slash is a LISTING request and is not a pattern — only a star
      --  makes it one.
      Pat : constant Materialized_Entity :=
        Drive ("get", Resource_Of (T1 ("app/*"), No_Strings), Wide_Token);
      Lst : constant Materialized_Entity :=
        Drive ("get", Resource_Of (T1 ("app/"), No_Strings), Wide_Token);
   begin
      Check ("a pattern target is 400 malformed_resource",
             Status_Of (Pat) = 400 and then Code_Of (Pat) = "malformed_resource");
      Check ("a trailing slash is a listing, not a pattern",
             Status_Of (Lst) = 200
               and then Text (Lst, "type") = "system/tree/listing");
   end;

   ---------------------------------------------------------------------------
   Put_Line ("-- the ladder, put (resource-REQUIRED) --");
   ---------------------------------------------------------------------------
   declare
      --  THE CODE CHANGE 0.8.2.20 FORCED. This branch answered
      --  `ambiguous_resource` for a MISSING target, which 0.8.2.20 names as the
      --  exact inversion it forbids: the remedies differ — supply a resource is
      --  not disambiguate your request — and the code selects the remedy.
      Miss  : constant Materialized_Entity := Drive ("put", Make_Null, Wide_Token);
      --  BOTH empties collapse here: §2.2a declares `put` resource-REQUIRED.
      Empty : constant Materialized_Entity :=
        Drive ("put", Resource_Of (T1 ("app/a"), T1 ("app/a")), Wide_Token);
      --  ...and more than one survivor is still ambiguous_resource, which says
      --  the two codes have not simply been swapped.
      Many  : constant Materialized_Entity :=
        Drive ("put", Resource_Of (T2 ("app/a", "app/b"), No_Strings), Wide_Token);
   begin
      Check ("put with a MISSING target is 400 path_required",
             Status_Of (Miss) = 400 and then Code_Of (Miss) = "path_required");
      Check ("put with a self-excluded target is also 400 path_required",
             Status_Of (Empty) = 400 and then Code_Of (Empty) = "path_required");
      Check ("put with two effective targets is 400 ambiguous_resource",
             Status_Of (Many) = 400 and then Code_Of (Many) = "ambiguous_resource");
   end;

   ---------------------------------------------------------------------------
   Put_Line ("-- section 6.3: the handler-level path check (0.8.2.20) --");
   ---------------------------------------------------------------------------
   declare
      --  THE F84 LAYER. §6.3: "not a secondary check ... the sole enforcement
      --  wherever the subject is derived after dispatch."
      --
      --  WHICH RUNG ANSWERS THIS 403 WAS MEASURED, NOT ASSUMED, AND THE ANSWER IS
      --  BOTH. Planting each rung alone leaves this pair green: with §6.3's get
      --  check deleted the DISPATCH-level Check_Resource_Scope still refuses, and
      --  with Check_Resource_Scope vacated §6.3 still refuses. That is a real
      --  property of this peer rather than a weak test -- its dispatch check
      --  requires every non-caller-excluded target to be covered, so for a SCALAR
      --  get the handler's derived path is always a path dispatch already saw, and
      --  the two rungs are independently sufficient.
      --
      --  So this pair asserts the COMPOSED behaviour and names the rungs; the
      --  arm where §6.3 is the ONLY thing standing is the LISTING, whose entries
      --  the dispatch check never sees, and that is measured below and is where
      --  the plant bites. Saying which rung the wire observes is the whole of the
      --  "two sites for one refusal" rule.
      Narrow : constant Materialized_Entity :=
        Token_Of (Scope_Of (T1 ("*"), No_Strings),
                  Scope_Of (T1 ("*"), No_Strings),
                  Scope_Of (T1 ("*"), T1 ("app/b")));
      Denied : constant Materialized_Entity :=
        Drive ("get", Resource_Of (T1 ("app/b"), No_Strings), Narrow);
      --  CONTROL, in the SAME capability: a path the same grant covers is served.
      Ok_One : constant Materialized_Entity :=
        Drive ("get", Resource_Of (T1 ("app/a"), No_Strings), Narrow);
   begin
      Check ("get on an excluded path is 403 capability_denied",
             Status_Of (Denied) = 403 and then Code_Of (Denied) = "capability_denied");
      Check ("get on a covered path under the SAME cap is 200",
             Status_Of (Ok_One) = 200);
   end;
   declare
      --  The unit-level form, reached directly so the three dimensions can be
      --  moved one at a time. A predicate test built only from DENY cases is
      --  indistinguishable from one asserting False = False, so the accept case
      --  is what validates the fixture.
      Wide : constant Materialized_Entity := Wide_Token;
      Ops  : constant Materialized_Entity :=
        Token_Of (Scope_Of (T1 ("*"), No_Strings),
                  Scope_Of (T1 ("put"), No_Strings),
                  Scope_Of (T1 ("*"), No_Strings));
      Hnd  : constant Materialized_Entity :=
        Token_Of (Scope_Of (T1 ("system/other"), No_Strings),
                  Scope_Of (T1 ("*"), No_Strings),
                  Scope_Of (T1 ("*"), No_Strings));
      Empty_Incl : constant Materialized_Entity :=
        Token_Of (Scope_Of (T1 ("*"), No_Strings),
                  Scope_Of (T1 ("*"), No_Strings),
                  Scope_Of (No_Strings, No_Strings));
   begin
      Check ("check_path_permission ACCEPTS under a wide grant",
             Cap.Check_Path_Permission (Local, "get", "app/a", Wide, "system/tree"));
      Check ("check_path_permission denies on the OPERATIONS dimension",
             not Cap.Check_Path_Permission (Local, "get", "app/a", Ops, "system/tree"));
      Check ("check_path_permission denies on the HANDLERS dimension",
             not Cap.Check_Path_Permission (Local, "get", "app/a", Hnd, "system/tree"));
      --  An empty resources.include is a LEGAL grant shape (§5.2) and denies every
      --  path here, which is what that note says it should.
      Check ("an empty resources include denies every path",
             not Cap.Check_Path_Permission
                   (Local, "get", "app/a", Empty_Incl, "system/tree"));
      --  Canonicalize is TOTAL and answers the sentinel, which matches no grant,
      --  so a malformed path falls through to DENY rather than being matched.
      Check ("a malformed path denies even under a wide grant",
             not Cap.Check_Path_Permission
                   (Local, "get", "../escape", Wide, "system/tree"));
   end;

   ---------------------------------------------------------------------------
   Put_Line ("-- section 6.3: the listing filter (0.8.2.21/.22) --");
   ---------------------------------------------------------------------------
   declare
      --  "Entries for which check_path_permission returns DENY MUST be omitted.
      --  The result's `count` field MUST reflect the FILTERED entry count." A
      --  count that still reported the source total IS the disclosure the rule
      --  exists to prevent, so it is asserted separately from the entry map.
      Narrow : constant Materialized_Entity :=
        Token_Of (Scope_Of (T1 ("*"), No_Strings),
                  Scope_Of (T1 ("*"), No_Strings),
                  Scope_Of (T1 ("*"), T1 ("app/b")));
      R : constant Materialized_Entity :=
        Drive ("get", Resource_Of (T1 ("app/"), No_Strings), Narrow);
      Res : constant Materialized_Entity := Of_Cbor (Entity_Core.Protocol.Cbor_Util.Field (Data (R), "result"));
      Entries : constant Ecf_Value :=
        Entity_Core.Protocol.Cbor_Util.Field (Data (Res), "entries");
      F : Boolean;
   begin
      Check ("the listing omits the entry the caller's cap excludes",
             Status_Of (R) = 200 and then Map_Length (Entries) = 1);
      Check ("the listing count follows the FILTER, not the source total",
             Uint_Field (Data (Res), "count", F) = 1);
   end;
   declare
      --  The differential that attributes the row above to the FILTER rather than
      --  to the store or the directory: same directory, a grant that covers both,
      --  both entries.
      R : constant Materialized_Entity :=
        Drive ("get", Resource_Of (T1 ("app/"), No_Strings), Wide_Token);
      Res : constant Materialized_Entity := Of_Cbor (Entity_Core.Protocol.Cbor_Util.Field (Data (R), "result"));
      Entries : constant Ecf_Value :=
        Entity_Core.Protocol.Cbor_Util.Field (Data (Res), "entries");
      F : Boolean;
   begin
      Check ("a wide capability sees both entries", Map_Length (Entries) = 2);
      Check ("...and the count agrees", Uint_Field (Data (Res), "count", F) = 2);
   end;
   declare
      --  THE FILTER NARROWS ON AN *INCLUDE* TOO, not only on an exclude. The two
      --  cases above both narrow with `exclude`, and a filter that only consulted
      --  the exclude list would pass both; this one covers the directory and one
      --  child and says nothing about the other.
      --
      --  SAY WHAT IS *NOT* ASSERTED HERE AND WHY. §6.3's "the DIRECTORY itself is
      --  deliberately not checked -- each ENTRY is the subject" is NOT separately
      --  observable through the dispatch chain on this peer: the dispatch-level
      --  check already requires the caller's grant to cover the listing TARGET, so
      --  a grant covering only `app/a` is refused at §5.2 before any listing is
      --  built, and a grant that does cover `app/` cannot distinguish a filter that
      --  checks the prefix from one that does not. The property is real and is
      --  enforced in Build_Listing (the per-entry call is on the CHILD path); it is
      --  recorded here as not-driven rather than asserted by a case that would pass
      --  either way.
      Dir_And_A : constant Materialized_Entity :=
        Token_Of (Scope_Of (T1 ("*"), No_Strings),
                  Scope_Of (T1 ("*"), No_Strings),
                  Scope_Of (T2 ("app/", "app/a"), No_Strings));
      R : constant Materialized_Entity :=
        Drive ("get", Resource_Of (T1 ("app/"), No_Strings), Dir_And_A);
      Res : constant Materialized_Entity :=
        Of_Cbor (Entity_Core.Protocol.Cbor_Util.Field (Data (R), "result"));
      Entries : constant Ecf_Value :=
        Entity_Core.Protocol.Cbor_Util.Field (Data (Res), "entries");
      F : Boolean;
   begin
      Check ("the filter narrows on an INCLUDE as well as on an exclude",
             Status_Of (R) = 200 and then Map_Length (Entries) = 1);
      Check ("...and the count follows it",
             Uint_Field (Data (Res), "count", F) = 1);
   end;

   ---------------------------------------------------------------------------
   Put_Line ("-- section 5.4: the sentinel is scoped to path-scope (0.8.2.24 N2/N3) --");
   ---------------------------------------------------------------------------
   --  §5.4 at 0.8.2.24: "a capability carrying an unmatchable PATH-SCOPE pattern
   --  is INVALID ... It does NOT reach `operations` or `peers` [MUST]". The
   --  un-scoped form we shipped at 0.8.2.21 ran an id pattern through the §5.4
   --  PATH transforms purely to classify it and then denied the WHOLE dimension.
   declare
      Star_Apply : constant String := "*" & "/apply";
   begin
      Check ("the id-scope witness really does path-canonicalize to the sentinel",
             Cap.Canonicalize (Local, Star_Apply) = "/never-match");
      --  Driven through check_path_permission, which is a real call site of
      --  Matches_Scope on all three dimensions.
      Check ("an operations exclude that canonicalizes to the sentinel does NOT deny",
             Cap.Check_Path_Permission
               (Local, "get", "app/a",
                Token_Of (Scope_Of (T1 ("*"), No_Strings),
                          Scope_Of (T1 ("*"), T1 (Star_Apply)),
                          Scope_Of (T1 ("*"), No_Strings)),
                "system/tree"));
      --  THE CONTROL that says the fix SCOPED the guard rather than deleting it:
      --  on a PATH-scope dimension an unmatchable exclude must still DENY, or the
      --  grant is silently wider than its author wrote.
      Check ("the same exclude on a PATH-scope dimension still denies (0.8.2.21)",
             not Cap.Check_Path_Permission
                   (Local, "get", "app/a",
                    Token_Of (Scope_Of (T1 ("*"), No_Strings),
                              Scope_Of (T1 ("*"), No_Strings),
                              Scope_Of (T1 ("*"), T1 (Star_Apply))),
                    "system/tree"));
      --  ...and an ordinary MATCHABLE exclude still excludes on the id dimension,
      --  or the accept case above is satisfied by a dimension nobody checks.
      Check ("a matchable operations exclude still excludes",
             not Cap.Check_Path_Permission
                   (Local, "get", "app/a",
                    Token_Of (Scope_Of (T1 ("*"), No_Strings),
                              Scope_Of (T1 ("*"), T1 ("get")),
                              Scope_Of (T1 ("*"), No_Strings)),
                    "system/tree"));
   end;

   ---------------------------------------------------------------------------
   Put_Line ("-- section 5.5a: scope_subset is typed by scope kind (F50, 0.8.2.16) --");
   ---------------------------------------------------------------------------
   --  §3.6's grammar binds the SCOPE TYPE, not one function: "An implementation
   --  on the canonicalizing reading is non-conformant and MUST adopt the literal
   --  matcher." F40 typed Matches_Scope; its §5.5a sibling was left on the path
   --  matcher for all four dimensions. The divergence is narrow and FAIL-CLOSED,
   --  which is exactly why no hand-tried example found it.
   --
   --  Driven through Grants_Are_Subset, the public §6.2 mint-bound call site — a
   --  test of the private helper would prove it CAN dispatch and say nothing
   --  about whether the four dimensions NAME their kind.
   declare
      Star_Apply : constant String := "*" & "/apply";
      function Grants1 (H, O, R : Ecf_Value) return Ecf_Value is
        (Array_Of ((1 => Map_Of (((Key => K ("handlers"),   Value => H),
                                  (Key => K ("operations"), Value => O),
                                  (Key => K ("resources"),  Value => R))))));
      Wide : constant Ecf_Value := Scope_Of (T1 ("*"), No_Strings);
   begin
      --  The formalization's two witnesses, on the OPERATIONS (id-scope)
      --  dimension. Under the path matcher the parent canonicalizes to
      --  /{parent}/* and the child to the sentinel, so both were refused.
      Check ("an operations include the ID matcher covers is a subset of a bare star",
             Cap.Grants_Are_Subset
               (Local, Grants1 (Wide, Scope_Of (T1 (Star_Apply), No_Strings), Wide),
                       Grants1 (Wide, Wide, Wide)));
      Check ("the second witness: an absolute-looking operation name under a star",
             Cap.Grants_Are_Subset
               (Local, Grants1 (Wide, Scope_Of (T1 ("/tree/get"), No_Strings), Wide),
                       Grants1 (Wide, Wide, Wide)));
      --  THE DIFFERENTIAL that attributes the two rows above to the scope TYPE
      --  rather than to Grants_Are_Subset having been loosened: `resources` is
      --  path-scope, so the same two patterns are still refused there.
      Check ("the SAME two patterns on RESOURCES are still path-matched (refused)",
             not Cap.Grants_Are_Subset
                   (Local, Grants1 (Wide, Wide, Scope_Of (T1 (Star_Apply), No_Strings)),
                           Grants1 (Wide, Wide, Wide))
             and then not Cap.Grants_Are_Subset
                   (Local, Grants1 (Wide, Wide, Scope_Of (T1 ("/tree/get"), No_Strings)),
                           Grants1 (Wide, Wide, Wide)));
      --  ...and an operations include NO parent include covers is still refused,
      --  or the accept rows are satisfied by a dimension that stopped being
      --  checked at all.
      Check ("an operations include no parent include covers is still refused",
             not Cap.Grants_Are_Subset
                   (Local, Grants1 (Wide, Scope_Of (T1 ("put"), No_Strings), Wide),
                           Grants1 (Wide, Scope_Of (T1 ("get"), No_Strings), Wide)));
   end;

   ---------------------------------------------------------------------------
   Put_Line ("-- section 4.11: the CODE belongs to the CAUSE (0.8.2.25) --");
   ---------------------------------------------------------------------------
   --  "The frame obligation belongs to the class; the CODE belongs to the cause
   --  [MUST]". Before 0.8.2.24 this peer answered 400 non_canonical_ecf for every
   --  one of these, which is the code-under-the-wrong-reason defect §5.2a names.
   --
   --  Each row RAISES its exception and classifies the live occurrence, because
   --  the classifier dispatches on Exception_Identity and a synthesized
   --  Exception_Occurrence would not exercise that.
   declare
      procedure Row (Name : String; Want : Wire.Pre_Admission_Cause;
                     Want_Status : Unsigned_64; Want_Code : String;
                     Raiser : access procedure) is
      begin
         Raiser.all;
         Check (Name & " (the raise did not happen)", False);
      exception
         when X : others =>
            Check (Name,
                   Wire.Classify_Pre_Admission (X) = Want
                     and then Wire.Refusal_Status (Want) = Want_Status
                     and then Wire.Refusal_Code (Want) = Want_Code);
      end Row;

      procedure R_Oversize is
      begin
         raise Entity_Core.Errors.Payload_Too_Large with "x";
      end R_Oversize;
      procedure R_Hash is
      begin
         raise Entity_Core.Errors.Hash_Mismatch with "x";
      end R_Hash;
      procedure R_Tag is
      begin
         raise Entity_Core.Errors.Tag_Rejected with "x";
      end R_Tag;
      procedure R_Trunc is
      begin
         raise Entity_Core.Errors.Truncated_Input with "x";
      end R_Trunc;
      procedure R_NonCanon is
      begin
         raise Entity_Core.Errors.Non_Canonical_Ecf with "x";
      end R_NonCanon;
      procedure R_Proto is
      begin
         raise Entity_Core.Errors.Protocol_Error with "x";
      end R_Proto;
      Rows : constant Natural := 6;
   begin
      Row ("413 payload_too_large is the oversize cause",
           Wire.Cause_Oversize, 413, "payload_too_large", R_Oversize'Access);
      Row ("400 hash_mismatch is the resolution-integrity cause",
           Wire.Cause_Hash_Mismatch, 400, "hash_mismatch", R_Hash'Access);
      Row ("400 non_canonical_ecf is the TAG-POLICY cause and only that one",
           Wire.Cause_Tag_Policy, 400, "non_canonical_ecf", R_Tag'Access);
      Row ("400 invalid_request is the framing cause (truncated)",
           Wire.Cause_Framing, 400, "invalid_request", R_Trunc'Access);
      --  The row that makes the split load-bearing: a non-minimal head is
      --  "non-canonical CBOR" BY NAME and is NOT the tag-policy arm.
      Row ("400 invalid_request is the framing cause (non-canonical, not a tag)",
           Wire.Cause_Framing, 400, "invalid_request", R_NonCanon'Access);
      Row ("400 invalid_request is the framing cause (protocol shape)",
           Wire.Cause_Framing, 400, "invalid_request", R_Proto'Access);
      Check ("examined the whole table", Rows = 6);
   end;
   declare
      --  Which read failures are owed a frame AT ALL. A closed or reset socket is
      --  not a refusal of anything and there is nobody left to answer.
      procedure Probe (Want : Boolean; Name : String; Raiser : access procedure) is
      begin
         Raiser.all;
         Check (Name & " (the raise did not happen)", False);
      exception
         when X : others =>
            Check (Name, Wire.Is_Framing_Refusal (X) = Want);
      end Probe;
      procedure R_Oversize is
      begin
         raise Entity_Core.Errors.Payload_Too_Large with "x";
      end R_Oversize;
      procedure R_Trunc is
      begin
         raise Entity_Core.Errors.Truncated_Input with "x";
      end R_Trunc;
      procedure R_Transport is
      begin
         raise Entity_Core.Errors.Transport_Error with "reset";
      end R_Transport;
   begin
      Probe (True,  "an oversize prefix IS a framing refusal", R_Oversize'Access);
      Probe (True,  "a truncated frame IS a framing refusal", R_Trunc'Access);
      Probe (False, "a reset socket is NOT a refusal", R_Transport'Access);
   end;
   declare
      --  A wire-visible message is ASCII-only (the ratified discipline: two peers,
      --  two unrelated compilers, one failure shape).
      All_Ascii : Boolean := True;
   begin
      for C in Wire.Pre_Admission_Cause loop
         for Ch of Wire.Refusal_Message (C) loop
            if Character'Pos (Ch) > 127 then
               All_Ascii := False;
            end if;
         end loop;
         for Ch of Wire.Refusal_Code (C) loop
            if Character'Pos (Ch) > 127 then
               All_Ascii := False;
            end if;
         end loop;
      end loop;
      Check ("every refusal code and message is ASCII", All_Ascii);
   end;

   ---------------------------------------------------------------------------
   Put_Line ("-- section 4.11: the decode boundary raises the CAUSE's identity --");
   ---------------------------------------------------------------------------
   declare
      --  The arc-probe B1/B2 input: a mis-keyed `included` entry. Its ENCODING is
      --  canonical; what is false is the claim the KEY makes, so the remedy
      --  `non_canonical_ecf` selects (re-encode) sends an honest caller to the
      --  wrong layer.
      Good : constant Materialized_Entity :=
        Make ("primitive/any", Map_Of ((1 => (Key => K ("x"), Value => Make_Uint (1)))));
      Bad_Key : constant Byte_Array (1 .. 33) := (others => 16#11#);
      M : constant Ecf_Value :=
        Map_Of (((Key => K ("root"),
                  Value => To_Cbor (Wire.Make_Execute
                    ("t1", "system/tree", "get", Wire.Empty_Params))),
                 (Key => K ("included"),
                  Value => Map_Of
                    ((1 => (Key => Make_Bytes (Bad_Key), Value => To_Cbor (Good)))))));
      Caught : Wire.Pre_Admission_Cause := Wire.Cause_Framing;
      Threw  : Boolean := False;

      --  AN EXCEPTION RAISED IN A BLOCK'S DECLARATIVE PART PROPAGATES PAST THAT
      --  BLOCK'S OWN HANDLER -- Ada's rule, and it cost this file a run: written
      --  as `declare E : ... := Of_Cbor (M); begin null; exception when ...`, the
      --  refusal escaped to the outer frame and killed the suite instead of being
      --  classified. The call goes in a STATEMENT, inside a procedure whose body
      --  can handle it.
      procedure Try is
         E : Env_Pkg.Protocol_Envelope;
      begin
         E := Env_Pkg.Of_Cbor (M);
         pragma Unreferenced (E);
      exception
         when X : others =>
            Threw := True;
            Caught := Wire.Classify_Pre_Admission (X);
      end Try;
   begin
      Try;
      Check ("a mis-keyed included entry is refused", Threw);
      Check ("...and it classifies as hash_mismatch, not non_canonical_ecf",
             Caught = Wire.Cause_Hash_Mismatch);
   end;
   declare
      --  The same obligation one level down: an entity whose CARRIED content_hash
      --  does not bind to {type, data}.
      Good : constant Materialized_Entity :=
        Make ("primitive/any", Map_Of ((1 => (Key => K ("x"), Value => Make_Uint (1)))));
      Bad : constant Byte_Array (1 .. 33) := (others => 16#22#);
      M : constant Ecf_Value :=
        Map_Of (((Key => K ("type"), Value => Make_Text (Type_Name (Good))),
                 (Key => K ("data"), Value => Data (Good)),
                 (Key => K ("content_hash"), Value => Make_Bytes (Bad))));
      Caught : Wire.Pre_Admission_Cause := Wire.Cause_Framing;
      Threw  : Boolean := False;

      --  Same declarative-part rule as above: the call is a STATEMENT.
      procedure Try is
         E : Materialized_Entity;
      begin
         E := Of_Cbor (M);
         pragma Unreferenced (E);
      exception
         when X : others =>
            Threw := True;
            Caught := Wire.Classify_Pre_Admission (X);
      end Try;
   begin
      Try;
      Check ("a non-binding carried content_hash is refused", Threw);
      Check ("...and it classifies as hash_mismatch", Caught = Wire.Cause_Hash_Mismatch);
   end;

   ---------------------------------------------------------------------------
   Put_Line ("-- section 6.5 N12/N17: a non-EXECUTE root is ANSWERED, not dropped --");
   ---------------------------------------------------------------------------
   declare
      --  §6.5's "Other type?" arm, as rewritten at 0.8.2.25: "400 invalid_request,
      --  coded frame; MAY then close. NOT a bare close -- that is
      --  indistinguishable from a network fault." This peer did something weaker
      --  still: Is_Response False, and the reader wrote NOTHING while keeping the
      --  connection open -- §4.11's silent drop.
      Conn : Hand.Conn_State;
      Root : constant Materialized_Entity :=
        Make ("primitive/any",
              Map_Of ((1 => (Key => K ("request_id"), Value => Make_Text ("x-1")))));
      E : constant Env_Pkg.Protocol_Envelope := Env_Pkg.Of_Root (Root);
      Is_Resp : Boolean;
      Resp : constant Env_Pkg.Protocol_Envelope := Hand.Dispatch (Peer, Conn, E, Is_Resp);
      Found : Boolean;
      Res : constant Materialized_Entity := Wire.Response_Result (Resp, Found);
   begin
      Check ("a non-EXECUTE root produces a response the reader will write", Is_Resp);
      Check ("...with status 400", Wire.Response_Status (Resp) = 400);
      Check ("...and code invalid_request",
             Found and then Text (Res, "code") = "invalid_request");
      --  request_id is read BEST-EFFORT and correlated when the root carries one.
      Check ("...correlated by the root's own request_id where it has one",
             Text (Resp.Root, "request_id") = "x-1");
   end;

   New_Line;
   Put_Line ("== peer self-tests:" & Natural'Image (Passed) & " passed,"
             & Natural'Image (Failed) & " failed, of" & Natural'Image (Checked)
             & " examined ==");

   --  A GATE THAT EXAMINED ZERO THINGS PRINTS THE SAME WORD AS ONE THAT EXAMINED
   --  FORTY. The floor is asserted so a dropped block or a short-circuited run is
   --  a RED, not a silent green.
   if Checked < 45 then
      Put_Line ("  FAIL: examined" & Natural'Image (Checked)
                & " checks, floor is 45 -- the suite did not fully run");
      Failed := Failed + 1;
   end if;

   if Failed > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   else
      Ada.Command_Line.Set_Exit_Status (0);
   end if;
exception
   when X : others =>
      Put_Line ("  FAIL: the suite itself raised: "
                & Ada.Exceptions.Exception_Information (X));
      Ada.Command_Line.Set_Exit_Status (1);
end Run_Peer_Tests;
