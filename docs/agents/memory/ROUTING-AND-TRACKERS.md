# Routing and trackers — keystone memory

Packets out, packets in, and what a claim from another repo is worth until you have re-derived it.

**Arrive here when:** you are sending a packet, reconciling a tracker, or about to act on something a counterpart told you.

Durable findings, not status — each entry names what happens, the mechanism behind it, and
the enforcement point. Moved verbatim out of `AGENTS.md`; the live trackers are
`docs/status/TRACKER-*.md` and the packets are `docs/outbox/`. See [`INDEX.md`](INDEX.md).

## Entries

- A ROUTED SOURCE CENSUS CAN BE EXACTLY RIGHT, AND SAYING SO IS AS IMPORTANT AS A CORRECTION
- A ROUTED LIST THAT DISAGREES WITH YOUR OWN RECOMPUTATION BY THREE FILES IS A FINDING, NOT A ROUNDING ERROR
- VERIFY A ROUTED CLAIM BEFORE ACTING ON IT, ESPECIALLY THE EXCULPATORY HALF — a packet's parenthetical "we checked, this one doesn't apply to you" is the sentence most likely to be wrong and least likely to be re-checked
- AUDITING OUR OWN RULING FOUND A COHORT-WIDE BYPASS IN ALL THREE GROUND-UP IMPLEMENTATIONS
- RE-DERIVE A COUNTERPART'S SELF-REPORTED RED NUMBER — AND WHEN IT MATCHES TO THE DIGIT, SAY SO, BECAUSE THAT IS WHAT MAKES THE REST OF THEIR NUMBERS WORTH READING
- A REGISTER THAT RECORDS NON-RECEIPT WITHOUT EVER RE-CHECKING IT CONVERTS A TEN-MINUTE READ INTO A STANDING ROW
- RATIFIED, and it BROADENS the routed-claim rule: the exculpation most likely to be wrong is the one WE wrote, because nothing routes it back for review
- A PACKET NOBODY ENUMERATES IS A PACKET NOBODY RECEIVES — one TRACKER per counterpart, at a predictable path, edited in place
- THE WATERMARK EARNED ITSELF ON ITS FIRST RUN, AND TWO COUNTERPART CHECKOUTS WERE BEHIND
- FOURTH OCCURRENCE — SIX SEATS TRACKED US AND WE KEPT FIVE, AND THE TWO MISSING BOTH HAD OPEN ITEMS

---

- **A ROUTED SOURCE CENSUS CAN BE EXACTLY RIGHT, AND SAYING SO IS AS IMPORTANT AS A CORRECTION.**
  Same session. `entity-core-formalization` censused 46 peers by reading source, explicitly flagged
  it as unmeasured, and left 11 unresolved. Measuring all 45 buildable peers found **zero
  disagreements across the 34 they committed to**. The standing rule to re-verify a routed claim
  exists for *calibration in both directions* — the point is that the check is cheap and answers
  directly, not that packets are unreliable — and a rule only ever exercised on the miss quietly
  becomes "distrust the sender." Record the corroboration with the same weight as a catch.
  What the measurement DID add is the part a source read structurally cannot reach: the 11
  unresolved, and the sequence-distinguished dimension above, which needs each peer's behaviour on
  *two* inputs. **Prefer measuring what a source read cannot see over re-deriving what it already
  got right.**

- **A ROUTED LIST THAT DISAGREES WITH YOUR OWN RECOMPUTATION BY THREE FILES IS A FINDING, NOT A
  ROUNDING ERROR.** 2026-08-24: DevOps sent a 119-file strip list; recomputing it here gave
  **122** — the delta was three `.sh` files under `research/diagnostics/`. Chasing that gap is
  what surfaced that `canon-filter` had been **corrected to prose-only** on 2026-08-23 and that
  our documented scope statement had been false ever since (see the keep-list entry above).
  **Neither list was wrong about its own tool; ours was wrong about a tool that had changed.**
  Enforcement, and it is cheap: **recompute any supplied inventory and diff it** — the diff is
  the question worth asking, and a zero diff is a corroboration worth having. Pairs with the
  routed-claim rule below: this is the same discipline applied to a *list* rather than a *claim*.

- **VERIFY A ROUTED CLAIM BEFORE ACTING ON IT, ESPECIALLY THE EXCULPATORY HALF — a packet's
  parenthetical "we checked, this one doesn't apply to you" is the sentence most likely to be
  wrong and least likely to be re-checked.** Same session, first occurrence, candidate. The
  routing packet listed **seven** at-risk files and added *"(`RESOURCE-CAPS.md` was named in the
  original fleet-wide finding. Checked: it is **not** on your public `master`, so it does not
  apply to you.)"* It **is** on our public `master` — confirmed identical across `origin`,
  `github` and `codeberg` at `d8c2b0a` — and the release pipeline's own source comment says so
  outright (*"and keystone `RESOURCE-CAPS.md`"*, `dev-pipeline/promote/promote.sh`). Acting on
  the packet as written would have shipped a release that **deleted a published file**, and the
  exemption is precisely the part a reader skims. The general form pairs with A1 (trace a value
  before you theorize): **an inbound claim that reduces your work is still an inbound claim.**
  Enforcement is the simulation above — one command, answers the question directly, and needs no
  trust in anyone's list.
  **Re-run 2026-08-23 on the next packet, and this time the routed claim held — record that too,
  or the rule degenerates into "distrust the sender."** The follow-up packet named two internal-
  token leaks on the publishable surface (`protocol-generator/shared/lifecycle/ORCHESTRATION.md`
  naming the coordination repo as *"the canonical source"*, and one line in the P-1 finding).
  Running the check ourselves — a case-insensitive `git grep -E` for every literal in
  `leak-audit`'s `internal-tokens.local` denylist (the coordination-repo name, the build-host
  name, the ops host and the ops address; read them from that file, and **do not transcribe them
  into a committed document** — the leak-detector's own denylist must not become a leak, which
  this paragraph got wrong on its first draft and its own scan caught) over the whole tree minus
  `docs/status`, `docs/archive` and the injected ADRs — returned **those two and nothing else.**
  Both were fixed with the packet's own corrected copies. **What the
  verification is for is calibration in both directions:** the point is that the check is cheap
  and answers directly, not that packets are unreliable. One line, two minutes, and it either
  corroborates the sender or catches the thing they skimmed.

- **AUDITING OUR OWN RULING FOUND A COHORT-WIDE BYPASS IN ALL THREE GROUND-UP IMPLEMENTATIONS.**
  Recorded 2026-09-10 as the payout of the standing *"the exculpation most likely to be wrong is
  the one WE wrote"* rule, extended to rulings. We proposed γ (PD-2 gate 1a) and it was folded at
  `0.8.2.17`; auditing it three days later found that it **relocated** the handler-grant ceiling
  rather than keeping it, and that in the shape it was written for the credential is
  **caller-supplied**. Arch folded the correction as `0.8.2.19` and `entity-core-go` reports the
  bypass was *"cohort-wide — rust and py carry the identical bypass."* **A ruling you authored and
  a sibling adopted is not evidence it is right; it is three seats sharing one unexamined argument.**
  The tell to look for is a defense that bounds the wrong party — γ's was *"a caller can steer the
  handler only toward peers that have already granted this peer something,"* which bounds the
  TARGET's exposure and says nothing about the HANDLER's authority.

- **RE-DERIVE A COUNTERPART'S SELF-REPORTED RED NUMBER — AND WHEN IT MATCHES TO THE DIGIT, SAY SO,
  BECAUSE THAT IS WHAT MAKES THE REST OF THEIR NUMBERS WORTH READING.** 2026-09-16, and it is the
  standing *verify-a-routed-claim* rule pointed at the flattering direction for the third time. Auditing
  arch, the temptation is to audit the claims that favour them. The higher-yield move was to re-derive
  the number that **damns** them: their board's `A-16` says `spec standards --scope published-narrative`
  is RED at **38 errors**, three of the four files being that week's own proposals landed without the
  gate being run. Run against their tree: **38 errors, 0 warnings**, matching to the digit. Likewise
  their citation of OUR instrument (`scope-cell-table.py --summary`: `640 → −320 → −32 → −16 → −126 →
  146`, 37 named-vector / 109 unmeasured / 32 ruled-but-ungated / 1 DEFECT) reproduces exactly, and
  `0.8.2.30`'s fold reached **all four** homes it names with §6.7 already consistent.
  **The rule: a seat that reports its own red count accurately has earned a different prior than one
  that does not, and the only way to know which you are dealing with is to re-derive the red one.** A
  correction landed against a counterpart who is accurate about their own failures is worth more than
  ten against one who is not — and recording the corroboration is what stops the audit degenerating
  into *"distrust the sender"*.

- **A REGISTER THAT RECORDS NON-RECEIPT WITHOUT EVER RE-CHECKING IT CONVERTS A TEN-MINUTE READ INTO
  A STANDING ROW.** RATIFIED 2026-09-16, and it is the tracker convention's own failure mode rather
  than a counterpart's. Three of our four outbound asks to `entity-core-formalization` (`A-1`, `A-2`,
  `A-3`) had been **answered on 2026-09-06** in a packet sitting in their tree, and sat in our Open
  column for **ten days**. Our own delivery note said *"receipt not established"* — which was true
  when written, and which we treated as **a state to record rather than a question to resolve.**
  They closed it for us, correctly calling it *"a receipt gap, not a work gap, which is the cheaper
  kind and the kind neither of us can see from inside our own tree."*
  **The shape generalizes past trackers: `not established` is the one status that never expires on
  its own.** An open ASK gets re-read every time someone looks for work; a `pending receipt` row
  reads as in-flight forever, and the thing that would clear it is a read of someone else's tree
  that nobody is scheduled to do. **Enforcement: every `Delivery state: not established` row carries
  the command that would settle it, and that command is run when the tracker is reconciled** — not
  when the packet is sent. For us that is one `ls`/`grep` in the counterpart's `docs/status/`.
  *(Their `INBOUND.md` has the mirror-image half — it reads sibling trees for packets addressed to
  them and never checks whether their own answers LANDED — and they named it first. **A register
  with no memory reports absence of a row as absence of the work, in whichever direction it is
  pointed.**)*

- **RATIFIED, and it BROADENS the routed-claim rule: the exculpation most likely to be wrong is the
  one WE wrote, because nothing routes it back for review.** Second occurrence 2026-08-30, in the
  same session as the `apl` exclusion below — which is the same defect wearing a different hat. The
  standing rule (*"verify a routed claim before acting on it, especially the exculpatory half"*)
  only ever pointed at **inbound** claims from a sibling repo. Both of this session's findings were
  self-authored exculpations that had never been re-read:
  - `CONFORMANCE-MATRIX.md` §3 carried `authz_peers_target_from_uri` for two weeks as *"WARN on
    every peer · **Low — inconclusive by design** · a single standalone peer cannot resolve
    `target_peer` against a synthetic foreign URI; needs a real two-peer harness. Not attempted
    since it was found 2026-08-16."* Measured: **40 WARN, 6 PASS**. The six return a full three-row
    verdict, so a standalone peer decides it fine and no harness was ever needed. The real split is
    one line of routing (a `!= localPeer → 404 handler_not_found` gate ahead of handler resolution),
    it is a **spec ambiguity worth a handoff**, and the phrase "inconclusive by design" had been
    doing the work of a decision nobody made.
  - `apl`'s `UNMEASURABLE — upstream-blocked` (below).
  **Both were single-command questions.** The severity-diff that answered the first is the standing
  highest-yield diagnostic in this file, applied to a *check* instead of a *peer*:
  `for each report → severity of check X`, then look at what the two groups have in common. **Rule:
  a row that explains why something CANNOT be measured, or need not be, is a claim — date it, name
  the command that would refute it, and re-run that command before citing the row.** A row asserting
  work is *owed* gets re-read every time someone looks for work; a row asserting work is *excused*
  is read once and never again, which is exactly backwards from how often each is wrong.

- **A PACKET NOBODY ENUMERATES IS A PACKET NOBODY RECEIVES — one TRACKER per counterpart, at a
  predictable path, edited in place.** Ecosystem convention, adopted 2026-09-09 on arch's
  `SEAT-CLEANUP-INSTRUCTIONS-2026-09-09.md`. **`docs/status/TRACKER-<counterpart-repo>.md`**, four
  sections — *Open — asks* (stable ids, **one sentence naming what must be decided**, the packet's
  FULL stem, and the *kind* of answer) · *Corrections we owe them* · *Filed, nothing owed back to
  us* · *Closed*. **FOUR today** — `entity-system-architecture`, `entity-system-generator`,
  `entity-core-formalization`, `entity-system-conformance`.
  **RATIFIED 2026-09-15 — THE FOURTH WAS MISSING FOR THREE DAYS, AND THE ENFORCEMENT CLAUSE IN THIS
  VERY ENTRY IS STRUCTURALLY BLIND TO THAT.** `entity-system-conformance` opened a
  `TRACKER-entity-core-keystone.md` on 2026-09-12 carrying **six asks marked `FILED, not routed`
  (X1–X8) and six more held (X9–X14)**; we had no tracker for that seat, so **not one of the twelve
  ever reached us** — we learned of them by reading their tree, not by a packet. Their file says so
  and declines to blame us: *"they have no `TRACKER-entity-system-conformance.md` … which is our
  seven-packets-unrouted problem and not a defect of theirs."* **It is ours.**
  **The mechanism is the false-negative family's arithmetic half, one level up: a reconciliation
  keyed on the trackers you KEEP cannot see the counterpart you OMITTED.** This entry's own
  enforcement — *"every in-flight packet must appear in exactly one tracker section"* — quantifies
  over the trackers that exist, so a seat with no file is not an unrowed packet, it is an absent
  row in an absent table, and the control reports clean. Three days, thirteen gates green.
  **Enforcement, and the discriminator must come from OUTSIDE our own list — ask which seats keep a
  tracker for US:** `for r in ../*/; do ls "$r"docs/status/TRACKER-entity-core-keystone.md; done`.
  Three hits against our three files, **intersection two**. One command, and it is the only form of
  the check that can name a channel we never thought of. Generalise past trackers: **whenever a
  convention is "one artifact per member of a set," the set must be derived from the world, never
  from the artifacts you have already made** — the H4 packaging survey's lesson, reached through an
  inbox instead of a package manager.
  *(Two of their asks turned out to be independent re-discoveries of debts WE had recorded
  internally and never routed — the non-minimal-head / duplicate-key decoder gap, which this file
  already carries as a deliberate non-fix, and `F47`. **A debt recorded in-tree so that changing it
  is a decision and not a drift is still unrouted if no counterpart is told**, and the seat whose
  job is to measure us is exactly the counterpart who should have been.)*
  **The failure it fixes is arch's, and it is the mirror of ours above.** Delivery here is *"commit
  a document to your own tree and the other party reads it"* — no queue, no notification — so a
  counterpart answering *"what does this seat need from us"* has to read a whole tree. Arch did,
  counted **one seat's private architecture notes as an inbox, and reported 44 open items where
  that seat's own tracker said eleven.**
  **Four rules, and the last two are the ones that will bite here.** Stable ids, never renumbered —
  ours are the register's `F<NN>` for arch, because minting a parallel `A-n` space for asks already
  cited in both trees is the citation-collision problem in a new place, and that deviation is
  stated *in* the tracker. **"Filed, nothing owed back" is a real section and most documents belong
  in it** — a review sent for information is not an open ask, and treating one as an ask is exactly
  what produced the 44. **`Filed` ≠ `routed` ≠ `answered`; default to NOT ESTABLISHED** — every row
  says which, and a packet committed to our tree with no cited reply is *not* delivered. **Archived
  is not delivered: close on their receipt, never on our own completion.**
  **Enforcement, and it is a reconciliation rather than a grep:** `git ls-files
  research/stewardship/HANDOFF-TO-*` names the packets, `docs/status/TRACKER-*.md` names the asks,
  and **every in-flight packet must appear in exactly one tracker section.** The trackers are under
  `docs/status/`, which never publishes ([ADR-0031]) — that is correct and deliberate: this is
  ecosystem operations, which by the publication rule does not belong in any file we declare
  canonical.
  **Routing, going forward only — do not rename history:** `docs/status/ROUTING-<date>-<letter>-<recipient>-<slug>.md`,
  opening with `**To:**` / `**From:**` / `**cc:**` **each on its own line**, `To:` naming
  REPOSITORIES (a brace list is fine), `cc:` meaning *not on the hook*. **Cite a packet by its FULL
  stem, never `ROUTING-<date>-<letter>`** — that id is unique to one repo on one day, which is not
  unique, and three ids in this ecosystem already reach three different packets each.
  **AND THE SECTION THAT SPECIFIES ALL THIS IS NOT IN OUR COPY OF THE STANDARD — a finding that
  was ALREADY MADE, better, by the seat next door.** The instructions say `AGENTS-STANDARD.md`
  §*Routing packets* *"already specifies this and it has simply not been adopted."* Measured across
  six repos the day we adopted it: the section exists in `entity-system-architecture` and
  `entity-system-generator` **only** — absent from `entity-core-keystone`, `entity-core-go`,
  `entity-core-protocol`, `entity-core-formalization` **and from the meta-root canonical copy.**
  `entity-system-generator`'s `HANDOFF-2026-09-09-c-the-outbox-nobody-could-route-and-the-standard-that-moved-in-one-tree.md`
  §1 had it first and with better evidence — line counts and sha256 (canonical and theirs 231 /
  `c3b32f98…`, arch's **305** / `674cfad7…`) — plus the mechanism, which we did not have: **arch
  edited its own copy under a clause arch added to its own copy the same day**, and the operator
  ruled that seat may take §*Routing packets* alone with a provenance blockquote. **We did NOT take
  it**: line 4 of our copy still says *"Do not edit it in your repo"* and no ruling reaches this
  seat, so the convention lives HERE, in the file that is ours to write.
  **Two things generalize.** (a) **Before recording that a convention was ignored, check that it
  was DELIVERED** — *"not adopted"* and *"not injected"* read identically from the receiving end
  and have opposite owners. (b) **Check whether a sibling already found it before writing it up as
  yours** — the standing rule to record corroboration with the same weight as a catch, reached from
  the side where WE are the second finder. `git log --since` in the sibling's `docs/status/` is one
  command, and it is the same discipline as re-deriving a routed claim.

- **THE WATERMARK EARNED ITSELF ON ITS FIRST RUN, AND THE FETCH IS THE LOAD-BEARING HALF: TWO
  COUNTERPART CHECKOUTS WERE BEHIND `origin/dev`, WHICH IS INDISTINGUISHABLE FROM A CLEAN SCAN.**
  RATIFIED 2026-09-17, adopting the `docs/outbox/` + watermark convention. The receiving half of
  routing is one line per counterpart — *"Last read X's outbox through `<date>`, at `<ref>` @
  `<sha>`"* — and the protocol is: **fetch, list their outbox for a filename dated after the
  watermark, act or ignore, then move the line and record the tip you scanned at.**
  **It returned a packet immediately, and one nobody had told us about.** Scanning seven
  counterparts at `origin/dev` surfaced `entity-system-architecture`'s
  `ROUTING-2026-09-17-b-entity-core-keystone-…`, addressed to us and dated that day: §5.3a folded
  and binding, the disclosure analyzer built, **nothing asked of us**, and our own `F88` closed by
  being acted on rather than answered. Under the previous arrangement — packets mixed into
  `docs/status/` with the recipient encoded in the filename — the only way to find it was to read
  a whole tree, which is how seats learn days late that something addressed to them existed.
  ⚠ **`entity-system-conformance` and `entity-core-rust` were BEHIND locally** (`de62199` against
  `origin/dev` `5fd9ddb`; `047a919` against `8768a42`, which moved again to `31bd8ca` during the
  pass). **A checkout you have not pulled lists nothing new and looks exactly like a clean scan** —
  and the watermark then advances **past** packets never seen, which is a permanent miss rather
  than a late one. The tip in the line is the only thing that makes *"nothing new AND I checked"*
  a different claim from *"nothing new."*
  **A second discriminator worth knowing, because the obvious check answers the wrong question:
  ask `git ls-tree origin/dev`, not `ls`.** Several seats had a `docs/outbox/` on disk and **not in
  `origin/dev`** — `entity-core-go` showed 130 files on disk and 0 tracked at its own tip. So a
  survey keyed on the filesystem reports a convention adopted where it is merely in progress, and
  a survey keyed on the shared ref reports what a counterpart can actually be read for. Say which
  you used; ours records the path scanned per seat and whether their outbox had reached their tip.
  **And `could not look` is a row, never an omission** — an absent row reads as clean.

- **FOURTH OCCURRENCE OF THE OMITTED-COUNTERPART SHAPE — SIX SEATS TRACKED US, WE KEPT FIVE, AND
  BOTH MISSING SEATS HAD OPEN ITEMS AGAINST US.** Ratified 2026-09-17, and what makes it worth a
  fourth entry is that the control was **already written down in this repo and had not been run.**
  The entry above prescribes it exactly: *ask which seats keep a tracker for US*. One command —
  `for r in ../*/; do ls "$r"docs/status/TRACKER-entity-core-keystone.md; done` — returned **six**
  against our **five**. Missing: `entity-core-py` and `entity-core-rust`, the two ground-up
  lineages, i.e. not obscure seats.
  **Both were already carrying items.** `entity-core-rust` lists two of our packets as **open**
  and wants a date on each; `entity-core-py` marks one *"believed answered — confirm the reading
  matches theirs before closing."* **Neither could reach us**, because a packet addressed to a seat
  with no tracker is not an unrowed packet — it is an absent row in an absent table, and every
  reconciliation reports clean.
  ⭐ **And `entity-core-py`'s standing note is a finding about US, which is the part to carry**:
  *"the generated family is the seat we forget we are in a cohort with… invisible to the `git log` /
  `grep` sweep we run across `entity-core-{go,rust}` — that habit is pointed at the trees that talk
  back."* They then declined to implement an arm on the ground that *refusing where a sibling
  accepts partitions the cohort* — **having polled two of three families.** Our 46 peers already
  required the field, so their reading would have made all 46 non-conformant: **they were the
  partition and could not see it.**
  ⇒ **The obligation that puts on us is to be GREPPABLE, not to route more.** Our 46 rows are the
  cohort's largest population and the one nobody opens, so whenever a ruling turns on *"what do
  implementations do"*, the evidence is here and is only usable by a counterpart who knows to look.
  **Enforcement: `tools/doc-standard-gate.py` check 8 derives the counterpart set from the sibling
  checkouts rather than from our own trackers, and REPORTS rather than fails** — a clean clone has
  no siblings, and a gate that is red on every clone is a gate people switch off. Its zero case
  prints *"could not look — that is not 'nothing to see'"*, because those two must never print the
  same word.
