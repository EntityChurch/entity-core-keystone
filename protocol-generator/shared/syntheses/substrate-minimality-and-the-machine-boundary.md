# How much substrate does the entity system actually need? — a keystone-grounded assessment

**Date:** 2026-07-20 · **Role:** an assessment, prompted by a host-failure observation,
of what the Keystone cohort and the surrounding research say about the **machine boundary** —
the interface between entity computation and the physical/host substrate. Connects three
tracks that have been approaching one question from different sides:

- **Paper 04** — *The Entity Machine Boundary* — the top-down
  analytic floor (bootstrap evaluator, seven primitives, four fixed points, five profiles).
- **The Keystone cohort** — 43 peers + the `AGENTS.md` §7b concurrency taxonomy — the
  bottom-up empirical demonstration of how thin the substrate can be.
- **The architecture device/host track** — the *runtime/orchestration* contract, reached
  independently via the compute-program spike
  (`entity-system-architecture/docs/research/explorations/{EXPLORATION-GENERIC-HOST-AND-DESCRIPTOR,
  ANALYSIS-SUBSTRATE-CONVERGENCE-COMPUTE-DEVICE-SCHEDULER}.md`).

## 0. Epistemic frame (read first)

Exploratory, in the same Tier-3 register as Paper 04 (architecturally-reasoned, largely
unimplemented, open questions flagged). Nothing here is established, nothing is a proposal,
nothing changes a peer or a spec. It **reads** the papers and the architecture explorations;
it edits neither (sibling repos, read-only). The value, if any, is that **three research
tracks launched separately are converging on one object**, and naming that convergence — and
its limits — is worth doing once. Where it reasons from a single field observation, that
observation is an anecdote, not evidence, and is used only to motivate the question.

## 1. The motivating observation, kept generic

A commodity Linux host under heavy concurrent container load can hard-lock in a way that
still feels archaic in 2026. A concrete, reproducible-in-kind failure mode: a rootless
container-teardown path wedges a task in the kernel's expedited-RCU machinery
(`synchronize_rcu_expedited`), in uninterruptible `D` state; the stalled grace period holds a
cgroup lock (`cgroup_kn_lock_live`) that every process spawn and teardown needs; the whole
system's process lifecycle halts; new shells never reach a prompt; eventually `init` (PID 1)
itself blocks. The stuck task takes no signal, `SIGKILL` included. Recovery is a reboot.

This is a *known* class of monolithic-kernel failure, not anything exotic — which is the
point. The question it provokes is the one worth this document: **why, in 2026, does managing
shared mutable state still do this — and does the entity system's different foundation say
anything about it?** (Hardware faults below the software stack are real and orthogonal; they
are the physics floor of §7, not the subject here.)

## 2. The diagnosis worth taking seriously: the von Neumann inheritance

State the hypothesis plainly, as a provocation to test rather than a doctrine to defend:

> **The foundational commitment of mainstream computing — the mutable memory address — may be
> the original design decision we have been patching ever since.**

Everything downstream is management of *shared mutable state under aliasing*: cache-coherency
protocols (MESI/MOESI) burning bus bandwidth, lock hierarchies and the deadlocks their
inversions cause, virtual memory, the RCU grace-period machinery itself. The lockup in §1 is a
pure specimen of the pattern — shared mutable kernel state, a lock protecting it, a
grace-period protocol coordinating readers, and weak fault isolation letting one wedged task
freeze unrelated subsystems.

Paper 04 makes the same diagnosis from the hardware side without the polemic: the "performance
overhead" of content-addressed computation (hashing, associative lookup) "appears inherent when
standing inside the von Neumann paradigm … The hypothesis is that these costs are artifacts of
the hardware model rather than the computational model." And crucially, because the content
store is *immutable*, "there is no cache coherency problem for the content store. Multiple
processors can read from it without coordination." The coherency tax — the same family of
mechanism that deadlocked in §1 — is charged only against *mutable* shared state. Remove the
mutability and the tax, and the deadlock surface, largely disappears.

The entity model's wager is the opposite foundation on all three axes that produced the failure:

| The failure's ingredient | The entity commitment |
|---|---|
| Shared **mutable** state under aliasing | **Immutable, content-addressed** content — no aliasing, no coherency traffic for the content store |
| A **lock hierarchy** with an inversion | **Single-writer ownership / message-passing** — no lock to invert |
| **Weak fault isolation** (one task freezes the system) | **Capability-scoped authority** — blast radius is the granted scope |

This is not a rhetorical flourish; it is the same disease/cure pairing the §7b concurrency
taxonomy keeps rediscovering across substrates. The peers that get store-safety *by
construction* — actor-isolation, dataflow-variable, STM, and Unison's single-`MVar`/abilities
route — are immune to this class of bug *because they refuse shared mutable state*. The Linux
kernel has precisely the property those substrates structurally decline. **Whether that
foundation is *the* answer is genuinely unknown — but it is a coherent, testable, opposite
bet, and that is what makes the question worth pursuing rather than dismissing.**

## 3. "How much substrate?" — three independent answers that stack

The operator's core question — *what must the substrate actually provide, and how much of it
do we depend on?* — has been answered independently by three tracks, at three altitudes. They
do not conflict; they stack.

### 3a. Top-down — the analytic floor (Paper 04)

The **bootstrap evaluator** (~400–500 LOC of C, a *design estimate*) boots the whole system
from a conforming tree via eight operations over **seven irreducible machine-level
primitives**: byte manipulation, SHA-256, CBOR encode/decode, string comparison, integer
arithmetic, memory allocation, I/O. Above that, four **fixed points** survive every
compilation stage because they are where the model touches reality: *tree writes, cross-peer
exchange, capability checks, handler transitions*. And five **profiles** (compute-only →
storage → OS-hosted → hybrid-kernel → bare-metal) trace how much of the machine gets absorbed
into entity computation. This is the floor stated by decomposition.

### 3b. Bottom-up — the empirical demonstration (the Keystone cohort)

The cohort is the *experiment* that the floor is genuinely thin and substrate-independent:

- **43 peers across every ISA, runtime, and paradigm pass the same core gate.** That is a
  strong experimental statement that the core protocol floats on a very thin substrate — the
  "free variables we never constrained" made concrete rather than asserted.
- **The §7b concurrency taxonomy maps *how thin the concurrency guarantee can be* and still
  host a conformant peer.** Answer: very thin. A **single-threaded event loop suffices** (Pd,
  Io, TurboWarp); threads, preemption, and shared-memory concurrency are *not* in the floor.
  That directly bounds, from experiment, what a Profile-4 substrate must provide for
  concurrency — **less than Linux offers.**
- **The Unison peer sharpened the crypto axis:** a managed runtime with *no C-FFI* still hosts
  a peer (it hand-rolled Ed25519 keygen in pure Unison). So even "can call out to C" is not in
  the floor.

Bottom-up meets top-down: the cohort is empirical evidence *for* the paper's claim that the
platform-specific footprint is small and the rest is transferable entity data.

### 3c. Sideways — the host-exposure contract (architecture's device/host track)

This is the third arrival, and the one most easily missed because it comes from the
*application/runtime* side, not the metal. Working the compute-program problem, the
architecture explorations independently reconstructed the substrate question as **sense →
schedule → actuate** — the universal orchestrator split (the same one Nomad/K8s/wasmCloud
use):

- **`system/device` = layer-1 sensing** — read-only advertisement of host facts.
- **The generic host = layer-3 actuation** — a `mount(descriptor) → running program` loop with
  *zero per-program code*: the first (deterministic-compute) actuation driver.
- **The scheduler = layer-2** — future; matches work to resources.
- **`system/device/host/offered` = the hostability contract** — the peer's set of
  currently-dispatchable host capabilities, *written by the sensor, read by every actuator's
  admission.* Two tracks (device-sensing and generic-host-admission) converged on this single
  field from opposite ends — the same "two tracks, one primitive" shape the continuation/network
  review found.
- **Transferability = two ABIs:** the **compute-IR** (the ABI for *evaluation* — each runtime
  brings its engine) and the descriptor's **`(role, shape)` vocabulary** (the ABI for *I/O* —
  each host brings its drivers, and the vocabulary is grounded in the *lineage of computer I/O*:
  text → raster → vector → audio, not in any one application).

This answers a *different facet* of "how much substrate": not "what must the metal provide"
(3a) or "what have we shown is dispensable" (3b), but **"what must the entity system expose
*about* a host to run work on it?"** — and the answer is a thin, read-only capability
advertisement plus a shared driver vocabulary. The determinism boundary the same analysis
draws (`ANALYSIS-SUBSTRATE-CONVERGENCE…` §4) is load-bearing: **the CPU/GPU line *is* the
`compute/apply` seam** — entity-compute stays a deterministic CPU tree-walk; GPU work lives on
the *native* side of the seam (rasterizer, DSP) as a driver, never as entity-compute. That is
the same idea as Paper 04's Category-C "native handler" boundary, reached from the runtime side.

*(Both architecture docs are explicitly labelled exploration/analysis, not ratified — cited as
directional convergence, not settled contract.)*

## 4. The convergence is the finding — the elephant

Take a step back and the three answers above are the same question at three altitudes; and
the tracks producing them are, between them, describing **one object that is larger than "an
operating system":**

| Track | The limb it's touching |
|---|---|
| Paper 04 (machine boundary) | Computer **architecture** — pipeline, CAM/LPM, compilation gradient, bootstrap |
| Paper 07 (DEOS) | The entity system as **operating system** |
| Architecture device/host/scheduler explorations | The **runtime / distributed-orchestration** layer (sense/schedule/actuate) |
| Paper 05 (computational genome) | **Compilation-down** — multi-architecture from one source |
| Keystone cohort + §7b taxonomy | Empirical **substrate-independence** + the concurrency floor |
| The convergence/substrate-theory thread (this repo) | The **six-primitive substrate model**, cross-corroborated |

Each track was launched to answer a bounded question. Each has been touching a different part
of the same animal. The step-back observation is that it *is* one animal: **simultaneously a
computer-architecture proposal, a runtime, a distributed operating system, and something with
microkernel-like properties (capability isolation, drivers-as-handlers) — reached from the
*protocol down* rather than the *hardware up*.** The reason the limbs align is that they are all
consequences of the same small core: content-addressed data + capability dispatch + the six
primitives. The alignment is not engineered between the tracks; it falls out of the shared
foundation, which is exactly why it is worth trusting more than any single track's local claim.

## 5. The inversion of method — and the reversal it makes conceivable

Most operating-system efforts start at the metal and build up: BIOS → memory manager →
scheduler → drivers → userland. The entity approach **inverted the build order** — author the
high-level protocol first, and treat the host (Linux/Windows/macOS, ARM/x86/RISC-V) as *free
variables*. The 43-peer cohort is the proof that the inversion held: nothing in the core
depends on any particular host, ISA, or runtime.

That inversion is what makes a later **reversal** conceivable rather than fanciful. Today the
entity system is a *guest* on Linux (Profile 3): it borrows scheduling, memory, and process
lifecycle, and inherits the host's failure modes (§1). The trajectory the tracks jointly
sketch is for the relation to flip: the entity system becomes the *host*, and Linux becomes a
**driver-abstraction guest** — the OS proper is a pristine peer; hardware and architecture
support grow through the computational genome (the compilation gradient + Paper 04's
"machine-architecture-as-entity-domain," where instructions/registers/ABIs are themselves typed
entities); and entity-native code runs pure, with conventional OSes and VMs hosted *above* the
entity layer rather than beneath it. In Paper 04's terms this is Profile 4 → Profile 5; in the
architecture track's terms it is "the generic host consumes device sensing," applied at the OS
level. **Honest status: entirely unbuilt, long horizon, and not required for the near-term
value — but coherent, and it is the same shape as the guest→host inversion the cohort already
demonstrated at the protocol layer.**

### 5a. The host as both asset and liability (the dual-layer trade)

One design thesis in circulation: run the entity system as a privileged first process on a
reduced host OS, so an attacker must breach **two independent security models** — entity
capabilities *and* a structurally-different host OS — to win (defense in depth via
heterogeneity; connects to Paper 10). The §1 observation surfaces this thesis's **cost**, which
the security framing alone hides: *the same second layer that adds security (an independent
barrier) subtracts availability (shared fate — it can wedge you).* So the dual-layer model is a
**security/availability trade**, and its two mitigations are two points on it: a *reduced/curated
host* shrinks the availability liability (fewer subsystems → fewer deadlock surfaces) at near-
constant security-heterogeneity; the *own-the-whole-stack* approach drives the liability toward
zero at the cost of the commodity-hardware pool. The cohort's substrate-agnosticism is what keeps
*both* options open without re-architecting the peer.

### 5b. "Reverse process zero" — the missing `init` row in the Entity ABI

Paper 04's Entity-ABI table maps syscall→EXECUTE, PID→peer, address→content-hash,
perms→capability grant, driver→handler — but has no row for `init`/PID 1: the *first* peer that
comes up at Profile 4 and roots all authority. The pieces already exist and are **already
prototyped at Profile 3 by the cohort's L1**: the bootstrap evaluator *runs first* (deliberately
authority-free); the **seed policy** roots authority (in the Unison peer, `--debug-open-grants`
is literally the degenerate root seed `default→*`, the ur-capability an attenuated tree grows
from); persistent identity anchors it. So **"peer zero" ≈ bootstrap evaluator + seed-policy root
+ persistent identity**, and its responsibilities are exactly the ones Keystone L1 already
discharges. The missing ABI row is `init/PID 1 → seed peer`. Offered as a thought for whoever
revisits Paper 04 / Paper 07, not a proposal to them.

## 6. Reopening "what is an operating system?"

The operator's deeper point deserves stating on its own. We inherited a definition — *OS = the
Unix-ish thing with a scheduler, drivers, and processes* — and then treated it as the whole of
what an OS must be. But an ESP32 running bare firmware is arguably an OS; a unikernel is; the
BEAM is a kind of OS. "OS-ness" is a *role* — mediate between programs and a machine, arbitrate
resources, provide identity and isolation — not a fixed artifact you must inherit.

The entity answer redefines the *target of that role*: **don't target Linux, its schedulers,
its drivers; target entity compute.** The Entity ABI is the concrete form of the redefinition
(syscall→EXECUTE, file→tree path, open→get, write→emit, process→peer, driver→handler). The
claim is not "those other things aren't operating systems" — it is "the OS role can be filled
by a protocol and its evaluator, reached from the top down, rather than by a fixed stack built
from the metal up." **Whether that role can actually be filled all the way to the metal — with
acceptable performance and without re-growing the very complexity it set out to avoid — is the
open question. The cohort proves the protocol is substrate-*independent*; it does not prove the
protocol can *replace* the substrate. Those are different claims, and only the first has
evidence.**

## 7. The bridge that cannot be escaped (physics)

One hard limit shows up in every track and in the methodology, and it is the honest boundary on
all of the above. **Informational closure is not physical closure.** The tree can describe its
own evaluator, but a description does not execute itself — some physical process must run first.
Paper 04: "The regression is infinite in description but terminates in physics: at the bottom, a
physical process (silicon, chemistry) implements state transitions governed by physical law, not
by another evaluator." Entity-native hardware does not escape this; it *moves* the bridge from
"compile the first evaluator with an external compiler" to "fabricate the first entity processor
with existing semiconductor processes." The dependency on the physical substrate is irreducible.

Two consequences worth stating:

1. **The hardware floor is below the whole edifice.** A flaky memory module, a marginal power
   rail, a silicon glitch — these live *beneath* the bootstrap bridge, where no protocol,
   capability model, or content-addressing reaches. Software fault-isolation isolates *software*
   fault propagation only. This is why the correct posture toward the physical layer is
   **survivability, not prevention**: at Profile 3 the entity model cannot *prevent* a host or
   hardware failure, but it can make the failure *cheap and recoverable* — content-addressed
   durable state loses no committed work, cross-peer continuation lets another peer resume,
   deliver-or-signal makes the failure observable rather than a silent freeze.
2. **The entity system's honesty is that it *names* this bridge.** The JVM, WASM, and the BEAM
   hide the machine boundary behind an opaque runtime; Paper 04's whole method is to make it
   explicit — which is what lets the system reason about its own physical realization at all,
   and what lets us say precisely where the irreducible physical dependency sits.

## 8. Honest limits, and what would turn theory into evidence

- **Protocol ≠ OS today.** entity-core is a protocol with no scheduler, memory manager, or
  drivers. A Profile-3 peer freezes when its host freezes. Profiles 4/5 are unbuilt; no
  bootstrap evaluator has been implemented; the reversal of §5 is a direction, not an option.
- **Substrate-independence ≠ substrate-replacement.** The cohort proves the former (strongly)
  and says nothing about the latter. Conflating them would be the easiest overclaim to make here.
- **"Cardinal sin" is a provocation, not a proof.** The von Neumann critique (§2) is a coherent
  hypothesis with a real mechanism behind it; it is not established that the entity foundation
  outperforms or out-survives the mutable-memory model in practice. Paper 04's own performance
  claims are explicitly *structural, not measured*.
- **One incident motivates; it does not validate.** §1 is an anecdote.

The cheapest experiments that would move any of this from theory toward evidence, roughly in
order of leverage:

1. **Implement and measure the bootstrap evaluator.** Does the ~400–500 LOC estimate hold?
   This is the single most load-bearing unmeasured number in the whole picture.
2. **A survivability-first Profile-3 deployment** — durable content store + cross-peer
   continuation + a host watchdog that panics-and-recovers on a `D`-state hang rather than
   wedging. This turns the §1 freeze into a bounded, signalled, auto-recovered handoff, and is
   buildable *now*, entirely at Profile 3. It is the cheapest test of the survivability thesis.
3. **The browser/Rust generic-host cross-runtime demo** (architecture's own falsification, §7 of
   `EXPLORATION-GENERIC-HOST-AND-DESCRIPTOR`): the same program, authored once, fetched by hash,
   run in Go and in a browser with no shared driver code and boundary-hash-identical state. This
   is the first real proof that "transferable compute across substrates" is a fact, not an
   assertion — and it exercises the compute-corpus cross-runtime equivalence contract.
4. **An FPGA prototype of the six-stage pipeline** — the far-horizon test of whether the
   von Neumann overhead is a translation artifact (Paper 04 §"Feasibility Path").

## 9. Bottom line

Three research tracks — a top-down machine-boundary analysis, a bottom-up 43-peer conformance
cohort, and a sideways device/host/runtime exploration — are independently converging on one
object that behaves like architecture, runtime, and operating system at once, reached from the
protocol down. The convergence is real and falls out of a shared minimal core, which is why it
is more trustworthy than any single track's claim. The provocation underneath it — that the
mutable-memory address is a foundational choice we have been paying for ever since, and that a
content-addressed, capability-dispatched foundation is the opposite bet — is coherent and
testable. What is *not* yet shown is that the bet pays: that the entity role can be filled all
the way to the metal without re-growing the complexity it set out to avoid. The honest position
is that we have proven substrate-*independence* and are now asking whether substrate-*
replacement* is possible — and that the irreducible physics bridge means the goal is not to
abolish the physical substrate but to meet it honestly and survive its failures.
