# The contract host — what every language implements so the suite can measure it

**Contract:** `keystone-peer-contract` v2.0-draft.1 (`requirements.toml`, `CONTRACT-DRAFT.md`).

The contract suite is **one** program, `tools/peer-contract/driver`, identical for every language.
It measures a peer through two binaries the language provides:

| Binary | What it is |
|---|---|
| **bare host** | the peer's own host: `run_host(argv, no-op)` |
| **contract host** | `run_host(argv, install_fixtures)`, built as a **separate package** that depends only on the peer's package |

A language is brought up to the contract by writing the contract host below (a few hundred lines in
any language that already has the surfaces), plus a handful of local tests for the requirements the
wire cannot see. Nothing else about the suite changes per language.

Everything below is exact. The driver checks bytes and values, not shapes.

---

## 1. Process interface (both binaries)

**Flags** (`run.cli`): `--port N` · `--bind ADDR` (default `127.0.0.1`) · `--name NAME` ·
`--validate` · `--seed-policy PATH` · `--max-frame-bytes N` · `--ready-file PATH` ·
`--debug-open-grants` (deprecated) · `--help`. Any other argument, or a flag missing its value:
exit non-zero before listening, no readiness record.

**Identity** (`run.identity`): `--name NAME` reads `$HOME/.entity/peers/NAME/keypair`, a PEM whose
body is base64 of the 32-byte Ed25519 seed between `-----BEGIN ENTITY PRIVATE KEY-----` and
`-----END ENTITY PRIVATE KEY-----`.

**Readiness record** (`run.ready`): once listening and after `configure` returned, exactly one
stdout line:

```
LISTENING {"record":"keystone-peer-ready/1","transport":"tcp","addr":"<host:port>","peer_id":"<base58>","posture":"standard|debug-open|file","posture_digest":"<sha256 hex of the policy file bytes, or the posture name>","limits":{"max_frame_bytes":N,"max_chain_depth":M},"validate":true|false}
```

A **contract host** adds one field, `"contract_host":{"package":"<its own package name>","depends_on":"<the peer package name>"}`.
The bare host does not carry it. Key order is free; the driver parses JSON. `--ready-file PATH`
writes the same JSON object (without `LISTENING `) followed by a newline.

**Stop** (`run.stop`): on SIGTERM the process ends within 5 seconds and the listening port stops
accepting connections. Exit status is not measured (a runtime without signal handling exits by
signal, and that is fine).

**Environment the contract host reads:** `KPC_NONCE` — a string the driver chooses per run. If it
is absent the contract host's `configure` MUST refuse (so a host started by hand cannot pass a
witness it did not receive).

---

## 2. Fixtures the contract host installs, in this order, in `configure`

`<L>` is the local peer id. All patterns are peer-relative. Results are `primitive/any` entities
whose data is the map shown. Byte strings in results are **lowercase hex text**. `absent` means the
key is omitted.

Install **order** matters only for §2.4 (consumers). Record each install refusal exactly as the
registration surface reported it — the §12.5 status as an unsigned integer and the code string.

### 2.1 `app/contract/witness` — `install.handler`, `install.types`

Spec: name `witness`; operation `echo` with `input_type = "primitive/any"`,
`output_type = "contract/witness-result"`; `internal_scope` null; types
`{"contract/witness-result": {"name": "contract/witness-result"}}`.

- `echo` → `{witness: "<KPC_NONCE>:app/contract/witness:<params.echo>"}`.

**Then, still in `configure`, attempt three installs that MUST be refused, and keep what the
surface reported:**
1. `app/contract/witness` again (any body) → expect 409 `pattern_collision`
2. `system/tree` (any body) → expect 409 `pattern_collision`
3. `app//bad` with one operation → expect 400 `invalid_handler_spec`

### 2.2 `app/contract/removable` — `install.remove`, `install.types`

Spec: name `removable`; operation `echo`; types `{"contract/removable-type": {"name": "contract/removable-type"}}`.
Keep the **handle**.

- `echo` → `{witness: "removable"}`

### 2.3 `app/contract/probe` — reads what the fixtures observed

Spec: name `probe`; operations `install_report`, `close_removable`, `events`, `unregister_b`.

- `install_report` → `{collision_status, collision_code, builtin_collision_status, builtin_collision_code, invalid_status, invalid_code}` from §2.1.
- `close_removable` → close the §2.2 handle **twice**; `{first: <bool>, second: <bool>}` where each
  bool is whether that close removed a registration (expect `true`, `false`). A language whose close
  returns nothing reports `true` for the call that ran first and `false` for a close on an already
  closed handle, as its handle can tell.
- `events` → `{log: [<text>…]}`, the §2.4 log in delivery order.
- `unregister_b` → unregister consumer B; `{removed: <bool>}`.

### 2.4 Consumers — `install.consumer`, `event.context`

Register, in this order: tree-change consumer **A**, tree-change consumer **B**, content-store
consumer **C**. All append to one shared, ordered, thread-safe log:

- A and B, for a tree-change event whose path starts with `/<L>/app/contract/events/`:
  `"A|tree|<path>|<author hex of the event's execution context, or empty>"` (B the same with `B`).
- C, for a content-store event whose entity type is `contract/event-marker`:
  `"C|content|<content hash hex>|"`.

### 2.5 `app/contract/granted` and `app/contract/ungranted` — `install.grant`

`granted`: name `granted`; operations `put_inside`, `put_outside`; `internal_scope`:

```
[{"handlers":{"include":["system/tree"]},
  "resources":{"include":["/<L>/app/contract/scratch/*"]},
  "operations":{"include":["put"]}}]
```

`ungranted`: name `ungranted`; operation `put_inside`; `internal_scope` null.

Both bodies do the same thing: a **local dispatch** (`context.dispatch`) of `system/tree` `put`,
under **the handler's own grant** as the capability, of the entity `{type: "primitive/any", data:
{v: 1}}` at target `app/contract/scratch/inside` (`put_inside`) or `app/contract/other/outside`
(`put_outside`). Result: `{status: <the sub-dispatch status>, code: <its code or "">}`. If the
handler has no grant at all, return `{status: 403, code: "capability_denied"}` without dispatching.

### 2.6 `app/contract/context` — `context.contents`, `context.frame_budget`

Name `context`; operations `echo`, `budget`.

- `echo` → `{operation, pattern, suffix, author, caller_capability, handler_grant, marker}`:
  `operation`/`pattern`/`suffix` as text; `author` hex; `caller_capability` and `handler_grant` the
  content-hash hex of those tokens, or `""` when absent; `marker` = `params.marker`.
- `budget` → `{frame_budget: <uint>}`, the connection's frame budget read from the context.

### 2.7 `app/contract/dispatch` — `context.dispatch`, `event.context`

Name `dispatch`; operation `put_as_caller`. A local dispatch of `system/tree` `put` under **the
caller's** capability (the default) of `{type: "contract/event-marker", data: {n: params.n}}` at
target `app/contract/events/sub`. Result `{status, code}` of the sub-dispatch.

### 2.8 `app/contract/authz` — `authority.path_permission`

Name `authz`; operation `check`. Evaluate the public path-permission predicate with
`operation = params.operation`, `path = params.path` (peer-relative), the **caller's capability
token**, `handler_pattern = params.handler_pattern`, and the local peer. Result `{allowed: <bool>}`.

### 2.9 Evaluator — `install.evaluator` (MODULE)

Install an entity-native evaluator that answers bodies of type `contract/echo-expression` **and
`compute/literal`**, with `{evaluated_by: "contract-evaluator", value: <the body's data.value>}` and
status 200, and declines everything else.

It claims `compute/literal` on purpose. The requirement is that the built-in literal floor answers
**first**; an evaluator that declined literals could never observe a peer consulting it first, so
the `literal-floor-first` control would pass on exactly the defect it exists to catch. A language that declines the module omits this and says so in its contract
manifest.

### 2.10 `app/contract/data` — `embed.data`

Name `data`; operations `put`, `get`, `bind`, `get_at`, `unbind`, `forge`. Every body uses the
peer's **data surface** directly — the store operations an extension calls in-process — never a
local dispatch. The **item** for a marker `m` is the entity `{type: "contract/data-item", data:
{marker: m}}`. `path` params are peer-relative; the fixture addresses the store in whatever form the
data surface takes (the rust peer's is `/<L>/<path>`). Hashes are lowercase hex both ways.

- `put` `{marker}` → store the item in the content store, bound at no path → `{hash, accepted}`,
  `accepted` being what the surface reported (`true` for a language whose put reports nothing).
- `get` `{hash}` → look the hash up in the content store → `{found, type, marker}`, the last two `""`
  when not found.
- `bind` `{path, marker}` → bind the item at `path` **carrying the request's execution context** →
  `{hash, accepted}`.
- `get_at` `{path}` → the entity bound at `path` → `{found, hash, marker}`.
- `unbind` `{path}` → remove the binding at `path`, **carrying the request's execution context** → `{}`.
- `forge` `{marker, victim_marker, path}` → build an entity of type `contract/data-item` with data
  `{marker}` whose **carried** content hash is the item hash of `victim_marker`; try to `put` it, then
  to `bind` it at `path` → `{constructible, put_accepted, bind_accepted}`. A language in which an
  entity cannot carry a hash other than its own reports `constructible: false` and both `false`.

---

## 3. What the driver does with it (summary)

Four identities, fixed seeds: the **host** (`0x41`×32, provisioned as `--name kpc`), **wide**
(`0x31`), **narrow** (`0x32`), **stranger** (`0x33`). The driver writes this seed policy and starts
the contract host with `--seed-policy`:

- `wide` → handlers `*`, resources `*` and `/*/*`, operations `*`
- `narrow` → handlers `app/contract/witness`, `app/contract/dispatch`, `app/contract/authz`;
  resources `/<L>/app/contract/*`; operations `echo`, `put_as_caller`, `check`
- `default` → the §4.4 discovery floor

Then, per case in `requirements.toml`, it asserts the values above — the witness string, the 404 at
`app/contract/never`, the refusal codes, the consumer log's order and authors, the budget equal to
the `--max-frame-bytes` it chose, the narrow identity's allow and deny. The case list and each
case's expectation live in `tools/peer-contract/driver/main.go`, next to the code that checks it.
