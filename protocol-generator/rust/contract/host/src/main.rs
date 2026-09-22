//! `kpc-host` — the keystone peer contract host for the rust peer.
//!
//! `run_host(argv, install_fixtures)`. Every fixture below is specified byte-for-byte in
//! `protocol-generator/shared/peer-contract/FIXTURE-HOST.md`, and the section numbers in the
//! comments are that document's. The shared driver (`tools/peer-contract/driver`) measures what
//! these fixtures do; nothing here decides a verdict.
//!
//! It uses only what the peer package exports. If a fixture needs something the package does not
//! expose, that is a contract finding about the peer, and the fix belongs in the peer, not here.

use std::sync::{Arc, Mutex};

use entity_core_protocol::peer::capability::check_path_permission;
use entity_core_protocol::peer::model::{self, hex, Entity};
use entity_core_protocol::peer::{
    run_host_with, ConsumerId, ExpressionEvaluator, ExpressionRequest, HandlerContext,
    HandlerHandle, HandlerResult, HandlerSpec, LocalExecute, OperationSpec, Peer, RegisterError,
};
use entity_core_protocol::value::{Key, Value};

fn any(pairs: Vec<(&str, Value)>) -> Entity {
    Entity::make("primitive/any", model::map(pairs))
}

fn param_text(ctx: &HandlerContext<'_>, key: &str) -> String {
    ctx.params()
        .and_then(|p| p.text_field(key).map(str::to_string))
        .unwrap_or_default()
}

/// Lowercase hex text → bytes (the fixture's own parsing of a driver param). `None` for bad hex.
fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

fn status_code(r: &HandlerResult) -> Entity {
    any(vec![
        ("status", Value::UInt(r.status)),
        ("code", model::text(r.result.text_field("code").unwrap_or(""))),
    ])
}

/// A `system/tree` put request for `entity` (§6.3: the submitter supplies the content hash).
fn put_request(entity: &Entity) -> Entity {
    Entity::make(
        "system/tree/put-request",
        model::map(vec![(
            "entity",
            Value::Map(vec![
                (Key::Text("type".into()), model::text(&entity.typ)),
                (Key::Text("data".into()), entity.data.clone()),
                (Key::Text("content_hash".into()), Value::Bytes(entity.hash.clone())),
            ]),
        )]),
    )
}

fn refusal(r: Result<HandlerHandle, RegisterError>) -> (u64, String) {
    match r {
        Ok(h) => {
            // Installed when it must not have been: leave it installed (so the driver sees it)
            // and report success, which the driver scores as a failure.
            h.detach();
            (200, String::new())
        }
        Err(e) => (e.status(), e.code().to_string()),
    }
}

/// §2.9 — answers `contract/echo-expression` AND `compute/literal` bodies, so a peer that asked it
/// before its own literal floor would be visible.
struct EchoEvaluator;

impl ExpressionEvaluator for EchoEvaluator {
    fn evaluate(&self, req: &ExpressionRequest<'_>, _ctx: &HandlerContext<'_>) -> Option<HandlerResult> {
        if req.expression.typ != "contract/echo-expression" && req.expression.typ != "compute/literal" {
            return None;
        }
        let value = req.expression.field("value").cloned().unwrap_or(Value::Null);
        Some(HandlerResult::ok(any(vec![
            ("evaluated_by", model::text("contract-evaluator")),
            ("value", value),
        ])))
    }
}

fn install_fixtures(peer: &Arc<Peer>) -> Result<(), String> {
    let nonce = std::env::var("KPC_NONCE")
        .map_err(|_| "KPC_NONCE is not set — the contract host is started by the contract driver".to_string())?;
    let local = peer.local_peer.clone();
    let err = |e: RegisterError| e.to_string();

    // §2.1 witness.
    let captured = format!("{nonce}:app/contract/witness");
    peer.register_handler(
        HandlerSpec::new("app/contract/witness", "witness")
            .operation(OperationSpec::typed("echo", "primitive/any", "contract/witness-result"))
            .with_type(
                "contract/witness-result",
                model::map(vec![("name", model::text("contract/witness-result"))]),
            ),
        move |ctx: &HandlerContext<'_>| {
            HandlerResult::ok(any(vec![(
                "witness",
                model::text(&format!("{captured}:{}", param_text(ctx, "echo"))),
            )]))
        },
    )
    .map_err(err)?
    .detach();

    let noop = |_ctx: &HandlerContext<'_>| HandlerResult::ok(any(vec![]));
    let collision = refusal(peer.register_handler(
        HandlerSpec::new("app/contract/witness", "again").operation(OperationSpec::named("echo")),
        noop,
    ));
    let builtin = refusal(peer.register_handler(
        HandlerSpec::new("system/tree", "shadow").operation(OperationSpec::named("get")),
        noop,
    ));
    let invalid = refusal(peer.register_handler(
        HandlerSpec::new("app//bad", "bad").operation(OperationSpec::named("echo")),
        noop,
    ));

    // §2.2 removable — the handle is kept.
    let removable = peer
        .register_handler(
            HandlerSpec::new("app/contract/removable", "removable")
                .operation(OperationSpec::named("echo"))
                .with_type(
                    "contract/removable-type",
                    model::map(vec![("name", model::text("contract/removable-type"))]),
                ),
            |_ctx: &HandlerContext<'_>| HandlerResult::ok(any(vec![("witness", model::text("removable"))])),
        )
        .map_err(err)?;
    let removable = Arc::new(removable);

    // §2.4 consumers, in order A, B (tree) then C (content).
    let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let events_prefix = format!("/{local}/app/contract/events/");
    let tree_consumer = |tag: &'static str| {
        let log = log.clone();
        let prefix = events_prefix.clone();
        move |ev: &entity_core_protocol::peer::TreeChangeEvent| {
            if ev.path.starts_with(&prefix) {
                let author = ev
                    .context
                    .as_ref()
                    .and_then(|c| c.author.as_ref())
                    .map(|a| hex(a))
                    .unwrap_or_default();
                log.lock().unwrap().push(format!("{tag}|tree|{}|{author}", ev.path));
            }
        }
    };
    let _a: ConsumerId = peer.store.register_tree_consumer(tree_consumer("A"));
    let b: ConsumerId = peer.store.register_tree_consumer(tree_consumer("B"));
    {
        let log = log.clone();
        peer.store.register_content_consumer(move |ev| {
            if ev.entity_type == "contract/event-marker" {
                log.lock().unwrap().push(format!("C|content|{}|", hex(&ev.content_hash)));
            }
        });
    }

    // §2.3 probe.
    {
        let log = log.clone();
        let store_peer = Arc::downgrade(peer);
        let removable = removable.clone();
        peer.register_handler(
            HandlerSpec::new("app/contract/probe", "probe").operations(vec![
                OperationSpec::named("install_report"),
                OperationSpec::named("close_removable"),
                OperationSpec::named("events"),
                OperationSpec::named("unregister_b"),
            ]),
            move |ctx: &HandlerContext<'_>| match ctx.operation() {
                "install_report" => HandlerResult::ok(any(vec![
                    ("collision_status", Value::UInt(collision.0)),
                    ("collision_code", model::text(&collision.1)),
                    ("builtin_collision_status", Value::UInt(builtin.0)),
                    ("builtin_collision_code", model::text(&builtin.1)),
                    ("invalid_status", Value::UInt(invalid.0)),
                    ("invalid_code", model::text(&invalid.1)),
                ])),
                "close_removable" => {
                    let first = removable.close();
                    let second = removable.close();
                    HandlerResult::ok(any(vec![("first", Value::Bool(first)), ("second", Value::Bool(second))]))
                }
                "events" => {
                    let entries = log.lock().unwrap().iter().map(|e| model::text(e)).collect();
                    HandlerResult::ok(any(vec![("log", Value::Array(entries))]))
                }
                "unregister_b" => {
                    let removed = store_peer
                        .upgrade()
                        .map(|p| p.store.unregister_consumer(b))
                        .unwrap_or(false);
                    HandlerResult::ok(any(vec![("removed", Value::Bool(removed))]))
                }
                other => HandlerResult::error(501, "unsupported_operation", Some(other)),
            },
        )
        .map_err(err)?
        .detach();
    }

    // §2.5 granted / ungranted.
    let put_under_handler_grant = |ctx: &HandlerContext<'_>, target: &str| -> HandlerResult {
        let grant = match ctx.handler_grant() {
            Some(g) => g.clone(),
            None => return HandlerResult::ok(any(vec![
                ("status", Value::UInt(403)),
                ("code", model::text("capability_denied")),
            ])),
        };
        let body = any(vec![("v", Value::UInt(1))]);
        let r = ctx.dispatch_execute(
            LocalExecute::new("system/tree", "put", put_request(&body))
                .with_target(target)
                .with_capability(grant),
        );
        HandlerResult::ok(status_code(&r))
    };
    let scope = vec![model::map(vec![
        ("handlers", model::map(vec![("include", model::text_array(&["system/tree"]))])),
        (
            "resources",
            model::map(vec![(
                "include",
                Value::Array(vec![model::text(&format!("/{local}/app/contract/scratch/*"))]),
            )]),
        ),
        ("operations", model::map(vec![("include", model::text_array(&["put"]))])),
    ])];
    peer.register_handler(
        HandlerSpec::new("app/contract/granted", "granted")
            .operation(OperationSpec::named("put_inside"))
            .operation(OperationSpec::named("put_outside"))
            .internal_scope(scope),
        move |ctx: &HandlerContext<'_>| match ctx.operation() {
            "put_inside" => put_under_handler_grant(ctx, "app/contract/scratch/inside"),
            _ => put_under_handler_grant(ctx, "app/contract/other/outside"),
        },
    )
    .map_err(err)?
    .detach();
    peer.register_handler(
        HandlerSpec::new("app/contract/ungranted", "ungranted").operation(OperationSpec::named("put_inside")),
        move |ctx: &HandlerContext<'_>| put_under_handler_grant(ctx, "app/contract/scratch/inside"),
    )
    .map_err(err)?
    .detach();

    // §2.6 context.
    peer.register_handler(
        HandlerSpec::new("app/contract/context", "context")
            .operation(OperationSpec::named("echo"))
            .operation(OperationSpec::named("budget")),
        |ctx: &HandlerContext<'_>| match ctx.operation() {
            "budget" => HandlerResult::ok(any(vec![("frame_budget", Value::UInt(ctx.frame_budget() as u64))])),
            _ => HandlerResult::ok(any(vec![
                ("operation", model::text(ctx.operation())),
                ("pattern", model::text(ctx.pattern())),
                ("suffix", model::text(ctx.suffix())),
                ("author", model::text(&ctx.author().map(hex).unwrap_or_default())),
                (
                    "caller_capability",
                    model::text(&ctx.caller_capability().map(|c| hex(&c.hash)).unwrap_or_default()),
                ),
                (
                    "handler_grant",
                    model::text(&ctx.handler_grant().map(|g| hex(&g.hash)).unwrap_or_default()),
                ),
                ("marker", model::text(&param_text(ctx, "marker"))),
            ])),
        },
    )
    .map_err(err)?
    .detach();

    // §2.7 dispatch.
    peer.register_handler(
        HandlerSpec::new("app/contract/dispatch", "dispatch").operation(OperationSpec::named("put_as_caller")),
        |ctx: &HandlerContext<'_>| {
            let n = ctx.params().and_then(|p| p.field("n").cloned()).unwrap_or(Value::UInt(0));
            let marker = Entity::make("contract/event-marker", model::map(vec![("n", n)]));
            let r = ctx.dispatch_execute(
                LocalExecute::new("system/tree", "put", put_request(&marker)).with_target("app/contract/events/sub"),
            );
            HandlerResult::ok(status_code(&r))
        },
    )
    .map_err(err)?
    .detach();

    // §2.8 authz.
    peer.register_handler(
        HandlerSpec::new("app/contract/authz", "authz").operation(OperationSpec::named("check")),
        |ctx: &HandlerContext<'_>| {
            let allowed = match ctx.caller_capability() {
                Some(token) => check_path_permission(
                    &param_text(ctx, "operation"),
                    &param_text(ctx, "path"),
                    token,
                    &param_text(ctx, "handler_pattern"),
                    ctx.local_peer(),
                ),
                None => false,
            };
            HandlerResult::ok(any(vec![("allowed", Value::Bool(allowed))]))
        },
    )
    .map_err(err)?
    .detach();

    // §2.10 data — the in-process data surface, which is the peer's own store.
    {
        let store_peer = Arc::downgrade(peer);
        let abs = {
            let local = local.clone();
            move |p: &str| format!("/{local}/{p}")
        };
        let item = |marker: &str| Entity::make("contract/data-item", model::map(vec![("marker", model::text(marker))]));
        peer.register_handler(
            HandlerSpec::new("app/contract/data", "data").operations(vec![
                OperationSpec::named("put"),
                OperationSpec::named("get"),
                OperationSpec::named("bind"),
                OperationSpec::named("get_at"),
                OperationSpec::named("unbind"),
                OperationSpec::named("forge"),
            ]),
            move |ctx: &HandlerContext<'_>| {
                let Some(p) = store_peer.upgrade() else {
                    return HandlerResult::error(500, "internal_error", Some("peer gone"));
                };
                let store = &p.store;
                let found = |e: Option<Entity>| {
                    let (typ, marker, hash) = match &e {
                        Some(e) => (e.typ.clone(), e.text_field("marker").unwrap_or("").to_string(), hex(&e.hash)),
                        None => (String::new(), String::new(), String::new()),
                    };
                    any(vec![
                        ("found", Value::Bool(e.is_some())),
                        ("type", model::text(&typ)),
                        ("marker", model::text(&marker)),
                        ("hash", model::text(&hash)),
                    ])
                };
                match ctx.operation() {
                    "put" => {
                        let e = item(&param_text(ctx, "marker"));
                        let accepted = store.put_entity(&e);
                        HandlerResult::ok(any(vec![("hash", model::text(&hex(&e.hash))), ("accepted", Value::Bool(accepted))]))
                    }
                    "get" => {
                        let h = unhex(&param_text(ctx, "hash")).unwrap_or_default();
                        HandlerResult::ok(found(store.get_by_hash(&h)))
                    }
                    "bind" => {
                        let e = item(&param_text(ctx, "marker"));
                        let accepted = store.bind_with_context(&abs(&param_text(ctx, "path")), &e, Some(ctx.exec_context()));
                        HandlerResult::ok(any(vec![("hash", model::text(&hex(&e.hash))), ("accepted", Value::Bool(accepted))]))
                    }
                    "get_at" => HandlerResult::ok(found(store.get_at(&abs(&param_text(ctx, "path"))))),
                    "unbind" => {
                        store.unbind_with_context(&abs(&param_text(ctx, "path")), Some(ctx.exec_context()));
                        HandlerResult::ok(any(vec![]))
                    }
                    "forge" => {
                        // Entity's fields are public, so the forgery is constructible in rust: the
                        // forger's data under the victim's content hash.
                        let mut forged = item(&param_text(ctx, "marker"));
                        forged.hash = item(&param_text(ctx, "victim_marker")).hash;
                        let put_accepted = store.put_entity(&forged);
                        let bind_accepted = store.bind(&abs(&param_text(ctx, "path")), &forged);
                        HandlerResult::ok(any(vec![
                            ("constructible", Value::Bool(true)),
                            ("put_accepted", Value::Bool(put_accepted)),
                            ("bind_accepted", Value::Bool(bind_accepted)),
                        ]))
                    }
                    other => HandlerResult::error(501, "unsupported_operation", Some(other)),
                }
            },
        )
        .map_err(err)?
        .detach();
    }

    // §2.9 evaluator (MODULE).
    peer.set_expression_evaluator(Some(Arc::new(EchoEvaluator)));

    // The removable handle lives in the probe's closure (an Arc clone), so it stays open after
    // configure returns and closes only when the driver asks.
    drop(removable);
    Ok(())
}

fn main() {
    let announce = format!(
        "{{\"package\":\"{}\",\"depends_on\":\"entity-core-protocol-rust\"}}",
        env!("CARGO_PKG_NAME")
    );
    let code = run_host_with(
        std::env::args().skip(1),
        &[("contract_host", announce)],
        install_fixtures,
    );
    std::process::exit(code);
}
