(* Core type floor (V7 §9.5) — render-from-model. The 53 core type *models* live
   in [Type_defs_data] (an in-code override table generated from the cross-impl
   Go-rendered type shapes); here we render each to a materialized
   [system/type] entity and publish it at system/type/{name}.

   Render-from-model, not ingest-bytes: the entity's content_hash is computed by
   our own S2 codec over the model, then diffed against the canonical
   type-registry vectors (test/type_registry.ml). A core peer publishes exactly
   these 53 (§9.5) — matched-if-present for anything outside the floor. *)

(* (type_name, rendered system/type entity) for all 53 core types. *)
let all : (string * Model.entity) list =
  List.map (fun (name, data) -> (name, Model.make ~typ:"system/type" data)) Type_defs_data.core_types

(* Publish every core type at its tree path under the local peer's namespace:
   /{peer}/system/type/{name}. The bytes are also content-addressed in the store. *)
let publish (store : Store.t) ~(local_peer : string) : unit =
  List.iter
    (fun (name, e) ->
      Store.bind store ~path:("/" ^ local_peer ^ "/system/type/" ^ name) e)
    all
