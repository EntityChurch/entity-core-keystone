// entity_core/core_typedefs.hpp — the §9.5 53-type core floor override table
// (render-from-model). Each entry names a core type and a builder returning its `data`
// EcfValue map; the peer bootstrap renders a `system/type` entity from it and binds it at
// /{peer}/system/type/{name}. The table body lives in the GENERATED core_typedefs.cpp
// (tools/gen-typedefs.py from the shared cross-impl type-registry-shapes.json).
//
// SPDX-License-Identifier: Apache-2.0
#ifndef ENTITY_CORE_CORE_TYPEDEFS_HPP
#define ENTITY_CORE_CORE_TYPEDEFS_HPP

#include <string>
#include <vector>

#include "entity_core/ecf.hpp"

namespace entity_core::types {

struct CoreTypeDef {
    std::string name;                  // the core type name (== tree suffix under system/type/)
    ecf::EcfValue (*build)();          // returns a fresh `data` map
};

// The §9.5 core floor (53 types), in a stable order. ECF Rule-2 canonical re-sort makes
// the emit order immaterial to each rendered content_hash.
const std::vector<CoreTypeDef>& core_typedefs();

}  // namespace entity_core::types

#endif  // ENTITY_CORE_CORE_TYPEDEFS_HPP
