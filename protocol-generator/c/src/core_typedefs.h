/*
 * core_typedefs.h — the §9.5 53-type core floor override table (render-from-model).
 * Each entry names a core type and a builder that returns its `data` ec_value map;
 * the publisher (dispatch.c bootstrap) renders a `system/type` entity from it and binds
 * it at /{peer}/system/type/{name}. The table body lives in the GENERATED core_typedefs.c
 * (tools/gen-typedefs.py from the shared cross-impl type-registry-shapes.json).
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef EC_CORE_TYPEDEFS_H
#define EC_CORE_TYPEDEFS_H

#include "peer_internal.h"

#include <stddef.h>

typedef struct ec_core_typedef {
    const char *name;          /* the core type name (== tree suffix under system/type/) */
    ec_value *(*build)(void);  /* returns a fresh `data` map (caller frees); NULL on OOM */
} ec_core_typedef;

extern const ec_core_typedef ec_core_typedefs[];
extern const size_t ec_core_typedefs_count;

#endif /* EC_CORE_TYPEDEFS_H */
