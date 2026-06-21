/*
 * typereg.c — render-from-model byte-diff harness for the §9.5 53-type core floor.
 * Builds each core type's `data` map (the GENERATED core_typedefs table), materializes a
 * `system/type` entity (content_hash computed by our own S2-green codec), and prints
 * "name <hex32>" for the 32-byte SHA-256 digest (the entity hash minus its 0x00 format
 * prefix). The runner diffs this against the canonical type-registry-vectors-v1 hashes.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "peer_internal.h"
#include "core_typedefs.h"

#include <stdio.h>

int main(void)
{
    int rc = 0;
    for (size_t i = 0; i < ec_core_typedefs_count; i++) {
        ec_value *data = ec_core_typedefs[i].build();
        if (!data) {
            fprintf(stderr, "build failed: %s\n", ec_core_typedefs[i].name);
            rc = 1;
            continue;
        }
        ec_entity *e = NULL;
        if (ec_entity_make_owning("system/type", data, &e) != EC_OK) {
            fprintf(stderr, "make failed: %s\n", ec_core_typedefs[i].name);
            rc = 1;
            continue;
        }
        printf("%s ", ec_core_typedefs[i].name);
        for (int b = 1; b < 33; b++) {      /* skip the 0x00 format prefix */
            printf("%02x", e->hash[b]);
        }
        printf("\n");
        ec_entity_unref(e);
    }
    return rc;
}
