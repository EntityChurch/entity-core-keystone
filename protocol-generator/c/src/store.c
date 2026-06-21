/*
 * store.c — the foundation storage (§1.7): two layers.
 *
 *   content store: hash-hex (66 chars) → entity   (immutable, content-addressed, dedup)
 *   entity tree:   path                 → hash-hex (mutable location index)
 *
 * In-memory minimal impl. §4.8 data-race safety (N6): a single pthread_rwlock_t guards
 * BOTH maps (many concurrent readers / one exclusive writer) — reads dominate the
 * dispatch path, so the rwlock beats a plain mutex (profile [concurrency].store_safety).
 * A data race here is a FAIL; the rwlock makes consistency structural.
 *
 * §6.13(c) emit bus: tree binds fire registered consumers — LIVE with zero consumers so
 * a future extension can register WITHOUT rebuilding the peer. A core peer registers none.
 *
 * Implementation note: the two maps are simple growable open-addressing-free arrays of
 * (key,value) — the conformance/loopback surface holds O(100) entries, so a linear/array
 * map is the dependency-minimal idiomatic choice (no hashtable dep). Lookups are linear;
 * fine at this scale and trivially correct under the rwlock.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "peer_internal.h"

#include <stdlib.h>
#include <string.h>

typedef struct content_row {
    char hex[67];               /* 66-char lowercase hex + NUL */
    ec_entity *entity;          /* +1 ref */
} content_row;

typedef struct tree_row {
    char *path;                 /* owned */
    char hex[67];               /* hash-hex bound here */
} tree_row;

typedef struct consumer_row {
    ec_tree_consumer fn;
    void *ctx;
} consumer_row;

struct ec_store {
    content_row *content;
    size_t content_len, content_cap;
    tree_row *tree;
    size_t tree_len, tree_cap;
    consumer_row *consumers;
    size_t consumers_len, consumers_cap;
    pthread_rwlock_t lock;      /* §4.8: many-reader / one-writer */
};

ec_status ec_store_new(ec_store **out)
{
    ec_store *s = calloc(1, sizeof(*s));
    if (!s) {
        return EC_ERR_OOM;
    }
    if (pthread_rwlock_init(&s->lock, NULL) != 0) {
        free(s);
        return EC_ERR_CRYPTO;
    }
    *out = s;
    return EC_OK;
}

void ec_store_free(ec_store *s)
{
    if (!s) {
        return;
    }
    for (size_t i = 0; i < s->content_len; i++) {
        ec_entity_unref(s->content[i].entity);
    }
    free(s->content);
    for (size_t i = 0; i < s->tree_len; i++) {
        free(s->tree[i].path);
    }
    free(s->tree);
    free(s->consumers);
    pthread_rwlock_destroy(&s->lock);
    free(s);
}

/* ── content store (caller holds the write lock) ────────────────────────────── */

static content_row *content_find(ec_store *s, const char *hex)
{
    for (size_t i = 0; i < s->content_len; i++) {
        if (memcmp(s->content[i].hex, hex, 67) == 0) {
            return &s->content[i];
        }
    }
    return NULL;
}

/* Put under the write lock; returns true if a NEW entity was inserted. */
static bool content_put_locked(ec_store *s, ec_entity *e)
{
    char hex[67];
    char *h = ec_hex(e->hash, 33);
    if (!h) {
        return false;           /* OOM: best-effort drop (deliver-or-signal §4.9) */
    }
    memcpy(hex, h, 67);
    free(h);
    if (content_find(s, hex)) {
        return false;
    }
    if (s->content_len == s->content_cap) {
        size_t cap = s->content_cap ? s->content_cap * 2 : 16;
        content_row *grown = realloc(s->content, cap * sizeof(*grown));
        if (!grown) {
            return false;
        }
        s->content = grown;
        s->content_cap = cap;
    }
    memcpy(s->content[s->content_len].hex, hex, 67);
    s->content[s->content_len].entity = ec_entity_ref(e);
    s->content_len++;
    return true;
}

void ec_store_put(ec_store *s, ec_entity *e)
{
    if (!s || !e) {
        return;
    }
    pthread_rwlock_wrlock(&s->lock);
    content_put_locked(s, e);
    pthread_rwlock_unlock(&s->lock);
}

ec_entity *ec_store_get_by_hash(ec_store *s, const uint8_t *h33)
{
    if (!s || !h33) {
        return NULL;
    }
    char *hex = ec_hex(h33, 33);
    if (!hex) {
        return NULL;
    }
    pthread_rwlock_rdlock(&s->lock);
    content_row *r = content_find(s, hex);
    ec_entity *out = r ? ec_entity_ref(r->entity) : NULL;
    pthread_rwlock_unlock(&s->lock);
    free(hex);
    return out;
}

/* ── entity tree (caller holds the write lock) ──────────────────────────────── */

static tree_row *tree_find(ec_store *s, const char *path)
{
    for (size_t i = 0; i < s->tree_len; i++) {
        if (strcmp(s->tree[i].path, path) == 0) {
            return &s->tree[i];
        }
    }
    return NULL;
}

/* Fire tree consumers after a binding change (called outside the lock). */
static void fire_tree(ec_store *s, const char *path)
{
    /* snapshot consumer list under read lock to avoid holding it during callbacks */
    consumer_row *snap = NULL;
    size_t n = 0;
    pthread_rwlock_rdlock(&s->lock);
    n = s->consumers_len;
    if (n) {
        snap = malloc(n * sizeof(*snap));
        if (snap) {
            memcpy(snap, s->consumers, n * sizeof(*snap));
        }
    }
    pthread_rwlock_unlock(&s->lock);
    if (snap) {
        for (size_t i = 0; i < n; i++) {
            snap[i].fn(snap[i].ctx, path);
        }
        free(snap);
    }
}

void ec_store_bind(ec_store *s, const char *path, ec_entity *e)
{
    if (!s || !path || !e) {
        return;
    }
    bool changed = false;
    char next_hex[67];
    char *h = ec_hex(e->hash, 33);
    if (!h) {
        return;
    }
    memcpy(next_hex, h, 67);
    free(h);

    pthread_rwlock_wrlock(&s->lock);
    content_put_locked(s, e);
    tree_row *r = tree_find(s, path);
    if (r) {
        if (memcmp(r->hex, next_hex, 67) != 0) {
            memcpy(r->hex, next_hex, 67);
            changed = true;
        }
    } else {
        if (s->tree_len == s->tree_cap) {
            size_t cap = s->tree_cap ? s->tree_cap * 2 : 32;
            tree_row *grown = realloc(s->tree, cap * sizeof(*grown));
            if (!grown) {
                pthread_rwlock_unlock(&s->lock);
                return;
            }
            s->tree = grown;
            s->tree_cap = cap;
        }
        s->tree[s->tree_len].path = strdup(path);
        if (!s->tree[s->tree_len].path) {
            pthread_rwlock_unlock(&s->lock);
            return;
        }
        memcpy(s->tree[s->tree_len].hex, next_hex, 67);
        s->tree_len++;
        changed = true;
    }
    pthread_rwlock_unlock(&s->lock);

    if (changed) {
        fire_tree(s, path);
    }
}

void ec_store_unbind(ec_store *s, const char *path)
{
    if (!s || !path) {
        return;
    }
    bool changed = false;
    pthread_rwlock_wrlock(&s->lock);
    for (size_t i = 0; i < s->tree_len; i++) {
        if (strcmp(s->tree[i].path, path) == 0) {
            free(s->tree[i].path);
            s->tree[i] = s->tree[s->tree_len - 1];
            s->tree_len--;
            changed = true;
            break;
        }
    }
    pthread_rwlock_unlock(&s->lock);
    if (changed) {
        fire_tree(s, path);
    }
}

ec_entity *ec_store_get_at(ec_store *s, const char *path)
{
    if (!s || !path) {
        return NULL;
    }
    pthread_rwlock_rdlock(&s->lock);
    ec_entity *out = NULL;
    tree_row *r = tree_find(s, path);
    if (r) {
        content_row *c = content_find(s, r->hex);
        if (c) {
            out = ec_entity_ref(c->entity);
        }
    }
    pthread_rwlock_unlock(&s->lock);
    return out;
}

ec_status ec_store_hash_at(ec_store *s, const char *path, char **out_hex)
{
    if (!s || !path || !out_hex) {
        return EC_ERR_BAD_INPUT;
    }
    pthread_rwlock_rdlock(&s->lock);
    tree_row *r = tree_find(s, path);
    ec_status st = EC_ERR_BAD_INPUT;
    if (r) {
        char *copy = strdup(r->hex);
        if (copy) {
            *out_hex = copy;
            st = EC_OK;
        } else {
            st = EC_ERR_OOM;
        }
    }
    pthread_rwlock_unlock(&s->lock);
    return st;
}

/* ── one-level listing (§3.9, sorted by segment) ────────────────────────────── */

ec_status ec_store_listing(ec_store *s, const char *prefix,
                           ec_list_entry **out, size_t *out_n)
{
    if (!s || !prefix || !out || !out_n) {
        return EC_ERR_BAD_INPUT;
    }
    /* normalize prefix to end with '/' */
    size_t plen = strlen(prefix);
    bool trailing = (plen > 0 && prefix[plen - 1] == '/');
    char *p = malloc(plen + 2);
    if (!p) {
        return EC_ERR_OOM;
    }
    memcpy(p, prefix, plen);
    if (!trailing) {
        p[plen++] = '/';
    }
    p[plen] = 0;

    ec_list_entry *rows = NULL;
    size_t nrows = 0, cap = 0;
    ec_status st = EC_OK;

    pthread_rwlock_rdlock(&s->lock);
    for (size_t i = 0; i < s->tree_len; i++) {
        const char *path = s->tree[i].path;
        size_t pathlen = strlen(path);
        if (pathlen <= plen || strncmp(path, p, plen) != 0) {
            continue;
        }
        const char *rest = path + plen;
        const char *slash = strchr(rest, '/');
        size_t seglen = slash ? (size_t)(slash - rest) : strlen(rest);
        bool deeper = (slash != NULL);
        /* find existing row for this segment */
        ec_list_entry *row = NULL;
        for (size_t j = 0; j < nrows; j++) {
            if (strlen(rows[j].segment) == seglen &&
                memcmp(rows[j].segment, rest, seglen) == 0) {
                row = &rows[j];
                break;
            }
        }
        if (!row) {
            if (nrows == cap) {
                size_t ncap = cap ? cap * 2 : 8;
                ec_list_entry *grown = realloc(rows, ncap * sizeof(*grown));
                if (!grown) {
                    st = EC_ERR_OOM;
                    break;
                }
                rows = grown;
                cap = ncap;
            }
            row = &rows[nrows++];
            row->segment = strndup(rest, seglen);
            row->hash_hex[0] = 0;
            row->has_children = false;
            if (!row->segment) {
                nrows--;
                st = EC_ERR_OOM;
                break;
            }
        }
        if (deeper) {
            row->has_children = true;
        } else {
            memcpy(row->hash_hex, s->tree[i].hex, 67);
        }
    }
    pthread_rwlock_unlock(&s->lock);
    free(p);

    if (st != EC_OK) {
        ec_store_listing_free(rows, nrows);
        return st;
    }

    /* sort by segment (insertion sort — small n) */
    for (size_t i = 1; i < nrows; i++) {
        ec_list_entry tmp = rows[i];
        size_t j = i;
        while (j > 0 && strcmp(rows[j - 1].segment, tmp.segment) > 0) {
            rows[j] = rows[j - 1];
            j--;
        }
        rows[j] = tmp;
    }

    *out = rows;
    *out_n = nrows;
    return EC_OK;
}

void ec_store_listing_free(ec_list_entry *rows, size_t n)
{
    if (!rows) {
        return;
    }
    for (size_t i = 0; i < n; i++) {
        free(rows[i].segment);
    }
    free(rows);
}

void ec_store_register_tree_consumer(ec_store *s, ec_tree_consumer fn, void *ctx)
{
    if (!s || !fn) {
        return;
    }
    pthread_rwlock_wrlock(&s->lock);
    if (s->consumers_len == s->consumers_cap) {
        size_t cap = s->consumers_cap ? s->consumers_cap * 2 : 4;
        consumer_row *grown = realloc(s->consumers, cap * sizeof(*grown));
        if (grown) {
            s->consumers = grown;
            s->consumers_cap = cap;
        }
    }
    if (s->consumers_len < s->consumers_cap) {
        s->consumers[s->consumers_len].fn = fn;
        s->consumers[s->consumers_len].ctx = ctx;
        s->consumers_len++;
    }
    pthread_rwlock_unlock(&s->lock);
}
