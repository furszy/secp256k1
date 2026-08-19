/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ICEBERG_KEYGEN_IMPL_H
#define SECP256K1_MODULE_ICEBERG_KEYGEN_IMPL_H

#include <string.h>

#include "../../../include/secp256k1_iceberg.h"
#include "../../../include/secp256k1_iceberg_dealer.h"

#include "rss_impl.h"
#include "scalar_poly_impl.h"
#include "vpss_impl.h"

#include "../../group.h"
#include "../../hash.h"
#include "../../scalar.h"
#include "../../util.h"

/* The label under which the signing key itself is derived. Everything else the
 * group produces is keyed on a session label; the key is keyed on this fixed
 * string, so it is the one sharing that never changes. Fourteen bytes, matching
 * the reference implementation; shares would not be portable otherwise. */
static const unsigned char secp256k1_iceberg_keygen_label[14] = {
    'I', 'c', 'e', 'b', 'e', 'r', 'g', '/', 'k', 'e', 'y', 'g', 'e', 'n'
};

static const unsigned char secp256k1_iceberg_share_magic[4] = { 0x1c, 0xeb, 0x27, 0x5a };
static const unsigned char secp256k1_iceberg_cache_magic[4] = { 0x1c, 0xeb, 0xc4, 0x03 };
static const unsigned char secp256k1_iceberg_pubshare_magic[4] = { 0x1c, 0xeb, 0x9d, 0xf1 };

/* share:    magic(4) | n(1) t(1) k(1) pad(1) | seeds[MAX_SEEDS][32]
 * cache:    magic(4) | n(1) t(1) k(1) pad(1) | weights[MAX_SEEDS][32]
 * pubshare: magic(4) | index(1) | ge_to_bytes_ext(64)
 *
 * Both share and cache are sized for the worst configuration, not the one in
 * use, so a 2-of-3 group carries mostly padding. That is the price of a
 * fixed-size opaque type in a library that never allocates; the serialized
 * forms are exact. */

static void secp256k1_iceberg_share_save(secp256k1_iceberg_share *share, unsigned int n, unsigned int t, unsigned int k) {
    /* Zero the whole object, not just the header. Only C(n-1, t-1) of the seed
     * slots are ever written, and leaving the rest as whatever was on the stack
     * would make two shares holding identical secrets compare unequal, and
     * would put uninitialized memory into anything that copies the struct. */
    memset(share->data, 0, sizeof(share->data));
    memcpy(share->data, secp256k1_iceberg_share_magic, 4);
    share->data[4] = (unsigned char)n;
    share->data[5] = (unsigned char)t;
    share->data[6] = (unsigned char)k;
    share->data[7] = 0;
}

/* Unpacks the header and hands back a pointer to the seeds. Returns the number
 * of seeds, or 0 if the object is not a well-formed share. */
static size_t secp256k1_iceberg_share_load(const secp256k1_context *ctx, unsigned int *n, unsigned int *t, unsigned int *k, const unsigned char **seeds, const secp256k1_iceberg_share *share) {
    ARG_CHECK(secp256k1_memcmp_var(share->data, secp256k1_iceberg_share_magic, 4) == 0);
    *n = share->data[4];
    *t = share->data[5];
    *k = share->data[6];
    ARG_CHECK(*n >= 1 && *n <= SECP256K1_ICEBERG_MAX_PARTICIPANTS);
    ARG_CHECK(*t >= 1 && *t <= (*n + 1) / 2);
    ARG_CHECK(*k >= 1 && *k <= *n);
    *seeds = &share->data[8];
    return secp256k1_rss_binom(*n - 1, *t - 1);
}

/* TODO: this call is optional and every caller of it can pass NULL instead, so
 * the saving has to justify an extra type in the API. What it avoids per call
 * is C(n, t-1) subset unrankings and count*(2t+2) - 3 scalar multiplications,
 * about 1500 at 5-of-10. bench_iceberg times share_cache_create and times the
 * three consumers without a cache; it does not time them with one, so the
 * saving is not yet a row you can read off. */
int secp256k1_iceberg_share_cache_create(const secp256k1_context *ctx, secp256k1_iceberg_share_cache *cache, const secp256k1_iceberg_share *share) {
    secp256k1_scalar weights[SECP256K1_ICEBERG_MAX_SEEDS];
    const unsigned char *seeds;
    unsigned int n, t, k;
    size_t count, i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(cache != NULL);
    memset(cache, 0, sizeof(*cache));
    ARG_CHECK(share != NULL);

    count = secp256k1_iceberg_share_load(ctx, &n, &t, &k, &seeds, share);
    if (count == 0) {
        return 0;
    }
    if (secp256k1_rss_lagrange_weights_var(weights, n, t, k) != count) {
        return 0;
    }

    memcpy(cache->data, secp256k1_iceberg_cache_magic, 4);
    cache->data[4] = (unsigned char)n;
    cache->data[5] = (unsigned char)t;
    cache->data[6] = (unsigned char)k;
    cache->data[7] = 0;
    for (i = 0; i < count; i++) {
        secp256k1_scalar_get_b32(&cache->data[8 + 32 * i], &weights[i]);
    }
    return 1;
}

/* Loads weights for this share, deriving them if the caller did not supply a
 * cache. */
static int secp256k1_iceberg_weights_for(const secp256k1_context *ctx, secp256k1_scalar *weights, size_t count, unsigned int n, unsigned int t, unsigned int k, const secp256k1_iceberg_share_cache *cache) {
    size_t i;

    if (cache == NULL) {
        return secp256k1_rss_lagrange_weights_var(weights, n, t, k) == count;
    }
    ARG_CHECK(secp256k1_memcmp_var(cache->data, secp256k1_iceberg_cache_magic, 4) == 0);
    /* A cache built for a different participant would silently produce a wrong
     * share, so the pairing is checked and not assumed. */
    ARG_CHECK(cache->data[4] == n && cache->data[5] == t && cache->data[6] == k);
    for (i = 0; i < count; i++) {
        secp256k1_scalar_set_b32(&weights[i], &cache->data[8 + 32 * i], NULL);
    }
    return 1;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("Iceberg/dealer")||SHA256("Iceberg/dealer"). */
static void secp256k1_iceberg_dealer_sha256_tagged(secp256k1_sha256 *sha) {
    static const uint32_t midstate[8] = {
        0xb40815eaul, 0x9e117bfaul, 0x4a71724ful, 0x1f71a00eul,
        0x19cf3ed1ul, 0xd5ff1efcul, 0xeb8b1dd5ul, 0x024d39e8ul
    };
    secp256k1_sha256_initialize_midstate(sha, 64, midstate);
}

/* The seed named after one subset: H_"Iceberg/dealer"(root || n || t || rank).
 *
 * It depends on the rank and not on who receives it, which is the whole of
 * replicated sharing: every participant outside the subset is handed this same
 * value. Deriving all of them from one root keeps dealing reproducible, which is
 * what makes test vectors possible, and it also means the root is as sensitive
 * as the group key and must be destroyed afterwards. */
static void secp256k1_iceberg_dealer_seed(const secp256k1_context *ctx, unsigned char *seed, const unsigned char *root32, unsigned int n, unsigned int t, uint32_t rank) {
    secp256k1_sha256 sha;
    unsigned char header[6];

    header[0] = (unsigned char)n;
    header[1] = (unsigned char)t;
    header[2] = (unsigned char)(rank >> 24);
    header[3] = (unsigned char)(rank >> 16);
    header[4] = (unsigned char)(rank >> 8);
    header[5] = (unsigned char)rank;
    secp256k1_iceberg_dealer_sha256_tagged(&sha);
    secp256k1_sha256_write(secp256k1_get_hash_context(ctx), &sha, root32, 32);
    secp256k1_sha256_write(secp256k1_get_hash_context(ctx), &sha, header, sizeof(header));
    secp256k1_sha256_finalize(secp256k1_get_hash_context(ctx), &sha, seed);
    secp256k1_sha256_clear(&sha);
}

int secp256k1_iceberg_shares_gen(const secp256k1_context *ctx, secp256k1_iceberg_share * const *shares, unsigned int n, unsigned int t, const unsigned char *seed32) {
    unsigned char seed[32];
    uint32_t total, rank;
    unsigned int k;

    VERIFY_CHECK(ctx != NULL);
    /* The out-params cannot be zeroed before n is validated, since n is what
     * says how many of them there are. A caller that ignores the return value
     * keeps whatever it passed in. */
    ARG_CHECK(shares != NULL);
    ARG_CHECK(seed32 != NULL);
    ARG_CHECK(n >= 1 && n <= SECP256K1_ICEBERG_MAX_PARTICIPANTS);
    /* The quorum needed to verify a sharing is 2t-1 and cannot exceed the
     * group, which is what makes Iceberg a minority-threshold scheme. Rejecting
     * here means callers meet the limitation at setup, not at signing.
     *
     * Written as t <= (n+1)/2 rather than 2t-1 <= n, which is the same
     * predicate over the integers but not over unsigned int: t is the caller's
     * to choose, and doubling it first lets a t near UINT_MAX wrap back inside
     * the bound. The dealer would then find C(n, t-1) == 0, write no seeds at
     * all, and return 1 on a group whose key is a public constant. */
    ARG_CHECK(t >= 1 && t <= (n + 1) / 2);
    for (k = 1; k <= n; k++) {
        ARG_CHECK(shares[k - 1] != NULL);
    }

    /* One participant at a time. Its share is exactly the seeds whose subsets
     * leave it out, appended in rank order.
     *
     * That ordering is the share layout, and it is not private to this function:
     * secp256k1_rss_lagrange_weights_var walks the same subsets in the same order
     * to produce one weight per seed, so seed i and weight i belong to each
     * other. Dealing per participant costs a repeated derivation, since a
     * subset's seed goes to every participant outside it, but the dealer runs
     * once per group. */
    total = secp256k1_rss_binom(n, t - 1);
    for (k = 1; k <= n; k++) {
        size_t held = 0;

        secp256k1_iceberg_share_save(shares[k - 1], n, t, k);
        for (rank = 0; rank < total; rank++) {
            if (secp256k1_rss_subset_unrank(n, t - 1, rank) & (secp256k1_rss_subset)(1u << k)) {
                continue;
            }
            secp256k1_iceberg_dealer_seed(ctx, seed, seed32, n, t, rank);
            memcpy(&shares[k - 1]->data[8 + 32 * held], seed, 32);
            held++;
        }
    }

    secp256k1_memclear_explicit(seed, sizeof(seed));
    return 1;
}

int secp256k1_iceberg_share_serialize(const secp256k1_context *ctx, unsigned char *out, size_t *outlen, const secp256k1_iceberg_share *share) {
    const unsigned char *seeds;
    unsigned int n, t, k;
    size_t count, needed;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(outlen != NULL);
    ARG_CHECK(out != NULL);
    ARG_CHECK(share != NULL);

    count = secp256k1_iceberg_share_load(ctx, &n, &t, &k, &seeds, share);
    if (count == 0) {
        /* A malformed share has no length to report, and the caller is told to
         * size a second call from *outlen. Leaving the old value there would
         * send it round the same loop forever. */
        *outlen = 0;
        return 0;
    }
    needed = 4 + 32 * count;
    if (*outlen < needed) {
        *outlen = needed;
        return 0;
    }
    out[0] = 1; /* format version */
    out[1] = (unsigned char)n;
    out[2] = (unsigned char)t;
    out[3] = (unsigned char)k;
    memcpy(&out[4], seeds, 32 * count);
    *outlen = needed;
    return 1;
}

int secp256k1_iceberg_share_parse(const secp256k1_context *ctx, secp256k1_iceberg_share *share, const unsigned char *in, size_t inlen) {
    unsigned int n, t, k;
    size_t count;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(share != NULL);
    memset(share, 0, sizeof(*share));
    ARG_CHECK(in != NULL);

    if (inlen < 4 || in[0] != 1) {
        return 0;
    }
    n = in[1];
    t = in[2];
    k = in[3];
    if (n < 1 || n > SECP256K1_ICEBERG_MAX_PARTICIPANTS) {
        return 0;
    }
    if (t < 1 || t > (n + 1) / 2 || k < 1 || k > n) {
        return 0;
    }
    count = secp256k1_rss_binom(n - 1, t - 1);
    if (inlen != 4 + 32 * count) {
        return 0;
    }

    secp256k1_iceberg_share_save(share, n, t, k);
    memcpy(&share->data[8], &in[4], 32 * count);
    return 1;
}

static void secp256k1_iceberg_pubshare_save(secp256k1_iceberg_pubshare *pubshare, unsigned int k, const secp256k1_ge *ge) {
    memcpy(pubshare->data, secp256k1_iceberg_pubshare_magic, 4);
    pubshare->data[4] = (unsigned char)k;
    secp256k1_ge_to_bytes_ext(&pubshare->data[5], ge);
}

static int secp256k1_iceberg_pubshare_load(const secp256k1_context *ctx, unsigned int *k, secp256k1_ge *ge, const secp256k1_iceberg_pubshare *pubshare) {
    ARG_CHECK(secp256k1_memcmp_var(pubshare->data, secp256k1_iceberg_pubshare_magic, 4) == 0);
    *k = pubshare->data[4];
    ARG_CHECK(*k >= 1 && *k <= SECP256K1_ICEBERG_MAX_PARTICIPANTS);
    secp256k1_ge_from_bytes_ext(ge, &pubshare->data[5]);
    return 1;
}

int secp256k1_iceberg_pubshare_gen(const secp256k1_context *ctx, secp256k1_iceberg_pubshare *pubshare, const secp256k1_iceberg_share *share, const secp256k1_iceberg_share_cache *cache) {
    secp256k1_scalar weights[SECP256K1_ICEBERG_MAX_SEEDS];
    secp256k1_scalar d;
    secp256k1_gej dj;
    secp256k1_ge point;
    const unsigned char *seeds;
    unsigned int n, t, k;
    size_t count;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubshare != NULL);
    memset(pubshare, 0, sizeof(*pubshare));
    ARG_CHECK(share != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));

    count = secp256k1_iceberg_share_load(ctx, &n, &t, &k, &seeds, share);
    if (count == 0 || !secp256k1_iceberg_weights_for(ctx, weights, count, n, t, k, cache)) {
        return 0;
    }

    secp256k1_rss_eval(secp256k1_get_hash_context(ctx), &d, seeds, weights, count,
                       secp256k1_iceberg_keygen_label, sizeof(secp256k1_iceberg_keygen_label));
    secp256k1_ecmult_gen_gej(&ctx->ecmult_gen_ctx, &dj, &d);
    secp256k1_ge_set_gej(&point, &dj);
    /* The commitment is about to be published, so it stops being secret here. */
    secp256k1_declassify(ctx, &point, sizeof(point));
    secp256k1_iceberg_pubshare_save(pubshare, k, &point);

    secp256k1_scalar_clear(&d);
    return 1;
}

int secp256k1_iceberg_pubshare_serialize(const secp256k1_context *ctx, unsigned char *out34, const secp256k1_iceberg_pubshare *pubshare) {
    secp256k1_ge point;
    unsigned int k;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out34 != NULL);
    memset(out34, 0, 34);
    ARG_CHECK(pubshare != NULL);

    if (!secp256k1_iceberg_pubshare_load(ctx, &k, &point, pubshare)) {
        return 0;
    }
    out34[0] = (unsigned char)k;
    secp256k1_musig_ge_serialize_ext(&out34[1], &point);
    return 1;
}

int secp256k1_iceberg_pubshare_parse(const secp256k1_context *ctx, secp256k1_iceberg_pubshare *pubshare, const unsigned char *in34) {
    secp256k1_ge point;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubshare != NULL);
    memset(pubshare, 0, sizeof(*pubshare));
    ARG_CHECK(in34 != NULL);

    if (in34[0] < 1 || in34[0] > SECP256K1_ICEBERG_MAX_PARTICIPANTS) {
        return 0;
    }
    if (!secp256k1_musig_ge_parse_ext(&point, &in34[1])) {
        return 0;
    }
    secp256k1_iceberg_pubshare_save(pubshare, in34[0], &point);
    return 1;
}

int secp256k1_iceberg_pubkey_agg(const secp256k1_context *ctx, secp256k1_pubkey *group_pk, const secp256k1_iceberg_pubshare * const *pubshares, size_t n_pubshares, unsigned int n, unsigned int t) {
    unsigned char idx[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_ge points[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_gej combined;
    secp256k1_ge result;
    size_t i, j;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(group_pk != NULL);
    memset(group_pk, 0, sizeof(*group_pk));
    ARG_CHECK(pubshares != NULL);
    ARG_CHECK(n >= 1 && n <= SECP256K1_ICEBERG_MAX_PARTICIPANTS);
    ARG_CHECK(t >= 1 && t <= (n + 1) / 2);
    /* Below 2t-1 the degree check proves nothing: too few honest points remain
     * to pin the true polynomial, and a coalition could present a consistent
     * sharing of a value it chose. Safe to double t here: the bound above has
     * already put it under (n+1)/2. How many members published is a fact about
     * the group rather than a caller bug, so it returns; a null entry in the
     * sweep below is a caller bug and gets the illegal callback.
     *
     * More shares than the group has is a repeated index by the pigeonhole, so
     * the loop below would refuse it anyway. The bound is here because idx and
     * points are sized for the largest group. */
    if (n_pubshares < 2 * (size_t)t - 1 || n_pubshares > n) {
        return 0;
    }
    for (i = 0; i < n_pubshares; i++) {
        ARG_CHECK(pubshares[i] != NULL);
    }

    for (i = 0; i < n_pubshares; i++) {
        unsigned int k;
        if (!secp256k1_iceberg_pubshare_load(ctx, &k, &points[i], pubshares[i])) {
            return 0;
        }
        /* An index above n names no member of this group, so nothing could have
         * authenticated what it carries. */
        if (k > n) {
            return 0;
        }
        idx[i] = (unsigned char)k;
        /* Duplicate indices would make the interpolation singular, and are how
         * a caller most easily passes fewer distinct participants than it
         * believes it has. */
        for (j = 0; j < i; j++) {
            if (idx[j] == idx[i]) {
                return 0;
            }
        }
    }

    if (!secp256k1_vpss_verify_var(ctx, idx, points, n_pubshares, t)) {
        return 0;
    }
    if (!secp256k1_vpss_combine_var(ctx, &combined, idx, points, n_pubshares)) {
        return 0;
    }
    if (secp256k1_gej_is_infinity(&combined)) {
        return 0;
    }
    secp256k1_ge_set_gej(&result, &combined);
    secp256k1_pubkey_save(group_pk, &result);
    return 1;
}

#endif /* SECP256K1_MODULE_ICEBERG_KEYGEN_IMPL_H */
