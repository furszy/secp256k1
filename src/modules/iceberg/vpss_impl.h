/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ICEBERG_VPSS_IMPL_H
#define SECP256K1_MODULE_ICEBERG_VPSS_IMPL_H

#include "../../../include/secp256k1_iceberg.h"

#include "vpss.h"
#include "scalar_poly_impl.h"

#include "../../ecmult.h"
#include "../../group.h"
#include "../../hash.h"
#include "../../scalar.h"
#include "../../util.h"

/* Both operations here are a weighted sum of the same points, so they share one
 * callback and differ only in how the weights were computed. */
typedef struct {
    const secp256k1_ge *points;
    const secp256k1_scalar *weights;
} secp256k1_vpss_multi_data;

static int secp256k1_vpss_multi_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_vpss_multi_data *ctx = (secp256k1_vpss_multi_data *)data;
    *sc = ctx->weights[idx];
    *pt = ctx->points[idx];
    return 1;
}

static int secp256k1_vpss_weighted_sum_var(const secp256k1_context *ctx, secp256k1_gej *r, const secp256k1_ge *points, const secp256k1_scalar *weights, size_t m) {
    secp256k1_vpss_multi_data data;
    data.points = points;
    data.weights = weights;
    /* No scratch space: the library does not allocate at runtime, and with at
     * most ten points the simple path this falls back to is the right one
     * anyway. This mirrors what musig's key aggregation does.
     *
     * Which also means this cannot return 0. Without a scratch space
     * ecmult_multi_var takes the simple path, and that fails only on a callback
     * that fails; ours cannot. Reaching a zero here would take a change to one
     * of those two things, which is why the callers still test it. */
    return secp256k1_ecmult_multi_var(&ctx->error_callback, NULL, r, NULL,
                                      secp256k1_vpss_multi_callback, &data, m);
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("Iceberg/batchcoef")||SHA256("Iceberg/batchcoef"). */
static void secp256k1_vpss_batchcoef_sha256_tagged(secp256k1_sha256 *sha) {
    static const uint32_t midstate[8] = {
        0xdbf8f1f6ul, 0xc46235d4ul, 0xc3d5e6fdul, 0xaed98a69ul,
        0x739fc2e8ul, 0x686b55faul, 0xb3b06820ul, 0x7f3c361bul
    };
    secp256k1_sha256_initialize_midstate(sha, 64, midstate);
}

static int secp256k1_vpss_verify_var(const secp256k1_context *ctx, const unsigned char *idx, secp256k1_ge *points, size_t m, unsigned int t) {
    secp256k1_scalar basis[SECP256K1_ICEBERG_MAX_PARTICIPANTS * SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_scalar weights[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_sha256 transcript;
    secp256k1_gej sum;
    unsigned char header[2];
    unsigned char buf[33];
    size_t i, j;

    VERIFY_CHECK(t >= 1 && m <= SECP256K1_ICEBERG_MAX_PARTICIPANTS);

    /* Below t the loop at the end runs zero times, and an empty sum is the
     * identity, so this would report success on a set too small to constrain
     * anything. No caller reaches it today; a degree check is the wrong place to
     * fail open if one ever does. */
    if (m < t) {
        return 0;
    }
    /* With m == t the interpolation is exactly determined and there is no
     * high coefficient left to test. Nothing has been proved, but nothing has
     * been violated either. */
    if (m == t) {
        return 1;
    }

    /* The naive check tests each high coefficient separately: for every
     * i in [t, m), sum_j basis[j][i] * points[j] must be the identity. Testing
     * a random linear combination of those equations instead collapses m-t
     * multiexponentiations into one. If any coefficient is non-zero, the
     * combination is the identity only if the weights happen to lie on a
     * hyperplane, which a hash commits them away from. The transcript covers
     * every input that defines the statement, so weights are fixed only after
     * the prover has committed to the points. */
    secp256k1_vpss_batchcoef_sha256_tagged(&transcript);
    header[0] = (unsigned char)t;
    header[1] = (unsigned char)m;
    secp256k1_sha256_write(secp256k1_get_hash_context(ctx), &transcript, header, sizeof(header));
    secp256k1_sha256_write(secp256k1_get_hash_context(ctx), &transcript, idx, m);
    for (j = 0; j < m; j++) {
        secp256k1_musig_ge_serialize_ext(buf, &points[j]);
        secp256k1_sha256_write(secp256k1_get_hash_context(ctx), &transcript, buf, sizeof(buf));
    }

    secp256k1_scalarpoly_lagrange_basis_var(basis, idx, m);
    for (j = 0; j < m; j++) {
        secp256k1_scalar_set_int(&weights[j], 0);
    }
    for (i = t; i < m; i++) {
        secp256k1_sha256 fork = transcript;
        secp256k1_scalar rho, term;
        unsigned char which = (unsigned char)i;
        unsigned char out[32];

        secp256k1_sha256_write(secp256k1_get_hash_context(ctx), &fork, &which, 1);
        secp256k1_sha256_finalize(secp256k1_get_hash_context(ctx), &fork, out);
        secp256k1_scalar_set_b32(&rho, out, NULL);

        for (j = 0; j < m; j++) {
            secp256k1_scalar_mul(&term, &rho, &basis[j * m + i]);
            secp256k1_scalar_add(&weights[j], &weights[j], &term);
        }
    }

    if (!secp256k1_vpss_weighted_sum_var(ctx, &sum, points, weights, m)) {
        return 0;
    }
    return secp256k1_gej_is_infinity(&sum);
}

static int secp256k1_vpss_eval_at_var(const secp256k1_context *ctx, secp256k1_gej *r, const unsigned char *idx, const secp256k1_ge *points, size_t m, unsigned int at) {
    secp256k1_scalar weights[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_scalar denominators[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    size_t j;

    VERIFY_CHECK(m >= 1 && m <= SECP256K1_ICEBERG_MAX_PARTICIPANTS);

    /* Fill the tail as well: only the first m entries are read, but GCC cannot
     * see that and warns on the partially filled array. */
    for (j = 0; j < SECP256K1_ICEBERG_MAX_PARTICIPANTS; j++) {
        secp256k1_scalar_set_int(&denominators[j], 1);
    }

    /* One inversion for the whole set instead of one per weight, as in
     * secp256k1_rss_lagrange_weights_var. Both partial_sign and
     * partial_sig_verify come through here once per nonce sharing, so twice
     * apiece. */
    for (j = 0; j < m; j++) {
        secp256k1_scalarpoly_lagrange_parts_var(&weights[j], &denominators[j],
                                                idx, m, idx[j], at);
    }
    secp256k1_scalarpoly_inverse_batch_var(denominators, denominators, m);
    for (j = 0; j < m; j++) {
        secp256k1_scalar_mul(&weights[j], &weights[j], &denominators[j]);
    }
    return secp256k1_vpss_weighted_sum_var(ctx, r, points, weights, m);
}

static int secp256k1_vpss_combine_var(const secp256k1_context *ctx, secp256k1_gej *r, const unsigned char *idx, const secp256k1_ge *points, size_t m) {
    return secp256k1_vpss_eval_at_var(ctx, r, idx, points, m, 0);
}

#endif /* SECP256K1_MODULE_ICEBERG_VPSS_IMPL_H */
