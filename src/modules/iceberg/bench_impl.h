/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ICEBERG_BENCH_H
#define SECP256K1_MODULE_ICEBERG_BENCH_H

#include <string.h>

#include "../../../include/secp256k1_iceberg.h"
#include "../../../include/secp256k1_iceberg_dealer.h"

/* Timings for each step of a signing session.
 *
 * Two growth laws meet here, which is what the configurations are chosen to
 * show rather than any of them being deployable; see doc/iceberg.md. Each
 * participant holds C(n-1, t-1) seeds (2 at 2-of-3, 126 at 5-of-10) and
 * hashes every one on every derivation, while the curve work grows only with the
 * quorum 2t-1, since that is the width of the multiexponentiation in the degree
 * check and everything else on the curve is a fixed number of multiplications.
 * The two grow at different rates. */

typedef struct {
    secp256k1_context *ctx;
    unsigned int n, t, mu;

    secp256k1_iceberg_share shares[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_iceberg_share *share_ptrs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_iceberg_share_cache cache;
    secp256k1_iceberg_pubshare pubshares[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    const secp256k1_iceberg_pubshare *pubshare_ptrs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_iceberg_pubnonce nonces[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    const secp256k1_iceberg_pubnonce *nonce_ptrs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_iceberg_partial_sig psigs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    const secp256k1_iceberg_partial_sig *psig_ptrs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_iceberg_aggnonce aggnonce;

    secp256k1_pubkey group_pk, cosigner_pk;
    secp256k1_keypair cosigner_keypair;
    secp256k1_xonly_pubkey agg_xonly;
    secp256k1_musig_keyagg_cache keyagg_cache;
    secp256k1_musig_secnonce cosigner_secnonce;
    secp256k1_musig_pubnonce cosigner_pubnonce, group_pubnonce;
    secp256k1_musig_aggnonce cosigner_aggnonce;
    secp256k1_musig_partial_sig group_psig;

    unsigned char seed[32], msg[32], sid[32];

    /* One of the two nonce sharings, kept in the form the group layer wants it,
     * so the degree check and the interpolation can be timed on their own. */
    unsigned char idx[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_ge commitments[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
} bench_iceberg_data;

static void bench_iceberg_setup(bench_iceberg_data *d) {
    const secp256k1_pubkey *pubkeys[2];
    const secp256k1_musig_pubnonce *one[1];
    unsigned char seckey[32], secrand[32];
    unsigned int k;

    memset(d->seed, 0x2a, 32);
    memset(d->msg, 0x5c, 32);
    memset(seckey, 0x31, 32);
    memset(secrand, 0x77, 32);

    for (k = 1; k <= d->n; k++) {
        d->share_ptrs[k - 1] = &d->shares[k - 1];
    }
    CHECK(secp256k1_iceberg_shares_gen(d->ctx, d->share_ptrs, d->n, d->t, d->seed));
    CHECK(secp256k1_iceberg_share_cache_create(d->ctx, &d->cache, &d->shares[0]));
    for (k = 1; k <= d->n; k++) {
        CHECK(secp256k1_iceberg_pubshare_gen(d->ctx, &d->pubshares[k - 1], &d->shares[k - 1], NULL));
        d->pubshare_ptrs[k - 1] = &d->pubshares[k - 1];
    }
    CHECK(secp256k1_iceberg_pubkey_agg(d->ctx, &d->group_pk, d->pubshare_ptrs, d->mu, d->n, d->t));

    CHECK(secp256k1_keypair_create(d->ctx, &d->cosigner_keypair, seckey));
    CHECK(secp256k1_keypair_pub(d->ctx, &d->cosigner_pk, &d->cosigner_keypair));
    pubkeys[0] = &d->group_pk;
    pubkeys[1] = &d->cosigner_pk;
    CHECK(secp256k1_musig_pubkey_agg(d->ctx, &d->agg_xonly, &d->keyagg_cache, pubkeys, 2));

    CHECK(secp256k1_musig_nonce_gen(d->ctx, &d->cosigner_secnonce, &d->cosigner_pubnonce,
                                    secrand, seckey, &d->cosigner_pk, d->msg, &d->keyagg_cache, NULL));
    one[0] = &d->cosigner_pubnonce;
    CHECK(secp256k1_musig_nonce_agg(d->ctx, &d->cosigner_aggnonce, one, 1));
    memset(d->sid, 0x2a, sizeof(d->sid));

    for (k = 1; k <= d->n; k++) {
        CHECK(secp256k1_iceberg_nonce_gen(d->ctx, &d->nonces[k - 1], &d->shares[k - 1], NULL, d->sid));
        d->nonce_ptrs[k - 1] = &d->nonces[k - 1];
    }
    CHECK(secp256k1_iceberg_nonce_agg(d->ctx, &d->group_pubnonce, &d->aggnonce,
                                      d->nonce_ptrs, d->mu, d->n, d->t, &d->group_pk));
    for (k = 1; k <= d->mu; k++) {
        secp256k1_ge pts[2];
        unsigned int who;
        CHECK(secp256k1_iceberg_pubnonce_load(d->ctx, &who, pts, &d->nonces[k - 1]));
        d->idx[k - 1] = (unsigned char)who;
        d->commitments[k - 1] = pts[0];
    }
    for (k = 1; k <= d->t; k++) {
        /* A cache is bound to one participant, so pass NULL and let each of
         * these derive its own. */
        CHECK(secp256k1_iceberg_partial_sign(d->ctx, &d->psigs[k - 1], &d->shares[k - 1], NULL, d->sid, d->nonce_ptrs, d->mu, &d->group_pk, &d->keyagg_cache, d->msg, &d->cosigner_aggnonce));
        d->psig_ptrs[k - 1] = &d->psigs[k - 1];
    }
}

static void bench_iceberg_shares_gen(void *arg, int iters) {
    bench_iceberg_data *d = (bench_iceberg_data *)arg;
    int i;
    for (i = 0; i < iters; i++) {
        CHECK(secp256k1_iceberg_shares_gen(d->ctx, d->share_ptrs, d->n, d->t, d->seed));
    }
}

static void bench_iceberg_cache_create(void *arg, int iters) {
    bench_iceberg_data *d = (bench_iceberg_data *)arg;
    int i;
    for (i = 0; i < iters; i++) {
        CHECK(secp256k1_iceberg_share_cache_create(d->ctx, &d->cache, &d->shares[0]));
    }
}

static void bench_iceberg_pubshare_gen(void *arg, int iters) {
    bench_iceberg_data *d = (bench_iceberg_data *)arg;
    int i;
    for (i = 0; i < iters; i++) {
        CHECK(secp256k1_iceberg_pubshare_gen(d->ctx, &d->pubshares[0], &d->shares[0], &d->cache));
    }
}

static void bench_iceberg_pubkey_agg(void *arg, int iters) {
    bench_iceberg_data *d = (bench_iceberg_data *)arg;
    int i;
    for (i = 0; i < iters; i++) {
        CHECK(secp256k1_iceberg_pubkey_agg(d->ctx, &d->group_pk, d->pubshare_ptrs, d->mu, d->n, d->t));
    }
}

static void bench_iceberg_nonce_gen(void *arg, int iters) {
    bench_iceberg_data *d = (bench_iceberg_data *)arg;
    int i;
    for (i = 0; i < iters; i++) {
        CHECK(secp256k1_iceberg_nonce_gen(d->ctx, &d->nonces[0], &d->shares[0], &d->cache, d->sid));
    }
}

static void bench_iceberg_nonce_agg(void *arg, int iters) {
    bench_iceberg_data *d = (bench_iceberg_data *)arg;
    int i;
    for (i = 0; i < iters; i++) {
        CHECK(secp256k1_iceberg_nonce_agg(d->ctx, &d->group_pubnonce, &d->aggnonce,
                                          d->nonce_ptrs, d->mu, d->n, d->t, &d->group_pk));
    }
}

static void bench_iceberg_partial_sign(void *arg, int iters) {
    bench_iceberg_data *d = (bench_iceberg_data *)arg;
    int i;
    for (i = 0; i < iters; i++) {
        CHECK(secp256k1_iceberg_partial_sign(d->ctx, &d->psigs[0], &d->shares[0], &d->cache, d->sid, d->nonce_ptrs, d->mu, &d->group_pk, &d->keyagg_cache, d->msg, &d->cosigner_aggnonce));
    }
}

/* Optional, and priced per share rather than per signature: a caller that wants
 * to know which share is bad runs this t times before aggregating once. */
static void bench_iceberg_partial_sig_verify(void *arg, int iters) {
    bench_iceberg_data *d = (bench_iceberg_data *)arg;
    int i;
    for (i = 0; i < iters; i++) {
        CHECK(secp256k1_iceberg_partial_sig_verify(d->ctx, &d->psigs[0], &d->pubshares[0], d->nonce_ptrs, d->mu, d->n, d->t, &d->group_pk, &d->keyagg_cache, d->msg, &d->cosigner_aggnonce));
    }
}

/* The degree check and the interpolation, timed on their own. Both run once per
 * nonce sharing inside nonce_agg, again inside partial_sign and inside
 * partial_sig_verify, and once more in pubkey_agg at setup.
 * Nothing in the API reaches these directly; they are here to take the rows
 * above apart. */
static void bench_iceberg_degree_check(void *arg, int iters) {
    bench_iceberg_data *d = (bench_iceberg_data *)arg;
    int i;
    for (i = 0; i < iters; i++) {
        CHECK(secp256k1_vpss_verify_var(d->ctx, d->idx, d->commitments, d->mu, d->t));
    }
}

static void bench_iceberg_interpolate(void *arg, int iters) {
    bench_iceberg_data *d = (bench_iceberg_data *)arg;
    secp256k1_gej r;
    int i;
    for (i = 0; i < iters; i++) {
        CHECK(secp256k1_vpss_combine_var(d->ctx, &r, d->idx, d->commitments, d->mu));
    }
}

/* And inside the degree check, the m x m basis, which depends on nothing but
 * the participant indices. All four checks in a signing session build the same
 * one. */
static void bench_iceberg_lagrange_basis(void *arg, int iters) {
    bench_iceberg_data *d = (bench_iceberg_data *)arg;
    secp256k1_scalar basis[SECP256K1_ICEBERG_MAX_PARTICIPANTS * SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    int i;
    for (i = 0; i < iters; i++) {
        secp256k1_scalarpoly_lagrange_basis_var(basis, d->idx, d->mu);
    }
}

static void bench_iceberg_partial_sig_agg(void *arg, int iters) {
    bench_iceberg_data *d = (bench_iceberg_data *)arg;
    int i;
    for (i = 0; i < iters; i++) {
        CHECK(secp256k1_iceberg_partial_sig_agg(d->ctx, &d->group_psig, d->psig_ptrs,
                                                d->t, d->n, d->t));
    }
}

#endif /* SECP256K1_MODULE_ICEBERG_BENCH_H */
