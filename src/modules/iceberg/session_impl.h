/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ICEBERG_SESSION_IMPL_H
#define SECP256K1_MODULE_ICEBERG_SESSION_IMPL_H

#include <string.h>

#include "../../../include/secp256k1_iceberg.h"

#include "keygen_impl.h"
#include "rss_impl.h"
#include "scalar_poly_impl.h"
#include "vpss_impl.h"

#include "../musig/keyagg.h"
#include "../musig/session.h"

#include "../../group.h"
#include "../../hash.h"
#include "../../scalar.h"
#include "../../util.h"

static const unsigned char secp256k1_iceberg_pubnonce_magic[4] = { 0x1c, 0xeb, 0x60, 0x2e };
static const unsigned char secp256k1_iceberg_aggnonce_magic[4] = { 0x1c, 0xeb, 0xa9, 0x77 };
static const unsigned char secp256k1_iceberg_psig_magic[4] = { 0x1c, 0xeb, 0x51, 0x8b };
/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("Iceberg/noncecoef")||SHA256("Iceberg/noncecoef"). */
static void secp256k1_iceberg_noncecoef_sha256_tagged(secp256k1_sha256 *sha) {
    static const uint32_t midstate[8] = {
        0x8848611aul, 0x6abc622ful, 0x7d0bbf3cul, 0x9d9c84faul,
        0x0188712dul, 0x04573e61ul, 0x23eb12e6ul, 0x88a27ee0ul
    };
    secp256k1_sha256_initialize_midstate(sha, 64, midstate);
}

/* The two VPSS labels a session uses, big-endian 1 and 2 followed by the
 * session label. Sixty-four bytes each, matching the reference exactly. */
static void secp256k1_iceberg_nonce_label(unsigned char *out64, unsigned int which, const unsigned char *sid32) {
    memset(out64, 0, 32);
    out64[31] = (unsigned char)which;
    memcpy(&out64[32], sid32, 32);
}

/* This participant's own two nonce points for a session: its share of each of
 * the two nonce sharings, in the group.
 *
 * Round one publishes these; round two derives them again to check the set it
 * was handed at its own index. That check means anything at all only if the two
 * rounds agree on the derivation, so they use this rather than a copy each. The
 * caller must have checked that the context carries an ecmult_gen table.
 *
 * k_out, if not NULL, receives the two scalars the points commit to. They are
 * secret, and a caller that asks for them owns them and must clear them. Pass
 * NULL to have them cleared here.
 *
 * The points are about to be published either way, so they are declassified. */
static void secp256k1_iceberg_own_nonce_points(const secp256k1_context *ctx, secp256k1_ge *pts, secp256k1_scalar *k_out, const unsigned char *seeds, const secp256k1_scalar *weights, size_t count, const unsigned char *sid32) {
    unsigned char label[64];
    int i;

    for (i = 0; i < 2; i++) {
        secp256k1_scalar k_i;
        secp256k1_gej pj;
        secp256k1_iceberg_nonce_label(label, (unsigned int)(i + 1), sid32);
        secp256k1_rss_eval(secp256k1_get_hash_context(ctx), &k_i, seeds, weights, count, label, sizeof(label));
        secp256k1_ecmult_gen_gej(&ctx->ecmult_gen_ctx, &pj, &k_i);
        secp256k1_ge_set_gej(&pts[i], &pj);
        secp256k1_declassify(ctx, &pts[i], sizeof(pts[i]));
        if (k_out != NULL) {
            k_out[i] = k_i;
        }
        secp256k1_scalar_clear(&k_i);
    }
}

/* b1 = H_Iceberg/noncecoef(R1 || R2' || P): the unscaled pre-nonces, then the
 * group's key, each in musig's 33-byte extended encoding. The paper writes the
 * arguments key first; the reference serializes them in this order and so do
 * we, which the cross-implementation vectors pin.
 *
 * An inner aggregate has no binding of its own and the outer coefficient is
 * computed too late to supply one, so every nesting level contributes a factor.
 * Computed here and nowhere else, so the preimage moves in one place. */
static void secp256k1_iceberg_noncecoef(const secp256k1_context *ctx, secp256k1_scalar *b1, secp256k1_ge *nonce_pts, const secp256k1_ge *group_pk) {
    secp256k1_sha256 sha;
    secp256k1_ge pk = *group_pk;
    unsigned char buf[33];
    unsigned char out[32];

    secp256k1_iceberg_noncecoef_sha256_tagged(&sha);
    secp256k1_musig_ge_serialize_ext(buf, &nonce_pts[0]);
    secp256k1_sha256_write(secp256k1_get_hash_context(ctx), &sha, buf, sizeof(buf));
    secp256k1_musig_ge_serialize_ext(buf, &nonce_pts[1]);
    secp256k1_sha256_write(secp256k1_get_hash_context(ctx), &sha, buf, sizeof(buf));
    secp256k1_musig_ge_serialize_ext(buf, &pk);
    secp256k1_sha256_write(secp256k1_get_hash_context(ctx), &sha, buf, sizeof(buf));
    secp256k1_sha256_finalize(secp256k1_get_hash_context(ctx), &sha, out);
    secp256k1_scalar_set_b32(b1, out, NULL);
}

/* The pair the group publishes, (R1, b1*R2'), from the internal one. Only the
 * second point is scaled: at nesting depth one the coefficient enters as
 * b1^(i-1), so the first is carried through untouched.
 *
 * Round one publishes this and round two rebuilds it from the aggregate it
 * derives from the contributions. The two have to agree exactly or every
 * signature the group produces is invalid, so it is written once rather than
 * twice.
 *
 * 0 if either point comes out at infinity, which a MuSig2 public nonce has no
 * encoding for. Both rounds refuse such a set because both reach it here: a
 * contribution set can be consistent, agree with a signer's own contribution,
 * and still interpolate to infinity at zero. */
static int secp256k1_iceberg_publish_nonce(secp256k1_ge *out, const secp256k1_ge *pre, const secp256k1_scalar *b1) {
    secp256k1_gej r2j, scaled;

    out[0] = pre[0];
    secp256k1_gej_set_ge(&r2j, &pre[1]);
    secp256k1_ecmult(&scaled, &r2j, b1, NULL);
    secp256k1_ge_set_gej(&out[1], &scaled);
    return !secp256k1_ge_is_infinity(&out[0]) && !secp256k1_ge_is_infinity(&out[1]);
}

static void secp256k1_iceberg_pubnonce_save(secp256k1_iceberg_pubnonce *nonce, unsigned int k, const secp256k1_ge *pts) {
    memset(nonce->data, 0, sizeof(nonce->data));
    memcpy(nonce->data, secp256k1_iceberg_pubnonce_magic, 4);
    nonce->data[4] = (unsigned char)k;
    secp256k1_ge_to_bytes_ext(&nonce->data[5], &pts[0]);
    secp256k1_ge_to_bytes_ext(&nonce->data[69], &pts[1]);
}

static int secp256k1_iceberg_pubnonce_load(const secp256k1_context *ctx, unsigned int *k, secp256k1_ge *pts, const secp256k1_iceberg_pubnonce *nonce) {
    ARG_CHECK(secp256k1_memcmp_var(nonce->data, secp256k1_iceberg_pubnonce_magic, 4) == 0);
    *k = nonce->data[4];
    ARG_CHECK(*k >= 1 && *k <= SECP256K1_ICEBERG_MAX_PARTICIPANTS);
    secp256k1_ge_from_bytes_ext(&pts[0], &nonce->data[5]);
    secp256k1_ge_from_bytes_ext(&pts[1], &nonce->data[69]);
    return 1;
}

static void secp256k1_iceberg_aggnonce_save(secp256k1_iceberg_aggnonce *nonce, const secp256k1_ge *pts) {
    memset(nonce->data, 0, sizeof(nonce->data));
    memcpy(nonce->data, secp256k1_iceberg_aggnonce_magic, 4);
    secp256k1_ge_to_bytes_ext(&nonce->data[4], &pts[0]);
    secp256k1_ge_to_bytes_ext(&nonce->data[68], &pts[1]);
}

static int secp256k1_iceberg_aggnonce_load(const secp256k1_context *ctx, secp256k1_ge *pts, const secp256k1_iceberg_aggnonce *nonce) {
    ARG_CHECK(secp256k1_memcmp_var(nonce->data, secp256k1_iceberg_aggnonce_magic, 4) == 0);
    secp256k1_ge_from_bytes_ext(&pts[0], &nonce->data[4]);
    secp256k1_ge_from_bytes_ext(&pts[1], &nonce->data[68]);
    return 1;
}

/* Read a set of nonce contributions: the index and both nonce points of each,
 * refusing an index outside the group, a repeated index, or points that do not
 * lie on a single sharing of degree t-1. */
static int secp256k1_iceberg_contributions_load(const secp256k1_context *ctx, unsigned char *idx, secp256k1_ge points[2][SECP256K1_ICEBERG_MAX_PARTICIPANTS], const secp256k1_iceberg_pubnonce * const *pubnonces, size_t m, unsigned int n, unsigned int t) {
    size_t i, j;

    if (n < 1 || n > SECP256K1_ICEBERG_MAX_PARTICIPANTS || t < 1 || t > (n + 1) / 2) {
        return 0;
    }
    if (m < 2 * (size_t)t - 1 || m > n) {
        return 0;
    }
    for (i = 0; i < m; i++) {
        secp256k1_ge pts[2];
        unsigned int who;

        if (!secp256k1_iceberg_pubnonce_load(ctx, &who, pts, pubnonces[i])) {
            return 0;
        }
        /* An index above n names no member of this group, so nothing could have
         * authenticated what it carries. */
        if (who > n) {
            return 0;
        }
        idx[i] = (unsigned char)who;
        for (j = 0; j < i; j++) {
            if (idx[j] == idx[i]) {
                return 0;
            }
        }
        points[0][i] = pts[0];
        points[1][i] = pts[1];
    }
    for (i = 0; i < 2; i++) {
        if (!secp256k1_vpss_verify_var(ctx, idx, points[i], m, t)) {
            return 0;
        }
    }
    return 1;
}

/* Both sharings interpolated back to their constant term: the group's internal
 * (R1, R2'). Only meaningful on a set contributions_load has accepted. */
static int secp256k1_iceberg_contributions_combine(const secp256k1_context *ctx, secp256k1_ge *combined, const unsigned char *idx, secp256k1_ge points[2][SECP256K1_ICEBERG_MAX_PARTICIPANTS], size_t m) {
    secp256k1_gej sum;
    int i;

    for (i = 0; i < 2; i++) {
        if (!secp256k1_vpss_combine_var(ctx, &sum, idx, points[i], m)) {
            return 0;
        }
        secp256k1_ge_set_gej(&combined[i], &sum);
    }
    return 1;
}

/* Wire formats.
 *
 *   pubnonce     67 = index(1) | point(33) | point(33)
 *   aggnonce     66 =            point(33) | point(33)
 *   partial_sig  33 = index(1) | scalar(32)
 *
 * Points use musig's extended serializer, which encodes infinity as 33 zero
 * bytes. The aggregate can reach infinity, so the format has to express it, and
 * a member's contribution uses the same encoding so the two do not differ
 * without a reason.
 *
 * A member's objects carry its index inside the encoding, because everything
 * downstream is indexed and pairing the two is then not something a caller can
 * get wrong on the wire. The group's aggregate belongs to no member and carries
 * none, which is the whole of the 67-versus-66 difference. */
int secp256k1_iceberg_pubnonce_serialize(const secp256k1_context *ctx, unsigned char *out67, const secp256k1_iceberg_pubnonce *pubnonce) {
    secp256k1_ge pts[2];
    unsigned int k;
    int i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out67 != NULL);
    memset(out67, 0, 67);
    ARG_CHECK(pubnonce != NULL);

    if (!secp256k1_iceberg_pubnonce_load(ctx, &k, pts, pubnonce)) {
        return 0;
    }
    out67[0] = (unsigned char)k;
    for (i = 0; i < 2; i++) {
        secp256k1_musig_ge_serialize_ext(&out67[1 + 33 * i], &pts[i]);
    }
    return 1;
}

int secp256k1_iceberg_pubnonce_parse(const secp256k1_context *ctx, secp256k1_iceberg_pubnonce *pubnonce, const unsigned char *in67) {
    secp256k1_ge pts[2];
    int i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubnonce != NULL);
    memset(pubnonce, 0, sizeof(*pubnonce));
    ARG_CHECK(in67 != NULL);

    if (in67[0] < 1 || in67[0] > SECP256K1_ICEBERG_MAX_PARTICIPANTS) {
        return 0;
    }
    for (i = 0; i < 2; i++) {
        if (!secp256k1_musig_ge_parse_ext(&pts[i], &in67[1 + 33 * i])) {
            return 0;
        }
    }
    secp256k1_iceberg_pubnonce_save(pubnonce, in67[0], pts);
    return 1;
}

int secp256k1_iceberg_aggnonce_serialize(const secp256k1_context *ctx, unsigned char *out66, const secp256k1_iceberg_aggnonce *aggnonce) {
    secp256k1_ge pts[2];
    int i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out66 != NULL);
    memset(out66, 0, 66);
    ARG_CHECK(aggnonce != NULL);

    if (!secp256k1_iceberg_aggnonce_load(ctx, pts, aggnonce)) {
        return 0;
    }
    for (i = 0; i < 2; i++) {
        secp256k1_musig_ge_serialize_ext(&out66[33 * i], &pts[i]);
    }
    return 1;
}

int secp256k1_iceberg_aggnonce_parse(const secp256k1_context *ctx, secp256k1_iceberg_aggnonce *aggnonce, const unsigned char *in66) {
    secp256k1_ge pts[2];
    int i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(aggnonce != NULL);
    memset(aggnonce, 0, sizeof(*aggnonce));
    ARG_CHECK(in66 != NULL);

    for (i = 0; i < 2; i++) {
        if (!secp256k1_musig_ge_parse_ext(&pts[i], &in66[33 * i])) {
            return 0;
        }
    }
    secp256k1_iceberg_aggnonce_save(aggnonce, pts);
    return 1;
}

int secp256k1_iceberg_partial_sig_serialize(const secp256k1_context *ctx, unsigned char *out33, const secp256k1_iceberg_partial_sig *partial_sig) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out33 != NULL);
    memset(out33, 0, 33);
    ARG_CHECK(partial_sig != NULL);
    /* ARG_CHECK rather than a plain return, so that a malformed object reaches
     * the caller the same way here as it does through the load helpers the four
     * sibling serializers use. */
    ARG_CHECK(secp256k1_memcmp_var(partial_sig->data, secp256k1_iceberg_psig_magic, 4) == 0);

    out33[0] = partial_sig->data[4];
    memcpy(&out33[1], &partial_sig->data[5], 32);
    return 1;
}

int secp256k1_iceberg_partial_sig_parse(const secp256k1_context *ctx, secp256k1_iceberg_partial_sig *partial_sig, const unsigned char *in33) {
    secp256k1_scalar s;
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(partial_sig != NULL);
    memset(partial_sig, 0, sizeof(*partial_sig));
    ARG_CHECK(in33 != NULL);

    if (in33[0] < 1 || in33[0] > SECP256K1_ICEBERG_MAX_PARTICIPANTS) {
        return 0;
    }
    /* Reject an out-of-range scalar here instead of reducing it. Aggregation
     * is linear, so a share that wrapped would combine into a signature that
     * simply fails to verify. */
    secp256k1_scalar_set_b32(&s, &in33[1], &overflow);
    if (overflow) {
        return 0;
    }
    memcpy(partial_sig->data, secp256k1_iceberg_psig_magic, 4);
    partial_sig->data[4] = in33[0];
    memcpy(&partial_sig->data[5], &in33[1], 32);
    secp256k1_scalar_clear(&s);
    return 1;
}

int secp256k1_iceberg_nonce_gen(const secp256k1_context *ctx, secp256k1_iceberg_pubnonce *pubnonce, const secp256k1_iceberg_share *share, const secp256k1_iceberg_share_cache *cache, const unsigned char *sid32) {
    secp256k1_scalar weights[SECP256K1_ICEBERG_MAX_SEEDS];
    secp256k1_ge pts[2];
    const unsigned char *seeds;
    unsigned int n, t, k;
    size_t count;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubnonce != NULL);
    memset(pubnonce, 0, sizeof(*pubnonce));
    ARG_CHECK(share != NULL);
    ARG_CHECK(sid32 != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));

    count = secp256k1_iceberg_share_load(ctx, &n, &t, &k, &seeds, share);
    if (count == 0 || !secp256k1_iceberg_weights_for(ctx, weights, count, n, t, k, cache)) {
        return 0;
    }

    secp256k1_iceberg_own_nonce_points(ctx, pts, NULL, seeds, weights, count, sid32);
    secp256k1_iceberg_pubnonce_save(pubnonce, k, pts);
    return 1;
}

int secp256k1_iceberg_nonce_agg(const secp256k1_context *ctx, secp256k1_musig_pubnonce *musig_pubnonce, secp256k1_iceberg_aggnonce *aggnonce, const secp256k1_iceberg_pubnonce * const *pubnonces, size_t n_pubnonces, unsigned int n, unsigned int t, const secp256k1_pubkey *group_pk) {
    unsigned char idx[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_ge points[2][SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_ge combined[2], published[2], pk;
    secp256k1_scalar b1;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(musig_pubnonce != NULL);
    memset(musig_pubnonce, 0, sizeof(*musig_pubnonce));
    /* Optional. Only the serializer reads an iceberg_aggnonce, so a caller with
     * no use for one passes NULL instead of allocating 132 bytes to ignore. */
    if (aggnonce != NULL) {
        memset(aggnonce, 0, sizeof(*aggnonce));
    }
    ARG_CHECK(pubnonces != NULL);
    ARG_CHECK(group_pk != NULL);
    ARG_CHECK(n >= 1 && n <= SECP256K1_ICEBERG_MAX_PARTICIPANTS);
    ARG_CHECK(t >= 1 && t <= (n + 1) / 2);
    /* Bounded here for the same reason as in partial_sign: the sweep has to stay
     * inside the array, and contributions_load checks the quorum itself. */
    if (n_pubnonces > n) {
        return 0;
    }
    for (i = 0; i < n_pubnonces; i++) {
        ARG_CHECK(pubnonces[i] != NULL);
    }

    if (!secp256k1_pubkey_load(ctx, &pk, group_pk)) {
        return 0;
    }
    if (!secp256k1_iceberg_contributions_load(ctx, idx, points, pubnonces, n_pubnonces, n, t)) {
        return 0;
    }
    if (!secp256k1_iceberg_contributions_combine(ctx, combined, idx, points, n_pubnonces)) {
        return 0;
    }
    secp256k1_iceberg_noncecoef(ctx, &b1, combined, &pk);
    if (!secp256k1_iceberg_publish_nonce(published, combined, &b1)) {
        return 0;
    }
    /* Both out-parameters are written here rather than as each is ready, so that
     * every path that returns 0 leaves them as the memset at the top left them. */
    if (aggnonce != NULL) {
        secp256k1_iceberg_aggnonce_save(aggnonce, combined);
    }
    secp256k1_musig_pubnonce_save(musig_pubnonce, published);
    return 1;
}

/* Everything round two needs from the upper session, recomputed here rather
 * than accepted from the caller.
 *
 * The aggregate nonce is assembled from the group's own exported contribution
 * plus the cosigners', so "my nonce is in there" is true by construction. A
 * signer that took a prepared session object instead would be trusting values
 * an adversary can choose.
 */
static int secp256k1_iceberg_session_values(const secp256k1_context *ctx, secp256k1_scalar *b0b1, secp256k1_scalar *key_coef, int *fin_parity, const secp256k1_iceberg_aggnonce *aggnonce, const secp256k1_pubkey *group_pk, const secp256k1_musig_keyagg_cache *keyagg_cache, const unsigned char *msg32, const secp256k1_musig_aggnonce *cosigner_aggnonce) {
    secp256k1_keyagg_cache_internal cache_i;
    secp256k1_ge group_pts[2], cosigner_pts[2], total[2], pk;
    secp256k1_scalar b1, b0, a, e;
    secp256k1_gej acc;
    unsigned char agg_pk32[32], fin_nonce[32];
    int i;

    if (!secp256k1_keyagg_cache_load(ctx, &cache_i, keyagg_cache)) {
        return 0;
    }
    if (!secp256k1_pubkey_load(ctx, &pk, group_pk)) {
        return 0;
    }
    if (!secp256k1_iceberg_aggnonce_load(ctx, group_pts, aggnonce)) {
        return 0;
    }
    if (!secp256k1_musig_aggnonce_load(ctx, cosigner_pts, cosigner_aggnonce)) {
        return 0;
    }

    /* Re-derive the group's published nonce with the same function round one
     * published it with, then add the cosigners' to it. */
    secp256k1_iceberg_noncecoef(ctx, &b1, group_pts, &pk);
    if (!secp256k1_iceberg_publish_nonce(total, group_pts, &b1)) {
        return 0;
    }
    for (i = 0; i < 2; i++) {
        secp256k1_gej_set_ge(&acc, &total[i]);
        secp256k1_gej_add_ge_var(&acc, &acc, &cosigner_pts[i], NULL);
        secp256k1_ge_set_gej(&total[i], &acc);
    }

    secp256k1_fe_get_b32(agg_pk32, &cache_i.pk.x);
    secp256k1_musig_nonce_process_internal(ctx, fin_parity, fin_nonce, &b0, total, agg_pk32, msg32);
    secp256k1_schnorrsig_challenge(secp256k1_get_hash_context(ctx), &e, fin_nonce, msg32, 32, agg_pk32);

    secp256k1_scalar_mul(b0b1, &b0, &b1);

    /* The key coefficient carries the aggregation weight and the parity
     * bookkeeping from BIP-340: e * a * g * gacc, where the sign flips if the
     * aggregate key is odd exactly once against the accumulated parity. */
    secp256k1_musig_keyaggcoef(secp256k1_get_hash_context(ctx), &a, &cache_i, &pk);
    secp256k1_scalar_mul(key_coef, &e, &a);
    if (secp256k1_fe_is_odd(&cache_i.pk.y) != cache_i.parity_acc) {
        secp256k1_scalar_negate(key_coef, key_coef);
    }
    return 1;
}

int secp256k1_iceberg_keyagg_check(const secp256k1_context *ctx, const secp256k1_musig_keyagg_cache *keyagg_cache, const secp256k1_pubkey * const *pubkeys, size_t n_pubkeys, const secp256k1_pubkey *group_pk) {
    secp256k1_keyagg_cache_internal given, rebuilt;
    secp256k1_musig_keyagg_cache scratch;
    secp256k1_ge target;
    int found = 0;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(keyagg_cache != NULL);
    ARG_CHECK(pubkeys != NULL);
    ARG_CHECK(group_pk != NULL);
    ARG_CHECK(n_pubkeys >= 1);
    for (i = 0; i < n_pubkeys; i++) {
        ARG_CHECK(pubkeys[i] != NULL);
    }

    if (!secp256k1_keyagg_cache_load(ctx, &given, keyagg_cache)) {
        return 0;
    }
    if (!secp256k1_musig_pubkey_agg(ctx, NULL, &scratch, pubkeys, n_pubkeys)) {
        return 0;
    }
    if (!secp256k1_keyagg_cache_load(ctx, &rebuilt, &scratch)) {
        return 0;
    }
    /* pks_hash is the hash of the key list, fixed when the list is aggregated
     * and untouched by any tweak applied afterwards, so this says the cache
     * aggregates this list whatever has since been tweaked onto it. Rebuilding
     * the cache from the list and using that instead would not do: the tweaks
     * are not recoverable from the list, and it is the caller's cache that
     * partial_sign will be working against.
     *
     * second_pk is also in the cache and is also fixed at aggregation, but it is
     * derived from the same list, so comparing it as well could only fail on a
     * hash collision. */
    if (secp256k1_memcmp_var(given.pks_hash, rebuilt.pks_hash, 32) != 0) {
        return 0;
    }
    if (!secp256k1_pubkey_load(ctx, &target, group_pk)) {
        return 0;
    }
    for (i = 0; i < n_pubkeys; i++) {
        secp256k1_ge candidate;
        if (!secp256k1_pubkey_load(ctx, &candidate, pubkeys[i])) {
            return 0;
        }
        if (secp256k1_ge_eq_var(&candidate, &target)) {
            found = 1;
        }
    }
    return found;
}

/* Rebuild the group's aggregate nonce from the contributions, and hand back the
 * polynomial's value at `index`. Nothing is refused on that value here, and the
 * two callers put it to opposite uses. Signing compares it against the
 * contribution the signer derives for itself, in
 * secp256k1_iceberg_verified_aggnonce below. Verification holds no share to
 * derive one from and takes the value as the member's own nonce, which is what
 * lets it check a member that published nothing in round one.
 *
 * A signer that accepts an aggregate from its coordinator is trusting a value it
 * cannot check, and the nesting coefficient is a hash of exactly that value.
 * Three fabricated aggregates under one label yield three equations in the same
 * three unknowns; the third is the key. Deriving it here instead is what Arctic
 * does, and the reason it does it. */
static int secp256k1_iceberg_aggnonce_from(const secp256k1_context *ctx, secp256k1_iceberg_aggnonce *aggnonce, secp256k1_ge *at_index, const secp256k1_iceberg_pubnonce * const *pubnonces, size_t n_pubnonces, unsigned int n, unsigned int t, unsigned int index) {
    unsigned char idx[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_ge points[2][SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_ge combined[2];
    secp256k1_gej sum;
    int i;

    if (!secp256k1_iceberg_contributions_load(ctx, idx, points, pubnonces, n_pubnonces, n, t)) {
        return 0;
    }
    /* The degree check proves the set lies on one polynomial of the right
     * degree, not which polynomial: a consistent set may be some other session's
     * sharing. Evaluating at `index` gives the caller the one value that ties the
     * set to a particular label.
     *
     * A caller that compares it deliberately does not have to have contributed.
     * A member who was offline still holds the shares that fix what its
     * contribution would have been. Requiring its presence would be stronger
     * against an unauthenticated transport and would lock the offline member out;
     * under the authenticated transport the scheme assumes it buys nothing,
     * because among 2t-1 contributions that all name members, with at most t-1
     * corrupt, t are honest and t points already pin the polynomial. */
    for (i = 0; i < 2; i++) {
        if (!secp256k1_vpss_eval_at_var(ctx, &sum, idx, points[i], n_pubnonces, index)) {
            return 0;
        }
        secp256k1_ge_set_gej(&at_index[i], &sum);
    }
    if (!secp256k1_iceberg_contributions_combine(ctx, combined, idx, points, n_pubnonces)) {
        return 0;
    }
    secp256k1_iceberg_aggnonce_save(aggnonce, combined);
    return 1;
}

/* The signer's use of the above, and the only place that value is compared: the
 * set must agree, at this participant's index, with the contribution the
 * participant derives for itself. */
static int secp256k1_iceberg_verified_aggnonce(const secp256k1_context *ctx, secp256k1_iceberg_aggnonce *aggnonce, const secp256k1_iceberg_pubnonce * const *pubnonces, size_t n_pubnonces, unsigned int n, unsigned int t, unsigned int own_index, const secp256k1_ge *own_pts) {
    secp256k1_ge mine[2];
    int i;

    if (!secp256k1_iceberg_aggnonce_from(ctx, aggnonce, mine, pubnonces, n_pubnonces, n, t, own_index)) {
        return 0;
    }
    for (i = 0; i < 2; i++) {
        if (!secp256k1_ge_eq_var(&mine[i], &own_pts[i])) {
            return 0;
        }
    }
    return 1;
}

/* The secrets secp256k1_iceberg_partial_sign holds. d and s are not yet
 * meaningful on its early error paths; clearing them there writes zeros over
 * whatever the stack held, which is what those paths want anyway. */
static void secp256k1_iceberg_partial_sign_clear(secp256k1_scalar *nonce_k, secp256k1_scalar *d, secp256k1_scalar *s) {
    secp256k1_scalar_clear(&nonce_k[0]);
    secp256k1_scalar_clear(&nonce_k[1]);
    secp256k1_scalar_clear(d);
    secp256k1_scalar_clear(s);
}

int secp256k1_iceberg_partial_sign(const secp256k1_context *ctx, secp256k1_iceberg_partial_sig *partial_sig, const secp256k1_iceberg_share *share, const secp256k1_iceberg_share_cache *cache, const unsigned char *sid32, const secp256k1_iceberg_pubnonce * const *pubnonces, size_t n_pubnonces, const secp256k1_pubkey *group_pk, const secp256k1_musig_keyagg_cache *keyagg_cache, const unsigned char *msg32, const secp256k1_musig_aggnonce *cosigner_aggnonce) {
    secp256k1_scalar weights[SECP256K1_ICEBERG_MAX_SEEDS];
    secp256k1_scalar nonce_k[2], d, s, b0b1, key_coef;
    secp256k1_iceberg_aggnonce aggnonce;
    secp256k1_ge own_pts[2];
    const unsigned char *seeds;
    unsigned int n, t, k;
    size_t count, j;
    int fin_parity;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(partial_sig != NULL);
    memset(partial_sig, 0, sizeof(*partial_sig));
    ARG_CHECK(share != NULL);
    ARG_CHECK(sid32 != NULL);
    ARG_CHECK(pubnonces != NULL);
    ARG_CHECK(group_pk != NULL);
    ARG_CHECK(keyagg_cache != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(cosigner_aggnonce != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    /* The group size is read before the count is checked, because it is what the
     * count has to be checked against. It comes off this participant's own
     * share, so no caller and no peer gets to choose it. */
    count = secp256k1_iceberg_share_load(ctx, &n, &t, &k, &seeds, share);
    if (count == 0) {
        return 0;
    }
    /* The count is peer-influenced, so an impossible one returns 0 the way the
     * rest of this call does, and the way the header says it will. It is bounded
     * here, ahead of the quorum check in contributions_load, so that the sweep
     * below stays inside an array a caller sized from n; a null entry is a caller
     * bug and gets the illegal callback instead. partial_sig_verify orders these
     * two the same way. */
    if (n_pubnonces > n) {
        return 0;
    }
    for (j = 0; j < n_pubnonces; j++) {
        ARG_CHECK(pubnonces[j] != NULL);
    }

    /* sid32 is the caller's to choose and the caller's to keep unique. Three
     * responses under one label are three equations in this participant's three
     * secrets, and the third of them is its key share. Nothing here can detect
     * that. doc/iceberg.md gives the rule in full. */

    if (!secp256k1_iceberg_weights_for(ctx, weights, count, n, t, k, cache)) {
        return 0;
    }

    /* Recompute our own contribution so the set can be matched against it, and
     * keep the scalars it commits to: they are what this participant signs
     * with. */
    secp256k1_iceberg_own_nonce_points(ctx, own_pts, nonce_k, seeds, weights, count, sid32);
    /* n comes off this participant's own share, so the signer bounds the
     * contribution indices against the group it was actually dealt into rather
     * than against whatever the coordinator would like the group to be. The
     * nonce scalars are live from here on, so every return below clears them. */
    if (!secp256k1_iceberg_verified_aggnonce(ctx, &aggnonce, pubnonces, n_pubnonces, n, t, k, own_pts)) {
        secp256k1_iceberg_partial_sign_clear(nonce_k, &d, &s);
        return 0;
    }
    if (!secp256k1_iceberg_session_values(ctx, &b0b1, &key_coef, &fin_parity,
                                          &aggnonce, group_pk, keyagg_cache, msg32,
                                          cosigner_aggnonce)) {
        secp256k1_iceberg_partial_sign_clear(nonce_k, &d, &s);
        return 0;
    }

    /* The third sharing this participant contributes to, keyed on the fixed
     * label rather than the session's. Like the two nonce sharings above it, it
     * is recomputed from the seeds rather than carried across from round one, so
     * nothing secret had to survive the gap. */
    secp256k1_rss_eval(secp256k1_get_hash_context(ctx), &d, seeds, weights, count,
                       secp256k1_iceberg_keygen_label, sizeof(secp256k1_iceberg_keygen_label));

    /* BIP-340 again: if the final nonce came out odd, both nonce terms flip. */
    if (fin_parity) {
        secp256k1_scalar_negate(&nonce_k[0], &nonce_k[0]);
        secp256k1_scalar_negate(&nonce_k[1], &nonce_k[1]);
    }

    /* s_k = k1 + b0*b1*k2 + e*a*g*gacc*d_k */
    secp256k1_scalar_mul(&s, &key_coef, &d);
    secp256k1_scalar_mul(&nonce_k[1], &b0b1, &nonce_k[1]);
    secp256k1_scalar_add(&s, &s, &nonce_k[1]);
    secp256k1_scalar_add(&s, &s, &nonce_k[0]);

    memcpy(partial_sig->data, secp256k1_iceberg_psig_magic, 4);
    partial_sig->data[4] = (unsigned char)k;
    secp256k1_scalar_get_b32(&partial_sig->data[5], &s);

    secp256k1_iceberg_partial_sign_clear(nonce_k, &d, &s);
    return 1;
}

int secp256k1_iceberg_partial_sig_verify(const secp256k1_context *ctx, const secp256k1_iceberg_partial_sig *partial_sig, const secp256k1_iceberg_pubshare *pubshare, const secp256k1_iceberg_pubnonce * const *pubnonces, size_t n_pubnonces, unsigned int n, unsigned int t, const secp256k1_pubkey *group_pk, const secp256k1_musig_keyagg_cache *keyagg_cache, const unsigned char *msg32, const secp256k1_musig_aggnonce *cosigner_aggnonce) {
    secp256k1_iceberg_aggnonce aggnonce;
    secp256k1_scalar b0b1, key_coef, s;
    secp256k1_ge nonce_pts[2], d;
    secp256k1_gej rj, dj, tmp;
    unsigned int k;
    size_t i;
    int fin_parity;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(pubshare != NULL);
    ARG_CHECK(pubnonces != NULL);
    ARG_CHECK(group_pk != NULL);
    ARG_CHECK(keyagg_cache != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(cosigner_aggnonce != NULL);
    ARG_CHECK(n >= 1 && n <= SECP256K1_ICEBERG_MAX_PARTICIPANTS);
    ARG_CHECK(t >= 1 && t <= (n + 1) / 2);
    /* Bounded here for the same reason as in partial_sign: the sweep has to stay
     * inside the array, and contributions_load checks the quorum itself. */
    if (n_pubnonces > n) {
        return 0;
    }
    for (i = 0; i < n_pubnonces; i++) {
        ARG_CHECK(pubnonces[i] != NULL);
    }

    if (secp256k1_memcmp_var(partial_sig->data, secp256k1_iceberg_psig_magic, 4) != 0) {
        return 0;
    }
    if (!secp256k1_iceberg_pubshare_load(ctx, &k, &d, pubshare)) {
        return 0;
    }
    if (k > n) {
        return 0;
    }
    /* The public share says which participant is being asked about. A signature
     * share carrying some other index is refused rather than verified against
     * its own, which catches the two arguments being drawn from different
     * members. Not a privacy measure: parse accepts any index in range, so a
     * share can be relabeled and tried against every public share until one
     * verifies. Authorship was never hidden. */
    if (partial_sig->data[4] != k) {
        return 0;
    }

    /* Same aggregate the signer derived, and the participant's own nonce read
     * off the same polynomial. Taking it from the set rather than as an argument
     * is what lets this check a member who sat out round one: it published no
     * contribution, and the set still fixes what its nonce had to be. */
    if (!secp256k1_iceberg_aggnonce_from(ctx, &aggnonce, nonce_pts, pubnonces, n_pubnonces, n, t, k)) {
        return 0;
    }
    if (!secp256k1_iceberg_session_values(ctx, &b0b1, &key_coef, &fin_parity,
                                          &aggnonce, group_pk, keyagg_cache, msg32,
                                          cosigner_aggnonce)) {
        return 0;
    }

    /* s_k*G == +-(R1,k + b0*b1*R2,k) + e*a*g*gacc*D_k, rearranged so the whole
     * check is one comparison against infinity. */
    secp256k1_gej_set_ge(&rj, &nonce_pts[1]);
    secp256k1_ecmult(&rj, &rj, &b0b1, NULL);
    secp256k1_gej_add_ge_var(&rj, &rj, &nonce_pts[0], NULL);
    if (fin_parity) {
        secp256k1_gej_neg(&rj, &rj);
    }

    secp256k1_scalar_set_b32(&s, &partial_sig->data[5], NULL);
    secp256k1_scalar_negate(&s, &s);
    secp256k1_gej_set_ge(&dj, &d);
    secp256k1_ecmult(&tmp, &dj, &key_coef, &s);
    secp256k1_gej_add_var(&tmp, &tmp, &rj, NULL);

    return secp256k1_gej_is_infinity(&tmp);
}


int secp256k1_iceberg_partial_sig_agg(const secp256k1_context *ctx, secp256k1_musig_partial_sig *musig_partial_sig, const secp256k1_iceberg_partial_sig * const *partial_sigs, size_t n_partial_sigs, unsigned int n, unsigned int t) {
    unsigned char idx[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_scalar vals[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_scalar s;
    size_t i, j;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(musig_partial_sig != NULL);
    memset(musig_partial_sig, 0, sizeof(*musig_partial_sig));
    ARG_CHECK(partial_sigs != NULL);
    ARG_CHECK(n >= 1 && n <= SECP256K1_ICEBERG_MAX_PARTICIPANTS);
    ARG_CHECK(t >= 1 && t <= (n + 1) / 2);
    /* Interpolation needs t points. The larger quorum belongs to the nonce
     * round, where a degree check has to be sound; here it would only cost
     * availability. How many members answered is a fact about the group rather
     * than a caller bug, so it returns. The upper bound duplicates what the
     * repeated-index check below would catch, and is here because idx and vals
     * are sized for the largest group. */
    if (n_partial_sigs < t || n_partial_sigs > n) {
        return 0;
    }
    for (i = 0; i < n_partial_sigs; i++) {
        ARG_CHECK(partial_sigs[i] != NULL);
    }

    for (i = 0; i < n_partial_sigs; i++) {
        ARG_CHECK(secp256k1_memcmp_var(partial_sigs[i]->data, secp256k1_iceberg_psig_magic, 4) == 0);
        idx[i] = partial_sigs[i]->data[4];
        if (idx[i] < 1 || idx[i] > n) {
            return 0;
        }
        for (j = 0; j < i; j++) {
            if (idx[j] == idx[i]) {
                return 0;
            }
        }
        secp256k1_scalar_set_b32(&vals[i], &partial_sigs[i]->data[5], NULL);
    }

    /* The shares of one session lie on a degree t-1 polynomial, as the nonce round's contributions do, though the
     * shares are a linear combination of three degree t-1 sharings with
     * group-level coefficients and so lie on a degree t-1 polynomial too. It
     * only bites above the threshold: at exactly t shares the interpolation is
     * determined and there is nothing to disagree with, which is why passing one
     * more share can turn a success into a refusal. A caller with a spare share
     * learns that the set contradicts itself here,
     * rather than from a signature that fails without naming a share.
     *
     * This says the set is self-consistent, not that the shares are the ones the
     * members would have produced; secp256k1_iceberg_partial_sig_verify answers
     * that, one share at a time, against the public share it names. */
    if (!secp256k1_scalarpoly_on_degree_var(idx, vals, n_partial_sigs, t)) {
        return 0;
    }
    secp256k1_scalarpoly_interpolate_at0(&s, idx, vals, n_partial_sigs);
    secp256k1_musig_partial_sig_save(musig_partial_sig, &s);
    return 1;
}

#endif /* SECP256K1_MODULE_ICEBERG_SESSION_IMPL_H */
