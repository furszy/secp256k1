/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ICEBERG_RSS_IMPL_H
#define SECP256K1_MODULE_ICEBERG_RSS_IMPL_H

#include "rss.h"
#include "scalar_poly_impl.h"

#include "../../hash.h"
#include "../../scalar.h"
#include "../../util.h"

/* C(n, k), zero outside the participant bound and above the diagonal. Computed
 * rather than tabulated so it cannot disagree with MAX_PARTICIPANTS: a table
 * sized for one bound and written out for another overruns below it and
 * zero-fills above it, and a C(n, t-1) of zero makes the dealer write no seeds
 * and report success. Both arguments count participants, never secret. */
static uint32_t secp256k1_rss_binom(unsigned int n, unsigned int size) {
    uint32_t result = 1;
    unsigned int i;

    if (n > SECP256K1_ICEBERG_MAX_PARTICIPANTS || size > n) {
        return 0;
    }
    if (size > n - size) {
        size = n - size;
    }
    for (i = 0; i < size; i++) {
        /* C(n, i+1) = C(n, i) * (n-i) / (i+1). The division is exact at every
         * step because the running product is itself a binomial coefficient, and
         * halving size above caps the intermediate at C(10, 4) * 6 = 1260 at
         * the participant bound. */
        result = result * (n - i) / (i + 1);
    }
    return result;
}

/* Lexicographic rank, walking the participants in order. Every participant we
 * pass over without selecting skips the whole block of subsets that would have
 * chosen it next. */
static uint32_t secp256k1_rss_subset_rank(unsigned int n, unsigned int size, secp256k1_rss_subset subset) {
    uint32_t rank = 0;
    unsigned int remaining = size;
    unsigned int j;

    for (j = 1; j <= n && remaining > 0; j++) {
        if (subset & (secp256k1_rss_subset)(1u << j)) {
            remaining--;
        } else {
            rank += secp256k1_rss_binom(n - j, remaining - 1);
        }
    }
    return rank;
}

static secp256k1_rss_subset secp256k1_rss_subset_unrank(unsigned int n, unsigned int size, uint32_t rank) {
    secp256k1_rss_subset subset = 0;
    unsigned int remaining = size;
    unsigned int j = 1;

    while (remaining > 0) {
        uint32_t block;
        VERIFY_CHECK(j <= n);
        block = secp256k1_rss_binom(n - j, remaining - 1);
        if (rank < block) {
            subset |= (secp256k1_rss_subset)(1u << j);
            remaining--;
        } else {
            rank -= block;
        }
        j++;
    }
    return subset;
}

/* The members of a subset, ascending, as the byte array the polynomial layer
 * expects. Returns how many were written. */
static size_t secp256k1_rss_subset_members(unsigned char *members, secp256k1_rss_subset subset, unsigned int n) {
    size_t count = 0;
    unsigned int j;

    for (j = 1; j <= n; j++) {
        if (subset & (secp256k1_rss_subset)(1u << j)) {
            members[count++] = (unsigned char)j;
        }
    }
    return count;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("VPSS/prf")||SHA256("VPSS/prf"). */
static void secp256k1_rss_prf_sha256_tagged(secp256k1_sha256 *sha) {
    static const uint32_t midstate[8] = {
        0x2c0fc184ul, 0x5cc276f5ul, 0x96930a47ul, 0x1991257eul,
        0x5b0bb737ul, 0x8786890cul, 0x875ba8bbul, 0x6b6162bbul
    };
    secp256k1_sha256_initialize_midstate(sha, 64, midstate);
}

static void secp256k1_rss_prf(const secp256k1_hash_ctx *hash_ctx, secp256k1_scalar *r, const unsigned char *seed32, const unsigned char *w, size_t wlen) {
    secp256k1_sha256 sha;
    unsigned char buf[32];

    secp256k1_rss_prf_sha256_tagged(&sha);
    secp256k1_sha256_write(hash_ctx, &sha, seed32, 32);
    secp256k1_sha256_write(hash_ctx, &sha, w, wlen);
    secp256k1_sha256_finalize(hash_ctx, &sha, buf);

    /* Reduce on overflow instead of rejecting. The bias is negligible and the
     * reference implementation does the same, which matters because the test
     * vectors have to agree byte for byte. */
    secp256k1_scalar_set_b32(r, buf, NULL);

    secp256k1_memclear_explicit(buf, sizeof(buf));
    secp256k1_sha256_clear(&sha);
}

static size_t secp256k1_rss_lagrange_weights_var(secp256k1_scalar *weights, unsigned int n, unsigned int t, unsigned int k) {
    secp256k1_scalar denominators[SECP256K1_ICEBERG_MAX_SUMMANDS];
    unsigned char members[SECP256K1_ICEBERG_MAX_T];
    uint32_t total = secp256k1_rss_binom(n, t - 1);
    uint32_t rank;
    size_t i, count = 0;

    VERIFY_CHECK(t >= 1 && k >= 1 && k <= n);
    VERIFY_CHECK(n <= SECP256K1_ICEBERG_MAX_PARTICIPANTS);
    /* The scheme's own bound, and what keeps a subset inside members[]: a
     * quorum of 2t-1 has to fit in the group, so t-1 < MAX_T. */
    VERIFY_CHECK(2 * t - 1 <= n);

    /* Walk every subset in rank order and keep the ones this participant holds
     * a seed for, which is exactly those it does not belong to. Iterating the
     * global order, instead of enumerating the complement directly, is what
     * guarantees seeds and weights stay in step with the serialized share.
     *
     * The weights come out as fractions and are divided through at the end, one
     * batch inversion for the whole share rather than one per weight. */
    for (rank = 0; rank < total; rank++) {
        secp256k1_rss_subset subset = secp256k1_rss_subset_unrank(n, t - 1, rank);
        size_t size;
        if (subset & (secp256k1_rss_subset)(1u << k)) {
            continue;
        }
        size = secp256k1_rss_subset_members(members, subset, n);
        /* L_a(k): exclude nothing, evaluate at k. */
        secp256k1_scalarpoly_lagrange_parts_var(&weights[count], &denominators[count], members, size, 0, k);
        count++;
    }

    VERIFY_CHECK(count == secp256k1_rss_binom(n - 1, t - 1));

    /* C(n-1, t-1) is never zero, but the batch inverter reads its first element
     * unconditionally, so guard the empty run anyway. */
    if (count > 0) {
        secp256k1_scalarpoly_inverse_batch_var(denominators, denominators, count);
        for (i = 0; i < count; i++) {
            secp256k1_scalar_mul(&weights[i], &weights[i], &denominators[i]);
        }
    }
    return count;
}

static void secp256k1_rss_eval(const secp256k1_hash_ctx *hash_ctx, secp256k1_scalar *r, const unsigned char *seeds, const secp256k1_scalar *weights, size_t num, const unsigned char *w, size_t wlen) {
    secp256k1_scalar term;
    size_t i;

    secp256k1_scalar_set_int(r, 0);
    for (i = 0; i < num; i++) {
        secp256k1_rss_prf(hash_ctx, &term, &seeds[32 * i], w, wlen);
        /* Secret times public. The loop bound and the stride are both public,
         * so nothing here branches or indexes on a seed value. */
        secp256k1_scalar_mul(&term, &term, &weights[i]);
        secp256k1_scalar_add(r, r, &term);
    }
    secp256k1_scalar_clear(&term);
}

#endif /* SECP256K1_MODULE_ICEBERG_RSS_IMPL_H */
