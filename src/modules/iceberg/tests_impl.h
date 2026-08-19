/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ICEBERG_TESTS_IMPL_H
#define SECP256K1_MODULE_ICEBERG_TESTS_IMPL_H

#include <string.h>

#include "../../../include/secp256k1_iceberg.h"
#include "../../../include/secp256k1_iceberg_dealer.h"

#include "../../scalar.h"
#include "../../testrand.h"
#include "../../testutil.h"
#include "../../unit_test.h"

#include "vectors.h"

/* The configuration tables below are written for a participant bound of ten.
 * That bound is fixed in the public header, so every one of these is false
 * today; they are here so that a build which edits the #define runs the subset
 * of each table that still fits instead of tripping an ARG_CHECK. */
static int iceberg_test_fits(unsigned int n) {
    return n <= SECP256K1_ICEBERG_MAX_PARTICIPANTS;
}

/* Horner evaluation, used only to check the library's own results against the
 * defining property of whatever it just computed. */
static void iceberg_test_poly_eval(secp256k1_scalar *r, const secp256k1_scalar *coeffs, size_t n_coeffs, unsigned int at) {
    secp256k1_scalar x;
    size_t i;

    secp256k1_scalar_set_int(&x, at);
    secp256k1_scalar_set_int(r, 0);
    for (i = n_coeffs; i > 0; i--) {
        secp256k1_scalar_mul(r, r, &x);
        secp256k1_scalar_add(r, r, &coeffs[i - 1]);
    }
}

static void iceberg_test_random_scalar(secp256k1_scalar *r) {
    unsigned char buf[32];
    testrand256(buf);
    secp256k1_scalar_set_b32(r, buf, NULL);
}

/* The outer MuSig2 half of a session, which most of the tests below need before
 * they can reach an iceberg call at all: a cosigner, and the aggregate of its
 * key with the group's. The group's key enters as an ordinary public key. */
static void iceberg_test_cosigner_key(secp256k1_keypair *keypair, secp256k1_pubkey *pk,
                                      secp256k1_xonly_pubkey *agg_xonly,
                                      secp256k1_musig_keyagg_cache *cache,
                                      const secp256k1_pubkey *group_pk,
                                      const unsigned char *seckey) {
    const secp256k1_pubkey *pubkeys[2];

    CHECK(secp256k1_keypair_create(CTX, keypair, seckey) == 1);
    CHECK(secp256k1_keypair_pub(CTX, pk, keypair) == 1);
    pubkeys[0] = group_pk;
    pubkeys[1] = pk;
    CHECK(secp256k1_musig_pubkey_agg(CTX, agg_xonly, cache, pubkeys, 2) == 1);
}

/* The cosigners' aggregate nonce, where the cosigners are the one made above.
 * An aggregate of one is not a special case anywhere. */
static void iceberg_test_cosigner_nonce(secp256k1_musig_secnonce *secnonce,
                                        secp256k1_musig_pubnonce *pubnonce,
                                        secp256k1_musig_aggnonce *aggnonce,
                                        unsigned char *secrand, const unsigned char *seckey,
                                        const secp256k1_pubkey *pk, const unsigned char *msg,
                                        const secp256k1_musig_keyagg_cache *cache) {
    const secp256k1_musig_pubnonce *just_cosigner[1];

    CHECK(secp256k1_musig_nonce_gen(CTX, secnonce, pubnonce, secrand, seckey, pk, msg, cache, NULL) == 1);
    just_cosigner[0] = pubnonce;
    CHECK(secp256k1_musig_nonce_agg(CTX, aggnonce, just_cosigner, 1) == 1);
}

/* A polynomial built from roots must vanish at each of them, and not at a
 * non-root: each round probes x = 11, which is never one. */
static void run_iceberg_from_roots_test(void) {
    unsigned char roots[5] = { 1, 3, 4, 7, 9 };
    secp256k1_scalar coeffs[6], value;
    size_t i, j;

    for (i = 1; i <= 5; i++) {
        secp256k1_scalarpoly_from_roots_var(coeffs, roots, i);
        for (j = 0; j < i; j++) {
            iceberg_test_poly_eval(&value, coeffs, i + 1, roots[j]);
            CHECK(secp256k1_scalar_is_zero(&value));
        }
        /* Monic, so the leading coefficient is one and the degree is exact. */
        CHECK(secp256k1_scalar_is_one(&coeffs[i]));
        /* An index that is not a root must not vanish. */
        iceberg_test_poly_eval(&value, coeffs, i + 1, 11);
        CHECK(!secp256k1_scalar_is_zero(&value));
    }
}

/* Dividing out a root and multiplying it back must return the original. */
static void run_iceberg_div_root_test(void) {
    unsigned char roots[4] = { 2, 5, 6, 8 };
    secp256k1_scalar master[5], quotient[4], value, expected;
    size_t j, at;

    secp256k1_scalarpoly_from_roots_var(master, roots, 4);
    for (j = 0; j < 4; j++) {
        secp256k1_scalarpoly_div_root_var(quotient, master, 4, roots[j]);
        /* q(x)*(x - root) == master(x), checked at a handful of points. */
        for (at = 1; at <= 12; at++) {
            secp256k1_scalar factor;
            iceberg_test_poly_eval(&value, quotient, 4, (unsigned int)at);
            secp256k1_scalarpoly_small_diff(&factor, (unsigned int)at, roots[j]);
            secp256k1_scalar_mul(&value, &value, &factor);
            iceberg_test_poly_eval(&expected, master, 5, (unsigned int)at);
            CHECK(secp256k1_scalar_eq(&value, &expected));
        }
    }
}

/* The two uses of lagrange_eval_var, each against an independent computation of
 * the same weight. These are the identities the whole scheme leans on, and both
 * routes below share no code with lagrange_parts_var.
 *
 * L_a(a) == 1 is not tested here: at == exclude makes the numerator and
 * denominator the same product, so it asserts x/x == 1 and any mutation that
 * changes both loops together still satisfies it. */
static void run_iceberg_lagrange_eval_test(void) {
    unsigned char set[3] = { 2, 4, 5 };
    unsigned char quorum[4] = { 1, 3, 4, 6 };
    secp256k1_scalar poly[4], basis[4 * 4], weight, expect, scale, total;
    unsigned int at;
    size_t j;

    /* exclude = 0 is the replicated-sharing weight L_a, which rss_impl.h evaluates
     * at a participant index outside a. Written as a polynomial the product over a
     * is monic, so L_a(x) = P_a(x)/P_a(0) with P_a from from_roots_var, which
     * run_iceberg_from_roots_test pins separately. L_a vanishing on every
     * member of a (why a party can evaluate its own share without the seeds it
     * lacks) is the special case P_a(i) == 0, so it is covered here too. */
    secp256k1_scalarpoly_from_roots_var(poly, set, 3);
    iceberg_test_poly_eval(&scale, poly, 4, 0);
    secp256k1_scalar_inverse_var(&scale, &scale);
    for (at = 0; at <= 9; at++) {
        secp256k1_scalarpoly_lagrange_eval_var(&weight, set, 3, 0, at);
        iceberg_test_poly_eval(&expect, poly, 4, at);
        secp256k1_scalar_mul(&expect, &expect, &scale);
        CHECK(secp256k1_scalar_eq(&weight, &expect));
    }

    /* exclude = j is the reconstruction weight lambda_j. Nothing above reaches the
     * skip in lagrange_parts_var, because 0 is never one of the indices; here it is
     * taken on every iteration. lagrange_basis_var builds the same polynomials
     * coefficient by coefficient and its own test pins it against poly_eval. */
    secp256k1_scalarpoly_lagrange_basis_var(basis, quorum, 4);
    for (j = 0; j < 4; j++) {
        for (at = 0; at <= 9; at++) {
            secp256k1_scalarpoly_lagrange_eval_var(&weight, quorum, 4, quorum[j], at);
            iceberg_test_poly_eval(&expect, &basis[j * 4], 4, at);
            CHECK(secp256k1_scalar_eq(&weight, &expect));
        }
    }

    /* And the reconstruction weights sum to one, for any quorum. */
    secp256k1_scalar_set_int(&total, 0);
    for (j = 0; j < 4; j++) {
        secp256k1_scalarpoly_lagrange_eval_var(&weight, quorum, 4, quorum[j], 0);
        secp256k1_scalar_add(&total, &total, &weight);
    }
    CHECK(secp256k1_scalar_is_one(&total));
}

/* Each basis polynomial is one at its own node and zero at the others. */
static void run_iceberg_lagrange_basis_test(void) {
    unsigned char quorum[5] = { 1, 2, 4, 7, 9 };
    secp256k1_scalar basis[5 * 5], value;
    size_t m, j, i;

    for (m = 1; m <= 5; m++) {
        secp256k1_scalarpoly_lagrange_basis_var(basis, quorum, m);
        for (j = 0; j < m; j++) {
            for (i = 0; i < m; i++) {
                iceberg_test_poly_eval(&value, &basis[j * m], m, quorum[i]);
                if (i == j) {
                    CHECK(secp256k1_scalar_is_one(&value));
                } else {
                    CHECK(secp256k1_scalar_is_zero(&value));
                }
            }
        }
    }
}

/* Interpolating m evaluations of a degree m-1 polynomial must return its
 * constant term.
 *
 * This runs all the way to SECP256K1_SCALARPOLY_MAX_POINTS deliberately. The
 * Python reference computes the same weights through numpy float64 and starts
 * returning wrong answers from a quorum of 19, with no indication that anything
 * went wrong. Working in the scalar field makes the size irrelevant, and testing
 * at the maximum is how we keep it that way. */
static void run_iceberg_interpolate_test_internal(void) {
    unsigned char quorum[SECP256K1_SCALARPOLY_MAX_POINTS];
    secp256k1_scalar coeffs[SECP256K1_SCALARPOLY_MAX_POINTS];
    secp256k1_scalar vals[SECP256K1_SCALARPOLY_MAX_POINTS];
    secp256k1_scalar recovered;
    size_t m, i, trial;

    /* Spread the indices rather than using 1..m, so a bug that only shows up
     * with consecutive nodes has somewhere to surface. */
    for (i = 0; i < SECP256K1_SCALARPOLY_MAX_POINTS; i++) {
        quorum[i] = (unsigned char)(2 * i + 1);
    }

    for (m = 1; m <= SECP256K1_SCALARPOLY_MAX_POINTS; m++) {
        for (trial = 0; trial < 2; trial++) {
            for (i = 0; i < m; i++) {
                iceberg_test_random_scalar(&coeffs[i]);
            }
            for (i = 0; i < m; i++) {
                iceberg_test_poly_eval(&vals[i], coeffs, m, quorum[i]);
            }
            secp256k1_scalarpoly_interpolate_at0(&recovered, quorum, vals, m);
            CHECK(secp256k1_scalar_eq(&recovered, &coeffs[0]));
        }
    }
}

static void run_iceberg_batch_inverse_test_internal(void) {
    secp256k1_scalar values[6], batched[6], single;
    size_t len, i;

    for (len = 1; len <= 6; len++) {
        for (i = 0; i < len; i++) {
            do {
                iceberg_test_random_scalar(&values[i]);
            } while (secp256k1_scalar_is_zero(&values[i]));
        }
        secp256k1_scalarpoly_inverse_batch_var(batched, values, len);
        for (i = 0; i < len; i++) {
            secp256k1_scalar_inverse_var(&single, &values[i]);
            CHECK(secp256k1_scalar_eq(&batched[i], &single));
        }
        /* In-place must give the same answer, since callers will want it. */
        secp256k1_scalarpoly_inverse_batch_var(values, values, len);
        for (i = 0; i < len; i++) {
            CHECK(secp256k1_scalar_eq(&batched[i], &values[i]));
        }
    }
}

/* The binomial is computed rather than tabulated, so check it against the
 * recurrence that defines it, and confirm the derived bounds in rss.h really
 * are the worst case they claim to be. */
static void run_iceberg_binom_test(void) {
    unsigned int n, k, max_t = 0;
    uint32_t max_summands = 0, max_subsets = 0;

    for (n = 0; n <= SECP256K1_ICEBERG_MAX_PARTICIPANTS; n++) {
        CHECK(secp256k1_rss_binom(n, 0) == 1);
        CHECK(secp256k1_rss_binom(n, n) == 1);
        for (k = 1; k < n; k++) {
            CHECK(secp256k1_rss_binom(n, k)
                  == secp256k1_rss_binom(n - 1, k - 1) + secp256k1_rss_binom(n - 1, k));
        }
    }

    /* A quorum of 2t-1 must fit in the group, so t <= (n+1)/2. Over every
     * expressible configuration, no threshold exceeds MAX_T, no participant
     * holds more seeds than MAX_SUMMANDS and no group has more subsets than
     * MAX_SUBSETS. All three are written out by hand, since C89 cannot evaluate
     * a binomial at preprocessing time, so all three are recomputed here.
     *
     * Each is pinned by equality rather than bounded. Too small overruns an
     * array and the bound alone would catch that; too large only wastes space,
     * which is a real thing to get told about when the participant bound has
     * been lowered and one of these was left behind. */
    for (n = 1; n <= SECP256K1_ICEBERG_MAX_PARTICIPANTS; n++) {
        unsigned int t;
        for (t = 1; 2 * t - 1 <= n; t++) {
            CHECK(t <= SECP256K1_ICEBERG_MAX_T);
            if (t > max_t) {
                max_t = t;
            }
            if (secp256k1_rss_binom(n - 1, t - 1) > max_summands) {
                max_summands = secp256k1_rss_binom(n - 1, t - 1);
            }
            if (secp256k1_rss_binom(n, t - 1) > max_subsets) {
                max_subsets = secp256k1_rss_binom(n, t - 1);
            }
        }
    }
    CHECK(max_t == SECP256K1_ICEBERG_MAX_T);
    CHECK(max_summands == SECP256K1_ICEBERG_MAX_SUMMANDS);
    CHECK(max_subsets == SECP256K1_ICEBERG_MAX_SUBSETS);
}

/* Ranking fixes the wire layout of a share, so it has to be a bijection and it
 * has to agree with lexicographic order. Both checked exhaustively. */
static void run_iceberg_subset_rank_test(void) {
    unsigned int n, size;

    for (n = 1; n <= SECP256K1_ICEBERG_MAX_PARTICIPANTS; n++) {
        for (size = 1; size <= n && size <= SECP256K1_ICEBERG_MAX_T; size++) {
            uint32_t total = secp256k1_rss_binom(n, size);
            unsigned char previous[SECP256K1_ICEBERG_MAX_T];
            unsigned char current[SECP256K1_ICEBERG_MAX_T];
            uint32_t rank;

            for (rank = 0; rank < total; rank++) {
                secp256k1_rss_subset subset = secp256k1_rss_subset_unrank(n, size, rank);
                size_t members = secp256k1_rss_subset_members(current, subset, n);
                CHECK(members == size);
                CHECK(secp256k1_rss_subset_rank(n, size, subset) == rank);
                if (rank > 0) {
                    /* Strictly increasing in lexicographic order. */
                    size_t i = 0;
                    while (i < size && previous[i] == current[i]) {
                        i++;
                    }
                    CHECK(i < size && previous[i] < current[i]);
                }
                memcpy(previous, current, size);
            }
        }
    }
}

/* Known answers taken from the reference implementation's own prf(). If these
 * drift, shares stop being portable between implementations. */
static void run_iceberg_prf_test(void) {
    static const unsigned char expected_hello[32] = {
        0xdf,0x15,0xf1,0x11,0xc7,0xd3,0xe8,0x7e,0x32,0x58,0x82,0x72,0xa0,0x9d,0x4f,0x25,
        0xaa,0x27,0x35,0xb5,0x4d,0x56,0x7e,0xbc,0xcd,0x10,0x29,0x79,0x01,0x74,0x71,0xbe
    };
    static const unsigned char expected_empty[32] = {
        0x20,0x15,0x27,0x95,0xd7,0x00,0x9c,0x6f,0x3c,0x7c,0x20,0x69,0x3e,0xf9,0xfc,0x51,
        0x63,0x8c,0x64,0x31,0x8e,0xb1,0xc2,0x65,0x1f,0x5f,0xd2,0x48,0xaf,0x05,0x9f,0x14
    };
    unsigned char seed[32], out[32];
    secp256k1_scalar r;

    memset(seed, 0x01, sizeof(seed));
    secp256k1_rss_prf(secp256k1_get_hash_context(CTX), &r, seed, (const unsigned char *)"hello", 5);
    secp256k1_scalar_get_b32(out, &r);
    CHECK(secp256k1_memcmp_var(out, expected_hello, 32) == 0);

    memset(seed, 0xab, sizeof(seed));
    secp256k1_rss_prf(secp256k1_get_hash_context(CTX), &r, seed, NULL, 0);
    secp256k1_scalar_get_b32(out, &r);
    CHECK(secp256k1_memcmp_var(out, expected_empty, 32) == 0);

}

/* Advance `chosen` to the next size-`size` subset of {1..n}, ascending.
 * Returns 0 once the last one has been passed. */
static int iceberg_test_next_combination(unsigned char *chosen, size_t size, unsigned int n) {
    size_t i = size;

    while (i > 0) {
        i--;
        if (chosen[i] < n - (size - 1 - i)) {
            size_t j;
            chosen[i]++;
            for (j = i + 1; j < size; j++) {
                chosen[j] = chosen[j - 1] + 1;
            }
            return 1;
        }
    }
    return 0;
}

/* Every precomputed midstate equals its tag applied at runtime.
 *
 * Each of the four is eight magic constants a person pasted in, and three of
 * them are only pinned by accident: dealer by the known-answer test, noncecoef
 * by the vectors, prf by the two digests above. Iceberg/batchcoef was pinned by
 * nothing at all, because the batching coefficient only has to be unpredictable:
 * any midstate produces a sound check, so a wrong one would have been invisible
 * here and two implementations would have disagreed in silence. */
static void run_iceberg_midstate_test(void) {
    static void (* const tagged[])(secp256k1_sha256 *) = {
        secp256k1_rss_prf_sha256_tagged,
        secp256k1_vpss_batchcoef_sha256_tagged,
        secp256k1_iceberg_dealer_sha256_tagged,
        secp256k1_iceberg_noncecoef_sha256_tagged
    };
    static const char * const tags[] = {
        "VPSS/prf", "Iceberg/batchcoef", "Iceberg/dealer", "Iceberg/noncecoef"
    };
    unsigned char probe[32];
    size_t i;

    memset(probe, 0x5e, sizeof(probe));
    for (i = 0; i < sizeof(tags) / sizeof(tags[0]); i++) {
        secp256k1_sha256 from_midstate, from_tag;
        unsigned char a[32], b[32];

        tagged[i](&from_midstate);
        secp256k1_sha256_initialize_tagged(secp256k1_get_hash_context(CTX), &from_tag,
                                           (const unsigned char *)tags[i], strlen(tags[i]));
        secp256k1_sha256_write(secp256k1_get_hash_context(CTX), &from_midstate, probe, sizeof(probe));
        secp256k1_sha256_write(secp256k1_get_hash_context(CTX), &from_tag, probe, sizeof(probe));
        secp256k1_sha256_finalize(secp256k1_get_hash_context(CTX), &from_midstate, a);
        secp256k1_sha256_finalize(secp256k1_get_hash_context(CTX), &from_tag, b);
        CHECK(secp256k1_memcmp_var(a, b, 32) == 0);
    }
}

/* The outer key aggregation, which partial_sign cannot check for itself.
 *
 * It takes the group's public key and the MuSig2 cache as two separate arguments
 * and nothing ties them together, because nothing can: a cache records the hash
 * of the key list rather than the list. keyagg_check answers the question
 * directly, and belongs where the cache is built rather than once per signature,
 * since the key set belongs to the channel. */
static void run_iceberg_keyagg_check_test(void) {
    enum { N = 7, T = 3, MU = 2 * T - 1 };
    secp256k1_iceberg_share shares[N];
    secp256k1_iceberg_share *share_ptrs[N];
    secp256k1_iceberg_pubshare pubshares[N];
    const secp256k1_iceberg_pubshare *pubshare_ptrs[MU];
    secp256k1_musig_keyagg_cache keyagg_cache;
    secp256k1_keypair cosigner_keypair;
    secp256k1_pubkey group_pk, cosigner_pk, impostor;
    const secp256k1_pubkey *pubkeys[2], *wrong[2];
    unsigned char seed[32], seckey[32], tweak[32];
    unsigned int k;
    size_t i;

    if (!iceberg_test_fits(N)) {
        return;
    }
    memset(seed, 0x11, sizeof(seed));
    memset(seckey, 0x22, sizeof(seckey));

    for (k = 1; k <= N; k++) {
        share_ptrs[k - 1] = &shares[k - 1];
    }
    CHECK(secp256k1_iceberg_shares_gen(CTX, share_ptrs, N, T, seed) == 1);
    for (k = 1; k <= N; k++) {
        CHECK(secp256k1_iceberg_pubshare_gen(CTX, &pubshares[k - 1], &shares[k - 1], NULL) == 1);
    }
    for (i = 0; i < MU; i++) {
        pubshare_ptrs[i] = &pubshares[i];
    }
    CHECK(secp256k1_iceberg_pubkey_agg(CTX, &group_pk, pubshare_ptrs, MU, N, T) == 1);

    CHECK(secp256k1_keypair_create(CTX, &cosigner_keypair, seckey) == 1);
    CHECK(secp256k1_keypair_pub(CTX, &cosigner_pk, &cosigner_keypair) == 1);
    /* A key the signer has no way to check against anything it holds. */
    seckey[0] ^= 1;
    CHECK(secp256k1_keypair_create(CTX, &cosigner_keypair, seckey) == 1);
    CHECK(secp256k1_keypair_pub(CTX, &impostor, &cosigner_keypair) == 1);

    pubkeys[0] = &group_pk;
    pubkeys[1] = &cosigner_pk;
    CHECK(secp256k1_musig_pubkey_agg(CTX, NULL, &keyagg_cache, pubkeys, 2) == 1);
    CHECK(secp256k1_iceberg_keyagg_check(CTX, &keyagg_cache, pubkeys, 2, &group_pk) == 1);

    /* The same two keys in the other order hash to something else. */
    pubkeys[0] = &cosigner_pk;
    pubkeys[1] = &group_pk;
    CHECK(secp256k1_iceberg_keyagg_check(CTX, &keyagg_cache, pubkeys, 2, &group_pk) == 0);

    /* The right list, but the group is not in it. */
    pubkeys[0] = &group_pk;
    pubkeys[1] = &cosigner_pk;
    CHECK(secp256k1_iceberg_keyagg_check(CTX, &keyagg_cache, pubkeys, 2, &impostor) == 0);

    /* A cosigner the cache was not built over. */
    wrong[0] = &group_pk;
    wrong[1] = &impostor;
    CHECK(secp256k1_iceberg_keyagg_check(CTX, &keyagg_cache, wrong, 2, &group_pk) == 0);

    /* Tweaks do not disturb it: the list hash is fixed at aggregation. */
    memset(tweak, 0x6e, sizeof(tweak));
    CHECK(secp256k1_musig_pubkey_xonly_tweak_add(CTX, NULL, &keyagg_cache, tweak) == 1);
    CHECK(secp256k1_iceberg_keyagg_check(CTX, &keyagg_cache, pubkeys, 2, &group_pk) == 1);
}


/* The identity the whole scheme rests on: participants who never communicate
 * produce evaluations of one degree t-1 polynomial whose constant term is the
 * sum of the hashes of every seed. Checked for every quorum, so "any t of them
 * agree" is exhaustive rather than sampled. */
static void run_iceberg_pss_test_internal(void) {
    static const unsigned char configs[][2] = { {3,2}, {4,2}, {5,3}, {6,3}, {7,4} };
    unsigned char seeds[SECP256K1_ICEBERG_MAX_SUBSETS][32];
    secp256k1_scalar weights[SECP256K1_ICEBERG_MAX_SUMMANDS];
    unsigned char held[SECP256K1_ICEBERG_MAX_SUMMANDS * 32];
    secp256k1_scalar shares[SECP256K1_ICEBERG_MAX_PARTICIPANTS + 1];
    unsigned char label[8] = "label";
    size_t config;

    for (config = 0; config < sizeof(configs) / sizeof(configs[0]); config++) {
        unsigned int n = configs[config][0], t = configs[config][1];
        uint32_t total = secp256k1_rss_binom(n, t - 1);
        secp256k1_scalar expected, term, recovered;
        unsigned char quorum[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        secp256k1_scalar quorum_vals[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        uint32_t rank;
        unsigned int k;
        size_t i;

        if (!iceberg_test_fits(n)) {
            continue;
        }

        for (rank = 0; rank < total; rank++) {
            testrand256(seeds[rank]);
        }

        /* f_w(0) is just the sum over every seed. No participant computes this,
         * and no participant could. */
        secp256k1_scalar_set_int(&expected, 0);
        for (rank = 0; rank < total; rank++) {
            secp256k1_rss_prf(secp256k1_get_hash_context(CTX), &term, seeds[rank], label, 5);
            secp256k1_scalar_add(&expected, &expected, &term);
        }

        for (k = 1; k <= n; k++) {
            size_t count = secp256k1_rss_lagrange_weights_var(weights, n, t, k);
            size_t got = 0;
            CHECK(count == secp256k1_rss_binom(n - 1, t - 1));
            /* Gather this participant's seeds in the same rank order the weights
             * were produced in. */
            for (rank = 0; rank < total; rank++) {
                secp256k1_rss_subset subset = secp256k1_rss_subset_unrank(n, t - 1, rank);
                if (subset & (secp256k1_rss_subset)(1u << k)) {
                    continue;
                }
                memcpy(&held[32 * got], seeds[rank], 32);
                got++;
            }
            CHECK(got == count);
            secp256k1_rss_eval(secp256k1_get_hash_context(CTX), &shares[k], held, weights, count, label, 5);
        }

        /* Every t-subset of participants must reconstruct the same value. */
        for (i = 0; i < t; i++) {
            quorum[i] = (unsigned char)(i + 1);
        }
        do {
            for (i = 0; i < t; i++) {
                quorum_vals[i] = shares[quorum[i]];
            }
            secp256k1_scalarpoly_interpolate_at0(&recovered, quorum, quorum_vals, t);
            CHECK(secp256k1_scalar_eq(&recovered, &expected));
        } while (iceberg_test_next_combination(quorum, t, n));
    }
}

/* The degree check, written out the way the definition reads: one
 * multiexponentiation per high coefficient, no batching, no transcript.
 *
 * This exists only to disagree with the batched implementation if the batching
 * is ever wrong, so it is deliberately a transcription of the defining property
 * rather than a refactor of the real code. It does share lagrange_basis_var with
 * the real one, which run_iceberg_lagrange_basis_test pins separately against
 * its defining property; an error there would pass both of these.
 */
static int iceberg_test_verify_naive(const unsigned char *idx, const secp256k1_ge *points, size_t m, unsigned int t) {
    secp256k1_scalar basis[SECP256K1_ICEBERG_MAX_PARTICIPANTS * SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    size_t i, j;

    secp256k1_scalarpoly_lagrange_basis_var(basis, idx, m);
    for (i = t; i < m; i++) {
        secp256k1_gej acc;
        secp256k1_gej_set_infinity(&acc);
        for (j = 0; j < m; j++) {
            secp256k1_gej term, pointj;
            secp256k1_gej_set_ge(&pointj, &points[j]);
            secp256k1_ecmult(&term, &pointj, &basis[j * m + i], NULL);
            secp256k1_gej_add_var(&acc, &acc, &term, NULL);
        }
        if (!secp256k1_gej_is_infinity(&acc)) {
            return 0;
        }
    }
    return 1;
}

/* Commit to a polynomial: points[i] <- f(idx[i]) * G. */
static void iceberg_test_commitments(secp256k1_ge *points, const unsigned char *idx, size_t m, const secp256k1_scalar *coeffs, size_t degree_plus_one) {
    size_t i;
    for (i = 0; i < m; i++) {
        secp256k1_scalar value;
        secp256k1_gej pointj;
        iceberg_test_poly_eval(&value, coeffs, degree_plus_one, idx[i]);
        secp256k1_ecmult_gen_gej(&CTX->ecmult_gen_ctx, &pointj, &value);
        secp256k1_ge_set_gej(&points[i], &pointj);
    }
}

static void run_iceberg_vpss_test_internal(void) {
    unsigned char idx[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_ge points[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_scalar coeffs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    unsigned int t;
    size_t m, i;

    for (i = 0; i < SECP256K1_ICEBERG_MAX_PARTICIPANTS; i++) {
        idx[i] = (unsigned char)(i + 1);
    }

    for (t = 2; t <= 4; t++) {
        for (m = 2 * t - 1; m <= SECP256K1_ICEBERG_MAX_PARTICIPANTS; m++) {
            secp256k1_ge tampered[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
            secp256k1_gej combined, expected_gej;
            secp256k1_ge expected;
            secp256k1_scalar high[SECP256K1_ICEBERG_MAX_PARTICIPANTS];

            for (i = 0; i < t; i++) {
                iceberg_test_random_scalar(&coeffs[i]);
            }
            iceberg_test_commitments(points, idx, m, coeffs, t);

            /* Honest commitments verify, and the batched check agrees with the
             * term-by-term one. */
            CHECK(secp256k1_vpss_verify_var(CTX, idx, points, m, t) == 1);
            CHECK(iceberg_test_verify_naive(idx, points, m, t) == 1);

            /* Combining gives the commitment to the secret, from any quorum. */
            CHECK(secp256k1_vpss_combine_var(CTX, &combined, idx, points, m) == 1);
            secp256k1_ecmult_gen_gej(&CTX->ecmult_gen_ctx, &expected_gej, &coeffs[0]);
            secp256k1_ge_set_gej(&expected, &expected_gej);
            CHECK(secp256k1_gej_eq_ge_var(&combined, &expected));

            /* One participant lying pushes the degree up and is caught. Both
             * implementations must agree that it was. */
            memcpy(tampered, points, sizeof(secp256k1_ge) * m);
            {
                secp256k1_gej bumped;
                secp256k1_scalar delta;
                iceberg_test_random_scalar(&delta);
                secp256k1_ecmult_gen_gej(&CTX->ecmult_gen_ctx, &bumped, &delta);
                secp256k1_gej_add_ge_var(&bumped, &bumped, &tampered[m / 2], NULL);
                secp256k1_ge_set_gej(&tampered[m / 2], &bumped);
            }
            CHECK(secp256k1_vpss_verify_var(CTX, idx, tampered, m, t) == 0);
            CHECK(iceberg_test_verify_naive(idx, tampered, m, t) == 0);

            /* A genuine degree-t sharing must also fail. The tamper case
             * above only shows that inconsistent points are caught; this shows
             * the check bounds the degree rather than merely testing that the
             * points lie on some polynomial. */
            if (m > t) {
                for (i = 0; i <= t; i++) {
                    iceberg_test_random_scalar(&high[i]);
                }
                do {
                    iceberg_test_random_scalar(&high[t]);
                } while (secp256k1_scalar_is_zero(&high[t]));
                iceberg_test_commitments(points, idx, m, high, t + 1);
                CHECK(secp256k1_vpss_verify_var(CTX, idx, points, m, t) == 0);
                CHECK(iceberg_test_verify_naive(idx, points, m, t) == 0);
            }
        }
    }
}

/* Any quorum, in any order, must combine to the same point. This is the
 * property that lets different participants show up in each signing round. */
static void run_iceberg_vpss_quorum_test_internal(void) {
    unsigned char all[7], quorum[7];
    secp256k1_ge points[7], chosen[7];
    secp256k1_scalar coeffs[3];
    secp256k1_gej expected, combined;
    unsigned int t = 3, n = 7;
    size_t i;

    if (!iceberg_test_fits(n)) {
        return;
    }

    for (i = 0; i < n; i++) {
        all[i] = (unsigned char)(i + 1);
    }
    for (i = 0; i < t; i++) {
        iceberg_test_random_scalar(&coeffs[i]);
    }
    iceberg_test_commitments(points, all, n, coeffs, t);
    secp256k1_ecmult_gen_gej(&CTX->ecmult_gen_ctx, &expected, &coeffs[0]);

    for (i = 0; i < t; i++) {
        quorum[i] = (unsigned char)(i + 1);
    }
    do {
        for (i = 0; i < t; i++) {
            chosen[i] = points[quorum[i] - 1];
        }
        CHECK(secp256k1_vpss_combine_var(CTX, &combined, quorum, chosen, t) == 1);
        {
            secp256k1_ge got;
            secp256k1_ge_set_gej(&got, &combined);
            CHECK(secp256k1_gej_eq_ge_var(&expected, &got));
        }
        /* The same quorum arranged backwards. next_combination only ever hands
         * out ascending sets, so without this the "in any order" above would be
         * an assumption: the weights are a function of the index set, not of how
         * it is laid out in the array. */
        {
            unsigned char reversed[7];
            secp256k1_ge backwards[7];
            secp256k1_ge got;
            for (i = 0; i < t; i++) {
                reversed[i] = quorum[t - 1 - i];
                backwards[i] = points[reversed[i] - 1];
            }
            CHECK(secp256k1_vpss_combine_var(CTX, &combined, reversed, backwards, t) == 1);
            secp256k1_ge_set_gej(&got, &combined);
            CHECK(secp256k1_gej_eq_ge_var(&expected, &got));
        }
    } while (iceberg_test_next_combination(quorum, t, n));
}

/* Deal a group and check the aggregated public key really is the shared secret.
 *
 * The secret is reconstructed here only to confirm the public path agrees with
 * it. No participant ever computes this value, and the API offers no way to. */
static void run_iceberg_keygen_test_internal(void) {
    static const unsigned char configs[][2] = { {3,2}, {5,3}, {5,2}, {7,4}, {9,5}, {10,5} };
    secp256k1_iceberg_share shares[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_iceberg_share *share_ptrs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_iceberg_share_cache caches[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_iceberg_pubshare pubshares[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    const secp256k1_iceberg_pubshare *pubshare_ptrs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    unsigned char seed[32];
    size_t config, i;

    for (config = 0; config < sizeof(configs) / sizeof(configs[0]); config++) {
        unsigned int n = configs[config][0], t = configs[config][1];
        unsigned int mu = 2 * t - 1;
        secp256k1_pubkey group_pk, again;
        secp256k1_scalar secret_shares[SECP256K1_ICEBERG_MAX_PARTICIPANTS + 1];
        secp256k1_scalar recovered;
        unsigned char quorum[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        secp256k1_scalar quorum_vals[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        secp256k1_gej expected_gej;
        secp256k1_ge expected, got;
        unsigned int k;

        if (!iceberg_test_fits(n)) {
            continue;
        }

        testrand256(seed);
        for (k = 1; k <= n; k++) {
            share_ptrs[k - 1] = &shares[k - 1];
        }
        CHECK(secp256k1_iceberg_shares_gen(CTX, share_ptrs, n, t, seed) == 1);

        for (k = 1; k <= n; k++) {
            const unsigned char *seeds;
            unsigned int gn, gt, gk;
            size_t count;
            secp256k1_scalar weights[SECP256K1_ICEBERG_MAX_SEEDS];

            CHECK(secp256k1_iceberg_share_cache_create(CTX, &caches[k - 1], &shares[k - 1]) == 1);
            CHECK(secp256k1_iceberg_pubshare_gen(CTX, &pubshares[k - 1], &shares[k - 1], &caches[k - 1]) == 1);
            pubshare_ptrs[k - 1] = &pubshares[k - 1];

            /* Reconstruct this participant's secret share, for the check below. */
            count = secp256k1_iceberg_share_load(CTX, &gn, &gt, &gk, &seeds, &shares[k - 1]);
            CHECK(count > 0 && gn == n && gt == t && gk == k);
            CHECK(secp256k1_rss_lagrange_weights_var(weights, n, t, k) == count);
            secp256k1_rss_eval(secp256k1_get_hash_context(CTX), &secret_shares[k], seeds, weights,
                               count, secp256k1_iceberg_keygen_label,
                               sizeof(secp256k1_iceberg_keygen_label));
        }

        /* A quorum of exactly 2t-1 aggregates to the group key. */
        CHECK(secp256k1_iceberg_pubkey_agg(CTX, &group_pk, pubshare_ptrs, mu, n, t) == 1);

        /* And that key is the commitment to the reconstructed secret. */
        for (i = 0; i < t; i++) {
            quorum[i] = (unsigned char)(i + 1);
            quorum_vals[i] = secret_shares[i + 1];
        }
        secp256k1_scalarpoly_interpolate_at0(&recovered, quorum, quorum_vals, t);
        secp256k1_ecmult_gen_gej(&CTX->ecmult_gen_ctx, &expected_gej, &recovered);
        secp256k1_ge_set_gej(&expected, &expected_gej);
        CHECK(secp256k1_pubkey_load(CTX, &got, &group_pk));
        CHECK(secp256k1_ge_eq_var(&expected, &got));

        /* The full group gives the same answer as the 2t-1 quorum. */
        if (n > mu) {
            CHECK(secp256k1_iceberg_pubkey_agg(CTX, &again, pubshare_ptrs, n, n, t) == 1);
            CHECK(secp256k1_memcmp_var(&group_pk, &again, sizeof(group_pk)) == 0);
        }

        /* Fewer than 2t-1 shares proves nothing and must be refused. */
        CHECK(secp256k1_iceberg_pubkey_agg(CTX, &again, pubshare_ptrs, mu - 1, n, t) == 0);

        /* Recomputing the weights must match using the cache. Against a saved
         * copy, not against pubshare_ptrs[0]: that points at pubshares[0], which
         * this line overwrites. */
        {
            secp256k1_iceberg_pubshare with_cache = pubshares[0];
            CHECK(secp256k1_iceberg_pubshare_gen(CTX, &pubshares[0], &shares[0], NULL) == 1);
            CHECK(secp256k1_memcmp_var(&pubshares[0], &with_cache, sizeof(pubshares[0])) == 0);
        }
    }
}

/* Serialization round-trips, and the configurations the scheme cannot express
 * are rejected at the point of dealing rather than later. */
static void run_iceberg_keygen_api_test(void) {
    secp256k1_iceberg_share shares[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_iceberg_share *ptrs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_iceberg_share parsed;
    secp256k1_iceberg_share_cache cache;
    secp256k1_iceberg_pubshare pubshare, reparsed;
    unsigned char seed[32], buf[4 + 32 * SECP256K1_ICEBERG_MAX_SEEDS], wire[34];
    size_t len, i;

    /* The only group this deals is five; the larger ones below are refusals. */
    if (!iceberg_test_fits(5)) {
        return;
    }

    memset(seed, 0x7c, sizeof(seed));
    for (i = 0; i < SECP256K1_ICEBERG_MAX_PARTICIPANTS; i++) {
        ptrs[i] = &shares[i];
    }

    /* Minority threshold only: t <= (n+1)/2, because a quorum of 2t-1 has to
     * fit in the group. These are the configurations people ask for first. */
    CHECK_ILLEGAL(CTX, secp256k1_iceberg_shares_gen(CTX, ptrs, 2, 2, seed)); /* 2-of-2 */
    CHECK_ILLEGAL(CTX, secp256k1_iceberg_shares_gen(CTX, ptrs, 4, 3, seed)); /* 3-of-4 */
    CHECK_ILLEGAL(CTX, secp256k1_iceberg_shares_gen(CTX, ptrs, 6, 4, seed)); /* 4-of-6 */
    CHECK_ILLEGAL(CTX, secp256k1_iceberg_shares_gen(CTX, ptrs, SECP256K1_ICEBERG_MAX_PARTICIPANTS + 1, 2, seed));

    CHECK(secp256k1_iceberg_shares_gen(CTX, ptrs, 5, 3, seed) == 1);

    /* Share round-trip, and a serialized share is exactly as large as it needs
     * to be rather than as large as the opaque type. */
    len = sizeof(buf);
    CHECK(secp256k1_iceberg_share_serialize(CTX, buf, &len, &shares[2]) == 1);
    CHECK(len == 4 + 32 * secp256k1_rss_binom(4, 2));
    CHECK(secp256k1_iceberg_share_parse(CTX, &parsed, buf, len) == 1);
    CHECK(secp256k1_memcmp_var(&parsed, &shares[2], sizeof(parsed)) == 0);

    /* Truncated, over-long and wrong-version inputs are all refused. The
     * over-long case matters on its own: a caller pulling a share out of a
     * longer record and passing the whole buffer must not have the tail
     * ignored. */
    CHECK(secp256k1_iceberg_share_parse(CTX, &parsed, buf, len - 1) == 0);
    CHECK(secp256k1_iceberg_share_parse(CTX, &parsed, buf, len + 1) == 0);
    CHECK(secp256k1_iceberg_share_parse(CTX, &parsed, buf, 3) == 0);
    buf[0] = 2;
    CHECK(secp256k1_iceberg_share_parse(CTX, &parsed, buf, len) == 0);
    buf[0] = 1;

    /* Too small a buffer reports the size it wanted. */
    len = 4;
    CHECK(secp256k1_iceberg_share_serialize(CTX, buf, &len, &shares[2]) == 0);
    CHECK(len == 4 + 32 * secp256k1_rss_binom(4, 2));

    /* A malformed share has no length to report, so it reports zero. A caller
     * that sizes a second call from *outlen, which is what the short-buffer case
     * above teaches it to do, would otherwise loop on the stale value
     * forever. */
    {
        secp256k1_iceberg_share broken = shares[2];
        broken.data[0] ^= 1;
        len = sizeof(buf);
        CHECK_ILLEGAL(CTX, secp256k1_iceberg_share_serialize(CTX, buf, &len, &broken));
        CHECK(len == 0);
    }

    /* SECP256K1_ICEBERG_SHARE_MAX_LEN is what the header promises callers can
     * size a buffer with, so it has to bound every configuration and not just
     * the ones above. The per-configuration check stays even though the last
     * line implies it: it fires on the offending n and t, where the other only
     * says the maximum came out wrong. */
    {
        unsigned int n, t;
        size_t largest = 0;
        for (n = 2; n <= SECP256K1_ICEBERG_MAX_PARTICIPANTS; n++) {
            for (t = 1; 2 * t - 1 <= n; t++) {
                size_t need = 4 + 32 * secp256k1_rss_binom(n - 1, t - 1);
                CHECK(need <= SECP256K1_ICEBERG_SHARE_MAX_LEN);
                if (need > largest) {
                    largest = need;
                }
            }
        }
        CHECK(largest == SECP256K1_ICEBERG_SHARE_MAX_LEN);
    }

    /* A cache belonging to another participant must not be usable, since it
     * would silently produce a wrong share rather than an error. */
    CHECK(secp256k1_iceberg_share_cache_create(CTX, &cache, &shares[0]) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_iceberg_pubshare_gen(CTX, &pubshare, &shares[1], &cache));

    /* Public share round-trip. */
    CHECK(secp256k1_iceberg_pubshare_gen(CTX, &pubshare, &shares[0], NULL) == 1);
    CHECK(secp256k1_iceberg_pubshare_serialize(CTX, wire, &pubshare) == 1);
    CHECK(secp256k1_iceberg_pubshare_parse(CTX, &reparsed, wire) == 1);
    CHECK(secp256k1_memcmp_var(&reparsed, &pubshare, sizeof(pubshare)) == 0);
    wire[0] = 0;
    CHECK(secp256k1_iceberg_pubshare_parse(CTX, &reparsed, wire) == 0);
}

/* The three objects that cross a network survive the trip, and the encodings
 * that would be ambiguous or unusable on the far side are refused. */
static void run_iceberg_wire_test(void) {
    enum { N = 5, T = 3, MU = 2 * T - 1 };
    secp256k1_iceberg_share shares[N];
    secp256k1_iceberg_share *share_ptrs[N];
    secp256k1_iceberg_pubnonce nonces[N], parsed_nonce;
    const secp256k1_iceberg_pubnonce *nonce_ptrs[N];
    secp256k1_iceberg_aggnonce aggnonce, parsed_agg;
    secp256k1_iceberg_partial_sig psig, parsed_psig;
    secp256k1_musig_pubnonce group_pubnonce;
    secp256k1_pubkey group_pk;
    secp256k1_iceberg_pubshare pubshares[N];
    const secp256k1_iceberg_pubshare *pubshare_ptrs[N];
    unsigned char seed[32], sid[32];
    unsigned char nonce67[67], agg66[66], psig33[33];
    unsigned int k;

    if (!iceberg_test_fits(N)) {
        return;
    }

    memset(seed, 0x5e, sizeof(seed));
    memset(sid, 0x9a, sizeof(sid));
    for (k = 0; k < N; k++) {
        share_ptrs[k] = &shares[k];
    }
    CHECK(secp256k1_iceberg_shares_gen(CTX, share_ptrs, N, T, seed) == 1);
    for (k = 0; k < N; k++) {
        CHECK(secp256k1_iceberg_pubshare_gen(CTX, &pubshares[k], &shares[k], NULL) == 1);
        pubshare_ptrs[k] = &pubshares[k];
    }
    CHECK(secp256k1_iceberg_pubkey_agg(CTX, &group_pk, pubshare_ptrs, MU, N, T) == 1);

    /* Any 32 bytes serve as a label: this test is about encodings, and the one
     * object here that would need an outer session is built by hand below. */
    for (k = 0; k < N; k++) {
        CHECK(secp256k1_iceberg_nonce_gen(CTX, &nonces[k], &shares[k], NULL, sid) == 1);
        nonce_ptrs[k] = &nonces[k];
    }
    CHECK(secp256k1_iceberg_nonce_agg(CTX, &group_pubnonce, &aggnonce,
                                      nonce_ptrs, MU, N, T, &group_pk) == 1);

    /* The internal aggregate is optional, since nothing in the API takes one
     * back. Asking for it must not change the nonce that does get published. */
    {
        secp256k1_musig_pubnonce without;
        CHECK(secp256k1_iceberg_nonce_agg(CTX, &without, NULL,
                                          nonce_ptrs, MU, N, T, &group_pk) == 1);
        CHECK(secp256k1_memcmp_var(&without, &group_pubnonce, sizeof(without)) == 0);
    }

    /* Round-trips. Comparing the opaque structs rather than re-serializing
     * catches a parse that loses something the encoding did carry. */
    CHECK(secp256k1_iceberg_pubnonce_serialize(CTX, nonce67, &nonces[2]) == 1);
    CHECK(nonce67[0] == 3);
    CHECK(secp256k1_iceberg_pubnonce_parse(CTX, &parsed_nonce, nonce67) == 1);
    CHECK(secp256k1_memcmp_var(&parsed_nonce, &nonces[2], sizeof(parsed_nonce)) == 0);

    CHECK(secp256k1_iceberg_aggnonce_serialize(CTX, agg66, &aggnonce) == 1);
    CHECK(secp256k1_iceberg_aggnonce_parse(CTX, &parsed_agg, agg66) == 1);
    CHECK(secp256k1_memcmp_var(&parsed_agg, &aggnonce, sizeof(parsed_agg)) == 0);

    /* A signature share, built by hand from a known scalar rather than by
     * signing, so this test needs no outer session. */
    {
        unsigned char raw[33];
        memset(raw, 0, sizeof(raw));
        raw[0] = 4;
        raw[32] = 0x2b;
        CHECK(secp256k1_iceberg_partial_sig_parse(CTX, &psig, raw) == 1);
        CHECK(secp256k1_iceberg_partial_sig_serialize(CTX, psig33, &psig) == 1);
        CHECK(secp256k1_memcmp_var(psig33, raw, sizeof(raw)) == 0);
        CHECK(secp256k1_iceberg_partial_sig_parse(CTX, &parsed_psig, psig33) == 1);
        CHECK(secp256k1_memcmp_var(&parsed_psig, &psig, sizeof(psig)) == 0);
    }

    /* An index past the end of the group names nobody. Zero is worse than that
     * and the two are worth separating: zero is where the secret lives. A set of
     * contributions containing a node at 0 puts the interpolation on top of one
     * of its own nodes, where the Lagrange weights are 1 for that node and 0 for
     * every other, so whoever sent it would be handing the group its aggregate
     * rather than contributing to it. These three comparisons are the only thing
     * standing there. */
    nonce67[0] = 0;
    CHECK(secp256k1_iceberg_pubnonce_parse(CTX, &parsed_nonce, nonce67) == 0);
    nonce67[0] = SECP256K1_ICEBERG_MAX_PARTICIPANTS + 1;
    CHECK(secp256k1_iceberg_pubnonce_parse(CTX, &parsed_nonce, nonce67) == 0);
    nonce67[0] = 3;
    psig33[0] = 0;
    CHECK(secp256k1_iceberg_partial_sig_parse(CTX, &parsed_psig, psig33) == 0);
    psig33[0] = 4;

    /* Not a point. Corrupting the x coordinate is no good as a test, since
     * about half of all x values do have a point, so break the prefix byte, which
     * is invalid for any x. */
    {
        unsigned char prefix = nonce67[1];
        nonce67[1] = 0x04;
        CHECK(secp256k1_iceberg_pubnonce_parse(CTX, &parsed_nonce, nonce67) == 0);
        nonce67[1] = prefix;
    }
    agg66[33] = 0x04;
    CHECK(secp256k1_iceberg_aggnonce_parse(CTX, &parsed_agg, agg66) == 0);

    /* A signature share at or above the group order. Aggregation is linear, so
     * one that wrapped would combine into a signature that merely fails to
     * verify, and nothing says which share was wrong. */
    memset(&psig33[1], 0xff, 32);
    CHECK(secp256k1_iceberg_partial_sig_parse(CTX, &parsed_psig, psig33) == 0);

    /* Infinity is representable, and must be, because the participants choose
     * their own contributions and nothing stops them summing to it. */
    memset(agg66, 0, sizeof(agg66));
    CHECK(secp256k1_iceberg_aggnonce_parse(CTX, &parsed_agg, agg66) == 1);
    CHECK(secp256k1_iceberg_aggnonce_serialize(CTX, agg66, &parsed_agg) == 1);
    for (k = 0; k < sizeof(agg66); k++) {
        CHECK(agg66[k] == 0);
    }
}

/* Rebuild one participant's serialized share from the group's seeds.
 *
 * The vectors carry the seeds once rather than every share, because each seed
 * belongs to n-(t-1) of them. Participant k holds the seeds whose subset leaves
 * it out, in the same rank order the dealer writes them. */
static size_t iceberg_test_share_from_seeds(unsigned char *out, const struct iceberg_session_vector *v, unsigned int k) {
    size_t used = 4, rank;

    out[0] = 1;
    out[1] = (unsigned char)v->n;
    out[2] = (unsigned char)v->t;
    out[3] = (unsigned char)k;
    for (rank = 0; rank < v->n_seeds; rank++) {
        secp256k1_rss_subset subset = secp256k1_rss_subset_unrank(v->n, v->t - 1, (uint32_t)rank);
        if (subset & (secp256k1_rss_subset)(1u << k)) {
            continue;
        }
        memcpy(&out[used], v->seeds[rank], 32);
        used += 32;
    }
    CHECK(used == 4 + 32 * secp256k1_rss_binom(v->n - 1, v->t - 1));
    return used;
}

/* Everything the group does, against what the Python reference produced.
 *
 * Until this existed the signing path was only ever checked against itself, so
 * a systematic disagreement with the reference would have passed every other
 * test in this file. It is not an authority, since both implementations
 * could be wrong the same way, but it is what catches them drifting apart. */
static void run_iceberg_vectors_test(void) {
    size_t which;

    for (which = 0; which < sizeof(iceberg_session_vectors) / sizeof(iceberg_session_vectors[0]); which++) {
        const struct iceberg_session_vector *v = &iceberg_session_vectors[which];
        secp256k1_iceberg_share shares[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        secp256k1_iceberg_pubshare pubshares[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        const secp256k1_iceberg_pubshare *pubshare_ptrs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        secp256k1_iceberg_pubnonce nonces[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        const secp256k1_iceberg_pubnonce *nonce_ptrs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        secp256k1_iceberg_partial_sig psigs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        const secp256k1_iceberg_partial_sig *psig_ptrs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        secp256k1_iceberg_aggnonce aggnonce;
        secp256k1_musig_pubnonce group_pubnonce, cosigner_pubnonce;
        const secp256k1_musig_pubnonce *just_the_cosigner[1];
        secp256k1_musig_aggnonce cosigner_aggnonce;
        secp256k1_musig_keyagg_cache keyagg_cache;
        secp256k1_musig_partial_sig group_psig;
        secp256k1_pubkey group_pk, cosigner_pk, parsed_group_pk;
        const secp256k1_pubkey *pubkeys[2];
        unsigned char buf[4 + 32 * SECP256K1_ICEBERG_MAX_SEEDS];
        unsigned char wire[67], sid[32];
        unsigned int k;
        size_t len;

        if (!iceberg_test_fits(v->n)) {
            continue;
        }

        for (k = 1; k <= v->n; k++) {
            len = iceberg_test_share_from_seeds(buf, v, k);
            CHECK(secp256k1_iceberg_share_parse(CTX, &shares[k - 1], buf, len) == 1);
        }

        /* Public shares. Each one is an independent evaluation of the keygen
         * label, so a disagreement here is in the PRF, the Lagrange weights or
         * the seed layout, before any of the session machinery runs. */
        for (k = 1; k <= v->n; k++) {
            CHECK(secp256k1_iceberg_pubshare_gen(CTX, &pubshares[k - 1], &shares[k - 1], NULL) == 1);
            CHECK(secp256k1_iceberg_pubshare_serialize(CTX, wire, &pubshares[k - 1]) == 1);
            CHECK(wire[0] == k);
            CHECK(secp256k1_memcmp_var(&wire[1], v->pubshares[k - 1], 33) == 0);
            pubshare_ptrs[k - 1] = &pubshares[k - 1];
        }

        CHECK(secp256k1_iceberg_pubkey_agg(CTX, &group_pk, pubshare_ptrs, v->mu, v->n, v->t) == 1);

        CHECK(secp256k1_ec_pubkey_parse(CTX, &parsed_group_pk, v->group_pk, 33) == 1);
        CHECK(secp256k1_memcmp_var(&group_pk, &parsed_group_pk, sizeof(group_pk)) == 0);

        /* The outer session, whose key and nonce the vector fixes. */
        CHECK(secp256k1_ec_pubkey_parse(CTX, &cosigner_pk, v->cosigner_pk, 33) == 1);
        pubkeys[0] = &group_pk;
        pubkeys[1] = &cosigner_pk;
        CHECK(secp256k1_musig_pubkey_agg(CTX, NULL, &keyagg_cache, pubkeys, 2) == 1);
        CHECK(secp256k1_musig_pubnonce_parse(CTX, &cosigner_pubnonce, v->cosigner_pubnonce) == 1);
        just_the_cosigner[0] = &cosigner_pubnonce;
        CHECK(secp256k1_musig_nonce_agg(CTX, &cosigner_aggnonce, just_the_cosigner, 1) == 1);

        /* The label is an input, so the vector carries it. Any 32 bytes would
         * do; these are the ones the generator happened to choose. */
        memcpy(sid, v->sid, 32);

        /* Round one. */
        for (k = 1; k <= v->mu; k++) {
            CHECK(secp256k1_iceberg_nonce_gen(CTX, &nonces[k - 1], &shares[k - 1], NULL, sid) == 1);
            CHECK(secp256k1_iceberg_pubnonce_serialize(CTX, wire, &nonces[k - 1]) == 1);
            CHECK(wire[0] == k);
            CHECK(secp256k1_memcmp_var(&wire[1], v->pubnonces[k - 1], 66) == 0);
            nonce_ptrs[k - 1] = &nonces[k - 1];
        }

        CHECK(secp256k1_iceberg_nonce_agg(CTX, &group_pubnonce, &aggnonce,
                                          nonce_ptrs, v->mu, v->n, v->t, &group_pk) == 1);
        CHECK(secp256k1_iceberg_aggnonce_serialize(CTX, wire, &aggnonce) == 1);
        CHECK(secp256k1_memcmp_var(wire, v->group_aggnonce, 66) == 0);
        /* The published nonce differs from the internal one by b1: the
         * aggregate compared above does not cover the nesting coefficient and
         * this does. So do the signature shares below, by a different route. */
        CHECK(secp256k1_musig_pubnonce_serialize(CTX, wire, &group_pubnonce) == 1);
        CHECK(secp256k1_memcmp_var(wire, v->group_pubnonce, 66) == 0);

        /* Round two. */
        for (k = 1; k <= v->t; k++) {
            CHECK(secp256k1_iceberg_partial_sign(CTX, &psigs[k - 1], &shares[k - 1], NULL, sid, nonce_ptrs, v->mu, &group_pk, &keyagg_cache, v->msg, &cosigner_aggnonce) == 1);
            CHECK(secp256k1_iceberg_partial_sig_serialize(CTX, wire, &psigs[k - 1]) == 1);
            CHECK(wire[0] == k);
            CHECK(secp256k1_memcmp_var(&wire[1], v->psigs[k - 1], 32) == 0);
            psig_ptrs[k - 1] = &psigs[k - 1];

            /* Verify the vector's share, parsed back off the wire, rather than
             * the one this run just produced. Everywhere else the verifier is
             * checked against another run of the code that wrote it. */
            {
                secp256k1_iceberg_partial_sig from_wire;
                unsigned char in33[33];

                in33[0] = (unsigned char)k;
                memcpy(&in33[1], v->psigs[k - 1], 32);
                CHECK(secp256k1_iceberg_partial_sig_parse(CTX, &from_wire, in33) == 1);
                CHECK(secp256k1_iceberg_partial_sig_verify(CTX, &from_wire, &pubshares[k - 1],
                                                           nonce_ptrs, v->mu, v->n, v->t, &group_pk, &keyagg_cache,
                                                           v->msg, &cosigner_aggnonce) == 1);
            }
        }

        CHECK(secp256k1_iceberg_partial_sig_agg(CTX, &group_psig, psig_ptrs, v->t, v->n, v->t) == 1);
        CHECK(secp256k1_musig_partial_sig_serialize(CTX, wire, &group_psig) == 1);
        CHECK(secp256k1_memcmp_var(wire, v->group_psig, 32) == 0);
    }
}

/* A participant who publishes something other than its real commitment raises
 * the degree of the interpolant and is caught. */
static void run_iceberg_keygen_cheat_test(void) {
    secp256k1_iceberg_share shares[5];
    secp256k1_iceberg_share *ptrs[5];
    secp256k1_iceberg_pubshare pubshares[5];
    const secp256k1_iceberg_pubshare *pubshare_ptrs[5];
    secp256k1_pubkey group_pk;
    unsigned char seed[32];
    unsigned int k;

    testrand256(seed);
    for (k = 0; k < 5; k++) {
        ptrs[k] = &shares[k];
    }
    CHECK(secp256k1_iceberg_shares_gen(CTX, ptrs, 5, 3, seed) == 1);
    for (k = 0; k < 5; k++) {
        CHECK(secp256k1_iceberg_pubshare_gen(CTX, &pubshares[k], &shares[k], NULL) == 1);
        pubshare_ptrs[k] = &pubshares[k];
    }
    CHECK(secp256k1_iceberg_pubkey_agg(CTX, &group_pk, pubshare_ptrs, 5, 5, 3) == 1);

    /* Swap two participants' commitments: each is individually valid, but they
     * no longer lie on one polynomial. */
    {
        secp256k1_iceberg_pubshare swapped = pubshares[1];
        pubshares[1] = pubshares[3];
        pubshares[3] = swapped;
        /* Restore the indices so only the points are wrong. */
        pubshares[1].data[4] = 2;
        pubshares[3].data[4] = 4;
    }
    CHECK(secp256k1_iceberg_pubkey_agg(CTX, &group_pk, pubshare_ptrs, 5, 5, 3) == 0);

    /* Duplicated indices are refused rather than producing a singular system. */
    CHECK(secp256k1_iceberg_pubshare_gen(CTX, &pubshares[1], &shares[1], NULL) == 1);
    CHECK(secp256k1_iceberg_pubshare_gen(CTX, &pubshares[3], &shares[3], NULL) == 1);
    pubshares[3].data[4] = 2;
    CHECK(secp256k1_iceberg_pubkey_agg(CTX, &group_pk, pubshare_ptrs, 5, 5, 3) == 0);
}

/* The three parsers, against input nobody meant them to see.
 *
 * The existing wire test picks malformations by hand: index zero, index past
 * the maximum, a point off the curve, a scalar at the group order. Those are the
 * cases somebody thought of. This covers the space between them: random buffers,
 * and single-bit flips of valid encodings, which is where a parser that is
 * almost right tends to be wrong.
 *
 * The invariant is round-tripping rather than acceptance. A parser is free to
 * reject anything it likes; what it must not do is accept something it cannot
 * then re-emit, because that is a value the rest of the module will treat as
 * well-formed and the wire will not agree about.
 */
static void run_iceberg_parser_fuzz_test(void) {
    secp256k1_iceberg_share shares[3];
    secp256k1_iceberg_share *share_ptrs[3];
    secp256k1_iceberg_pubnonce pubnonce, reparsed_nonce;
    secp256k1_iceberg_aggnonce aggnonce, reparsed_agg;
    secp256k1_iceberg_partial_sig psig, reparsed_psig;
    secp256k1_musig_pubnonce musig_pubnonce;
    const secp256k1_iceberg_pubnonce *nonce_ptrs[3];
    secp256k1_iceberg_pubshare pubshares[3];
    const secp256k1_iceberg_pubshare *pubshare_ptrs[3];
    secp256k1_pubkey group_pk;
    unsigned char seed[32], sid[32], seen[3][67], buffer[67], again[67];
    unsigned int k;
    int i, round;

    testrand256(seed);
    testrand256(sid);
    for (k = 0; k < 3; k++) {
        share_ptrs[k] = &shares[k];
    }
    CHECK(secp256k1_iceberg_shares_gen(CTX, share_ptrs, 3, 2, seed) == 1);
    for (k = 0; k < 3; k++) {
        CHECK(secp256k1_iceberg_pubshare_gen(CTX, &pubshares[k], &shares[k], NULL) == 1);
        pubshare_ptrs[k] = &pubshares[k];
    }
    CHECK(secp256k1_iceberg_pubkey_agg(CTX, &group_pk, pubshare_ptrs, 3, 3, 2) == 1);

    /* One real encoding of each, to flip bits in. */
    CHECK(secp256k1_iceberg_nonce_gen(CTX, &pubnonce, &shares[0], NULL, sid) == 1);
    CHECK(secp256k1_iceberg_pubnonce_serialize(CTX, seen[0], &pubnonce) == 1);

    /* Three distinct objects: nonce_agg reads each pointer in turn, so three
     * pointers at one object would offer the same participant's index three
     * times and be refused as duplicates. */
    {
        secp256k1_iceberg_pubnonce nonces[3];
        for (k = 0; k < 3; k++) {
            CHECK(secp256k1_iceberg_nonce_gen(CTX, &nonces[k], &shares[k], NULL, sid) == 1);
            nonce_ptrs[k] = &nonces[k];
        }
        CHECK(secp256k1_iceberg_nonce_agg(CTX, &musig_pubnonce, &aggnonce,
                                          nonce_ptrs, 3, 3, 2, &group_pk) == 1);
    }
    CHECK(secp256k1_iceberg_aggnonce_serialize(CTX, seen[1], &aggnonce) == 1);
    memset(&psig, 0, sizeof(psig));
    {
        /* A signature share built by hand, so this test does not need a whole
         * session to have something well-formed to corrupt. */
        unsigned char raw[33];
        memset(raw, 0, sizeof(raw));
        raw[0] = 1;
        /* Just under the group order, so a flipped bit in the top half has a
         * chance of pushing it over rather than always landing in range. */
        raw[1] = 0xff; raw[2] = 0xff; raw[3] = 0xff; raw[4] = 0xff;
        raw[32] = 7;
        CHECK(secp256k1_iceberg_partial_sig_parse(CTX, &psig, raw) == 1);
        CHECK(secp256k1_iceberg_partial_sig_serialize(CTX, seen[2], &psig) == 1);
    }

    /* Random bytes will not find the scalar boundary: a random 32-byte value
     * exceeds the group order with probability about 2^-128, so it essentially
     * never overflows, and neither does a bit flipped in a small one. The out-of-range share is
     * therefore named explicitly below. Without it a parser that reduced
     * instead of rejecting passes everything above. */
    {
        static const unsigned char order[32] = {
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
            0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41
        };
        unsigned char probe[33];
        probe[0] = 1;

        memcpy(&probe[1], order, 32);
        CHECK(secp256k1_iceberg_partial_sig_parse(CTX, &reparsed_psig, probe) == 0);

        memset(&probe[1], 0xff, 32);
        CHECK(secp256k1_iceberg_partial_sig_parse(CTX, &reparsed_psig, probe) == 0);

        /* One below the order is the largest thing that must be accepted, and it
         * has to survive a round trip unchanged rather than being reduced. */
        memcpy(&probe[1], order, 32);
        probe[32] -= 1;
        CHECK(secp256k1_iceberg_partial_sig_parse(CTX, &reparsed_psig, probe) == 1);
        CHECK(secp256k1_iceberg_partial_sig_serialize(CTX, again, &reparsed_psig) == 1);
        CHECK(secp256k1_memcmp_var(again, probe, 33) == 0);

        /* And zero, which is in range and easy to special-case by accident. */
        memset(&probe[1], 0, 32);
        CHECK(secp256k1_iceberg_partial_sig_parse(CTX, &reparsed_psig, probe) == 1);
        CHECK(secp256k1_iceberg_partial_sig_serialize(CTX, again, &reparsed_psig) == 1);
        CHECK(secp256k1_memcmp_var(again, probe, 33) == 0);
    }

    /* round 0: random bytes. round 1: one bit flipped in something valid. */
    for (round = 0; round < 2; round++) {
        for (i = 0; i < 64 * COUNT; i++) {
            int which = (int)testrand_int(3);
            size_t length = which == 0 ? 67 : (which == 1 ? 66 : 33);

            if (round == 0) {
                testrand_bytes_test(buffer, length);
            } else {
                memcpy(buffer, seen[which], length);
                testrand_flip(buffer, length);
            }

            if (which == 0) {
                if (secp256k1_iceberg_pubnonce_parse(CTX, &reparsed_nonce, buffer)) {
                    CHECK(secp256k1_iceberg_pubnonce_serialize(CTX, again, &reparsed_nonce) == 1);
                    CHECK(secp256k1_memcmp_var(again, buffer, length) == 0);
                }
            } else if (which == 1) {
                if (secp256k1_iceberg_aggnonce_parse(CTX, &reparsed_agg, buffer)) {
                    CHECK(secp256k1_iceberg_aggnonce_serialize(CTX, again, &reparsed_agg) == 1);
                    CHECK(secp256k1_memcmp_var(again, buffer, length) == 0);
                }
            } else {
                if (secp256k1_iceberg_partial_sig_parse(CTX, &reparsed_psig, buffer)) {
                    CHECK(secp256k1_iceberg_partial_sig_serialize(CTX, again, &reparsed_psig) == 1);
                    CHECK(secp256k1_memcmp_var(again, buffer, length) == 0);
                }
            }
        }
    }
}

/* Constraint C1, exhaustively: whoever shows up, the signature is the same one.
 *
 * The scheme's whole reason for deriving nonces rather than storing them is that
 * a member can go offline between the rounds and rejoin. So round one may be run
 * by any 2t-1 members, round two signed by any t members, and the two sets need
 * not overlap at all, and every combination must produce a byte-identical
 * signature, because the aggregate nonce and the key are the same either way.
 *
 * The e2e test checks two of those combinations. This checks all of them, at
 * sizes where "all of them" is cheap, because an earlier version of this module
 * imposed a restriction that broke C1 and no test could see it: every
 * configuration then had n == 2t-1, so there was only ever one round-one set.
 *
 * The cosigner's nonce is regenerated from the same randomness inside the loop.
 * That is not laziness. The final signature depends on it, so holding it fixed
 * is what makes "byte-identical" the right assertion rather than a coincidence.
 */
static void run_iceberg_c1_property_test(void) {
    static const unsigned char configs[][2] = { {4,2}, {5,2} };
    size_t config;

    for (config = 0; config < sizeof(configs) / sizeof(configs[0]); config++) {
        unsigned int n = configs[config][0], t = configs[config][1], mu = 2 * t - 1;
        secp256k1_iceberg_share shares[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        secp256k1_iceberg_share *share_ptrs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        secp256k1_iceberg_pubshare pubshares[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        const secp256k1_iceberg_pubshare *pubshare_ptrs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        secp256k1_iceberg_pubnonce nonces[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        const secp256k1_iceberg_pubnonce *nonce_ptrs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        secp256k1_iceberg_partial_sig psigs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        const secp256k1_iceberg_partial_sig *psig_ptrs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];

        secp256k1_pubkey group_pk, cosigner_pk;
        secp256k1_keypair cosigner_keypair;
        secp256k1_xonly_pubkey agg_xonly;
        secp256k1_musig_keyagg_cache keyagg_cache;
        unsigned char seed[32], msg[32], seckey[32], secrand[32], sid[32];
        unsigned char first_sig[64];
        unsigned char round_one[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        /* musig_nonce_gen wipes the randomness it is handed, so that one call
         * cannot silently become two. Keep a master copy and spend a fresh one
         * each time round the loop. */
        unsigned char secrand_master[32];
        unsigned char signers[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        unsigned int k;
        size_t i;
        int have_first = 0;
        int combinations = 0;

        if (!iceberg_test_fits(n)) {
            continue;
        }

        testrand256(seed);
        testrand256(msg);
        testrand256(seckey);
        testrand256(secrand_master);
        testrand256(sid);

        for (k = 1; k <= n; k++) {
            share_ptrs[k - 1] = &shares[k - 1];
        }
        CHECK(secp256k1_iceberg_shares_gen(CTX, share_ptrs, n, t, seed) == 1);

        for (k = 1; k <= n; k++) {
            CHECK(secp256k1_iceberg_pubshare_gen(CTX, &pubshares[k - 1], &shares[k - 1], NULL) == 1);
            pubshare_ptrs[k - 1] = &pubshares[k - 1];
        }
        CHECK(secp256k1_iceberg_pubkey_agg(CTX, &group_pk, pubshare_ptrs, mu, n, t) == 1);
        iceberg_test_cosigner_key(&cosigner_keypair, &cosigner_pk, &agg_xonly, &keyagg_cache,
                                  &group_pk, seckey);

        /* Every set that could run round one. */
        for (i = 0; i < mu; i++) {
            round_one[i] = (unsigned char)(i + 1);
        }
        do {
            secp256k1_musig_pubnonce cosigner_pubnonce, group_pubnonce;
            const secp256k1_musig_pubnonce *all_pubnonces[2];
            secp256k1_musig_aggnonce cosigner_aggnonce, full_aggnonce;

            for (i = 0; i < mu; i++) {
                CHECK(secp256k1_iceberg_nonce_gen(CTX, &nonces[i],
                                                  &shares[round_one[i] - 1], NULL, sid) == 1);
                nonce_ptrs[i] = &nonces[i];
            }
            CHECK(secp256k1_iceberg_nonce_agg(CTX, &group_pubnonce, NULL,
                                              nonce_ptrs, mu, n, t, &group_pk) == 1);

            /* Every set that could then sign, drawn from the whole group. */
            for (i = 0; i < t; i++) {
                signers[i] = (unsigned char)(i + 1);
            }
            do {
                secp256k1_musig_secnonce cosigner_secnonce;
                secp256k1_musig_session session;
                secp256k1_musig_partial_sig group_psig, cosigner_psig;
                const secp256k1_musig_partial_sig *musig_psigs[2];
                unsigned char sig[64];

                /* Rebuilt every time, from the same randomness, so the only
                 * thing varying across the loop is who took part. */
                memcpy(secrand, secrand_master, sizeof(secrand));
                CHECK(secp256k1_musig_nonce_gen(CTX, &cosigner_secnonce, &cosigner_pubnonce,
                                                secrand, seckey, &cosigner_pk, msg,
                                                &keyagg_cache, NULL) == 1);
                all_pubnonces[0] = &cosigner_pubnonce;
                CHECK(secp256k1_musig_nonce_agg(CTX, &cosigner_aggnonce, all_pubnonces, 1) == 1);
                all_pubnonces[0] = &group_pubnonce;
                all_pubnonces[1] = &cosigner_pubnonce;
                CHECK(secp256k1_musig_nonce_agg(CTX, &full_aggnonce, all_pubnonces, 2) == 1);
                CHECK(secp256k1_musig_nonce_process(CTX, &session, &full_aggnonce,
                                                    msg, &keyagg_cache) == 1);

                for (i = 0; i < t; i++) {
                    CHECK(secp256k1_iceberg_partial_sign(CTX, &psigs[i], &shares[signers[i] - 1], NULL, sid, nonce_ptrs, mu, &group_pk, &keyagg_cache, msg, &cosigner_aggnonce) == 1);
                    psig_ptrs[i] = &psigs[i];
                }
                CHECK(secp256k1_iceberg_partial_sig_agg(CTX, &group_psig, psig_ptrs, t, n, t) == 1);
                CHECK(secp256k1_musig_partial_sign(CTX, &cosigner_psig, &cosigner_secnonce,
                                                   &cosigner_keypair, &keyagg_cache,
                                                   &session) == 1);
                musig_psigs[0] = &group_psig;
                musig_psigs[1] = &cosigner_psig;
                CHECK(secp256k1_musig_partial_sig_agg(CTX, sig, &session, musig_psigs, 2) == 1);
                CHECK(secp256k1_schnorrsig_verify(CTX, sig, msg, 32, &agg_xonly) == 1);

                if (!have_first) {
                    memcpy(first_sig, sig, sizeof(sig));
                    have_first = 1;
                } else {
                    CHECK(secp256k1_memcmp_var(sig, first_sig, sizeof(sig)) == 0);
                }
                combinations++;
            } while (iceberg_test_next_combination(signers, t, n));
        } while (iceberg_test_next_combination(round_one, mu, n));

        /* C(n, mu) * C(n, t), so a silently truncated loop is caught. */
        CHECK(combinations == (int)(secp256k1_rss_binom(n, mu) * secp256k1_rss_binom(n, t)));
    }
}

/* A whole signing session: an Iceberg group standing in for one MuSig2
 * participant, beside an ordinary single signer who never learns a group is
 * involved, ending in a BIP-340 signature.
 *
 * The cosigner produces its nonce first here, but only because something has to
 * be written first. Both sides of round one need the session label and nothing
 * from each other, so either order works and a group can open a session.
 */
static void run_iceberg_e2e_test_internal(void) {
    /* The last two have n > 2t-1, so round one leaves somebody out. That is
     * what reaches the branch below where a member absent from round one signs
     * anyway; with n == 2t-1 throughout, nothing exercises it. */
    static const unsigned char configs[][2] = { {3,2}, {5,3}, {7,4}, {5,2}, {7,3} };
    size_t config;

    for (config = 0; config < sizeof(configs) / sizeof(configs[0]); config++) {
        unsigned int n = configs[config][0], t = configs[config][1], mu = 2 * t - 1;
        secp256k1_iceberg_share shares[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        secp256k1_iceberg_share *share_ptrs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        secp256k1_iceberg_share_cache first_cache;
        secp256k1_iceberg_pubshare pubshares[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        const secp256k1_iceberg_pubshare *pubshare_ptrs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        secp256k1_iceberg_pubnonce nonces[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        const secp256k1_iceberg_pubnonce *nonce_ptrs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        secp256k1_iceberg_partial_sig psigs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        const secp256k1_iceberg_partial_sig *psig_ptrs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
        secp256k1_iceberg_aggnonce iceberg_aggnonce;

        secp256k1_pubkey group_pk, cosigner_pk;
        secp256k1_keypair cosigner_keypair;
        secp256k1_xonly_pubkey agg_xonly;
        secp256k1_musig_keyagg_cache keyagg_cache;
        secp256k1_musig_secnonce cosigner_secnonce;
        secp256k1_musig_pubnonce cosigner_pubnonce, group_pubnonce;
        const secp256k1_musig_pubnonce *all_pubnonces[2];
        secp256k1_musig_aggnonce cosigner_aggnonce, full_aggnonce;
        secp256k1_musig_session session;
        secp256k1_musig_partial_sig group_psig, cosigner_psig;
        const secp256k1_musig_partial_sig *musig_psigs[2];

        unsigned char seed[32], msg[32], seckey[32], secrand[32], sid[32];
        unsigned char sig[64], sig_again[64];
        unsigned int k;
        size_t i;

        testrand256(seed);
        testrand256(msg);
        testrand256(seckey);
        if (!iceberg_test_fits(n)) {
            continue;
        }

        testrand256(secrand);

        /** setup **/
        for (k = 1; k <= n; k++) {
            share_ptrs[k - 1] = &shares[k - 1];
        }
        CHECK(secp256k1_iceberg_shares_gen(CTX, share_ptrs, n, t, seed) == 1);

        for (k = 1; k <= n; k++) {
            CHECK(secp256k1_iceberg_pubshare_gen(CTX, &pubshares[k - 1], &shares[k - 1], NULL) == 1);
            pubshare_ptrs[k - 1] = &pubshares[k - 1];
        }
        CHECK(secp256k1_iceberg_pubkey_agg(CTX, &group_pk, pubshare_ptrs, mu, n, t) == 1);

        /* The group's key enters aggregation as an ordinary public key. */
        iceberg_test_cosigner_key(&cosigner_keypair, &cosigner_pk, &agg_xonly, &keyagg_cache,
                                  &group_pk, seckey);

        /** round 1 **/
        iceberg_test_cosigner_nonce(&cosigner_secnonce, &cosigner_pubnonce, &cosigner_aggnonce,
                                   secrand, seckey, &cosigner_pk, msg, &keyagg_cache);

        /* Any 32 bytes. The caller owns this choice and the rule about it. */
        memset(sid, 0x5b, sizeof(sid));

        for (k = 1; k <= n; k++) {
            CHECK(secp256k1_iceberg_nonce_gen(CTX, &nonces[k - 1], &shares[k - 1], NULL, sid) == 1);
            nonce_ptrs[k - 1] = &nonces[k - 1];
        }
        CHECK(secp256k1_iceberg_nonce_agg(CTX, &group_pubnonce, &iceberg_aggnonce,
                                          nonce_ptrs, mu, n, t, &group_pk) == 1);

        all_pubnonces[0] = &group_pubnonce;
        all_pubnonces[1] = &cosigner_pubnonce;
        CHECK(secp256k1_musig_nonce_agg(CTX, &full_aggnonce, all_pubnonces, 2) == 1);
        CHECK(secp256k1_musig_nonce_process(CTX, &session, &full_aggnonce, msg, &keyagg_cache) == 1);

        /** round 2 **/
        for (k = 1; k <= t; k++) {
            CHECK(secp256k1_iceberg_partial_sign(CTX, &psigs[k - 1], &shares[k - 1], NULL, sid, nonce_ptrs, mu, &group_pk, &keyagg_cache, msg, &cosigner_aggnonce) == 1);
            psig_ptrs[k - 1] = &psigs[k - 1];
        }
        /* The cache must not change a single answer. It only saves recomputing
         * the Lagrange weights, so the whole risk in it is that it silently
         * produces a different one, and every other call in this file passes NULL,
         * which would leave that undetected. Both rounds, byte for byte. */
        CHECK(secp256k1_iceberg_share_cache_create(CTX, &first_cache, &shares[0]) == 1);
        {
            secp256k1_iceberg_pubnonce cached_nonce;
            secp256k1_iceberg_partial_sig cached_psig;
            CHECK(secp256k1_iceberg_nonce_gen(CTX, &cached_nonce, &shares[0], &first_cache, sid) == 1);
            CHECK(secp256k1_memcmp_var(&cached_nonce, &nonces[0], sizeof(cached_nonce)) == 0);
            CHECK(secp256k1_iceberg_partial_sign(CTX, &cached_psig, &shares[0], &first_cache, sid, nonce_ptrs, mu, &group_pk, &keyagg_cache, msg, &cosigner_aggnonce) == 1);
            CHECK(secp256k1_memcmp_var(&cached_psig, &psigs[0], sizeof(cached_psig)) == 0);
        }

        /* Every share verifies against its author's public share, at every
         * configuration this test runs. */
        for (k = 1; k <= t; k++) {
            CHECK(secp256k1_iceberg_partial_sig_verify(CTX, &psigs[k - 1], &pubshares[k - 1],
                                                       nonce_ptrs, mu, n, t, &group_pk, &keyagg_cache, msg,
                                                       &cosigner_aggnonce) == 1);
        }
        {
            secp256k1_iceberg_partial_sig altered = psigs[0];
            unsigned char other_msg[32];

            altered.data[10] ^= 0x40;
            CHECK(secp256k1_iceberg_partial_sig_verify(CTX, &altered, &pubshares[0],
                                                       nonce_ptrs, mu, n, t, &group_pk, &keyagg_cache, msg,
                                                       &cosigner_aggnonce) == 0);

            /* Participant 2's share against participant 1's public share. */
            if (t >= 2) {
                CHECK(secp256k1_iceberg_partial_sig_verify(CTX, &psigs[1], &pubshares[0],
                                                           nonce_ptrs, mu, n, t, &group_pk, &keyagg_cache, msg,
                                                           &cosigner_aggnonce) == 0);
            }

            /* Participant 1's own share, relabeled as
             * participant 2's, against participant 1's public share. Everything
             * the equation touches is participant 1's, so it still balances,
             * and nothing but the index comparison rejects this. Without that
             * comparison the answer would be a confident yes to a question
             * about participant 2. */
            altered = psigs[0];
            altered.data[4] = 2;
            CHECK(secp256k1_iceberg_partial_sig_verify(CTX, &altered, &pubshares[0],
                                                       nonce_ptrs, mu, n, t, &group_pk, &keyagg_cache, msg,
                                                       &cosigner_aggnonce) == 0);

            /* An input that differs from the signer's gives the same 0 as a bad
             * share, which is the reason a 0 is not evidence about a member. */
            memcpy(other_msg, msg, 32);
            other_msg[0] ^= 1;
            CHECK(secp256k1_iceberg_partial_sig_verify(CTX, &psigs[0], &pubshares[0],
                                                       nonce_ptrs, mu, n, t, &group_pk, &keyagg_cache, other_msg,
                                                       &cosigner_aggnonce) == 0);

            /* An uninitialized share is a 0 rather than a crash. */
            memset(&altered, 0, sizeof(altered));
            CHECK(secp256k1_iceberg_partial_sig_verify(CTX, &altered, &pubshares[0],
                                                       nonce_ptrs, mu, n, t, &group_pk, &keyagg_cache, msg,
                                                       &cosigner_aggnonce) == 0);
        }

        CHECK(secp256k1_iceberg_partial_sig_agg(CTX, &group_psig, psig_ptrs, t, n, t) == 1);

        /* One share past the threshold, which is where aggregation can tell that
         * a set contradicts itself. At exactly t it cannot: t points always lie
         * on some polynomial of degree t-1, so the tampered share below is
         * accepted there and refused here, and that difference is the check. */
        if (t + 1 <= n) {
            secp256k1_musig_partial_sig with_spare;
            secp256k1_iceberg_partial_sig tampered;

            CHECK(secp256k1_iceberg_partial_sign(CTX, &psigs[t], &shares[t], NULL, sid,
                                                 nonce_ptrs, mu, &group_pk, &keyagg_cache,
                                                 msg, &cosigner_aggnonce) == 1);
            psig_ptrs[t] = &psigs[t];

            /* A spare share changes nothing: any qualifying set interpolates to
             * the same value, which is the property the whole scheme rests on. */
            CHECK(secp256k1_iceberg_partial_sig_agg(CTX, &with_spare, psig_ptrs, t + 1, n, t) == 1);
            CHECK(secp256k1_memcmp_var(&with_spare, &group_psig, sizeof(with_spare)) == 0);

            tampered = psigs[0];
            tampered.data[36] ^= 1;
            psig_ptrs[0] = &tampered;
            CHECK(secp256k1_iceberg_partial_sig_agg(CTX, &with_spare, psig_ptrs, t, n, t) == 1);
            CHECK(secp256k1_iceberg_partial_sig_agg(CTX, &with_spare, psig_ptrs, t + 1, n, t) == 0);
            psig_ptrs[0] = &psigs[0];
        }

        CHECK(secp256k1_musig_partial_sign(CTX, &cosigner_psig, &cosigner_secnonce,
                                           &cosigner_keypair, &keyagg_cache, &session) == 1);

        musig_psigs[0] = &group_psig;
        musig_psigs[1] = &cosigner_psig;
        CHECK(secp256k1_musig_partial_sig_agg(CTX, sig, &session, musig_psigs, 2) == 1);

        /* The whole point: an ordinary BIP-340 signature. */
        CHECK(secp256k1_schnorrsig_verify(CTX, sig, msg, 32, &agg_xonly) == 1);

        /* A different quorum in round two produces the identical signature.
         * The signers may be any t of the n. A member absent from round one
         * still holds the share that fixes what its contribution would have
         * been, so it can check the set it is handed and sign against it. The
         * case below with mu < n exercises exactly that. */
        if (mu > t) {
            for (i = 0; i < t; i++) {
                k = (unsigned int)(mu - t + i + 1);
                CHECK(secp256k1_iceberg_partial_sign(CTX, &psigs[i], &shares[k - 1], NULL, sid, nonce_ptrs, mu, &group_pk, &keyagg_cache, msg, &cosigner_aggnonce) == 1);
                psig_ptrs[i] = &psigs[i];
            }
            CHECK(secp256k1_iceberg_partial_sig_agg(CTX, &group_psig, psig_ptrs, t, n, t) == 1);
            CHECK(secp256k1_musig_partial_sig_agg(CTX, sig_again, &session, musig_psigs, 2) == 1);
            CHECK(secp256k1_memcmp_var(sig, sig_again, 64) == 0);
            CHECK(secp256k1_schnorrsig_verify(CTX, sig_again, msg, 32, &agg_xonly) == 1);
        }

        /* What the module enforces, and what it does not.
         *
         * It does NOT refuse a different message under the same label. The
         * label is an argument again, because Lightning fixes the nonce a full
         * round-trip before the transaction exists and a label derived from the
         * message could not be computed in time. So one label with two messages
         * is expressible, it is the first attack in this family, and it is the
         * caller's job to make it impossible: half by never answering twice
         * under one label, half by the group agreeing which message a label
         * belongs to. See doc/iceberg.md.
         *
         * What it does enforce is that the contributions it is handed belong to
         * the session it thinks it is in. */
        {
            /* A set from a different label is refused. The contributions are
             * internally consistent, since they are a real sharing, but the
             * polynomial they define does not pass through this participant's
             * own contribution for the label it is signing under, and that is
             * what the check compares. */
            secp256k1_iceberg_pubnonce elsewhere[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
            const secp256k1_iceberg_pubnonce *elsewhere_ptrs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
            unsigned char other_sid[32];
            memcpy(other_sid, sid, 32);
            other_sid[0] ^= 1;
            for (i = 0; i < mu; i++) {
                CHECK(secp256k1_iceberg_nonce_gen(CTX, &elsewhere[i], &shares[i], NULL, other_sid) == 1);
                elsewhere_ptrs[i] = &elsewhere[i];
            }
            CHECK(secp256k1_iceberg_partial_sign(CTX, &psigs[0], &shares[0], NULL, sid, elsewhere_ptrs, mu, &group_pk, &keyagg_cache, msg, &cosigner_aggnonce) == 0);

            /* And the property that check must not cost: a member who was
             * absent from round one can still sign. Its contribution is a
             * function of its share and the label, so it can derive what its
             * contribution would have been and compare that against the
             * polynomial, without having been one of the contributors.
             *
             * Requiring the member's own contribution to be present would break
             * this and buy nothing: a corrupt minority can fit a consistent set
             * through any single honest contribution either way. Only checkable
             * when the group is larger than the quorum. */
            if (n > mu) {
                const secp256k1_iceberg_pubnonce *without_us[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
                for (i = 0; i < mu; i++) {
                    without_us[i] = nonce_ptrs[i + 1];
                }
                CHECK(secp256k1_iceberg_partial_sign(CTX, &psigs[0], &shares[0], NULL, sid, without_us, mu, &group_pk, &keyagg_cache, msg, &cosigner_aggnonce) == 1);
                CHECK(secp256k1_iceberg_partial_sign(CTX, &psigs[0], &shares[mu], NULL, sid, nonce_ptrs, mu, &group_pk, &keyagg_cache, msg, &cosigner_aggnonce) == 1);

                /* And that share verifies, which is the case the verifier exists
                 * for: participant mu+1 published no contribution, so
                 * there is no nonce of its own to hand over. The set fixes what
                 * its nonce had to be, and the verifier reads it from there. */
                CHECK(secp256k1_iceberg_partial_sig_verify(CTX, &psigs[0], &pubshares[mu],
                                                           nonce_ptrs, mu, n, t, &group_pk, &keyagg_cache, msg,
                                                           &cosigner_aggnonce) == 1);
            }

            /* The count a caller gets wrong: t contributions instead of the
             * 2t-1 this needs, because t is the number that signs and it is
             * easy to assume it is also the number to pass. Returns 0 rather
             * than aborting, which is what makes it worth documenting as
             * recoverable. */
            if (mu > t) {
                CHECK(secp256k1_iceberg_partial_sign(CTX, &psigs[0], &shares[0], NULL, sid, nonce_ptrs, t, &group_pk, &keyagg_cache, msg, &cosigner_aggnonce) == 0);
            }

            CHECK(secp256k1_iceberg_partial_sign(CTX, &psigs[0], &shares[0], NULL, sid, nonce_ptrs, mu, &group_pk, &keyagg_cache, msg, &cosigner_aggnonce) == 1);
            for (i = 1; i < t; i++) {
                CHECK(secp256k1_iceberg_partial_sign(CTX, &psigs[i], &shares[i], NULL, sid, nonce_ptrs, mu, &group_pk, &keyagg_cache, msg, &cosigner_aggnonce) == 1);
                psig_ptrs[i] = &psigs[i];
            }
            psig_ptrs[0] = &psigs[0];
            CHECK(secp256k1_iceberg_partial_sig_agg(CTX, &group_psig, psig_ptrs, t, n, t) == 1);
            CHECK(secp256k1_musig_partial_sig_agg(CTX, sig_again, &session, musig_psigs, 2) == 1);
            CHECK(secp256k1_schnorrsig_verify(CTX, sig_again, msg, 32, &agg_xonly) == 1);
        }
    }
}

/* Iceberg under tweaks, which every Taproot output uses.
 *
 * `tacc` belongs to the outer session: musig_nonce_process sets `e * tacc`
 * aside and musig_partial_sig_agg adds it once. A group's shares therefore
 * carry `e * a * g * gacc` and NOT the tweak, or it is added twice and the
 * signature fails. Nothing in the module mentions tacc, so the correct
 * behavior is an absence, and this is what would catch someone reintroducing
 * it while editing the key coefficient.
 *
 * Both tweak kinds and both orders, since tacc accumulates and an x-only tweak
 * can flip the aggregate key's parity. */
static void run_iceberg_tweak_test_internal(void) {
    enum { N = 5, T = 3, MU = 2 * T - 1 };
    /* ec then xonly, xonly then ec, two xonly, and one of each alone. */
    static const unsigned char plans[][2] = { {0,1}, {1,0}, {1,1}, {0,2}, {1,2} };
    size_t plan;

    if (!iceberg_test_fits(N)) {
        return;
    }

    for (plan = 0; plan < sizeof(plans) / sizeof(plans[0]); plan++) {
        secp256k1_iceberg_share shares[N];
        secp256k1_iceberg_share *share_ptrs[N];
        secp256k1_iceberg_pubshare pubshares[N];
        const secp256k1_iceberg_pubshare *pubshare_ptrs[N];
        secp256k1_iceberg_pubnonce nonces[N];
        const secp256k1_iceberg_pubnonce *nonce_ptrs[N];
        secp256k1_iceberg_partial_sig psigs[N];
        const secp256k1_iceberg_partial_sig *psig_ptrs[N];
        secp256k1_iceberg_aggnonce iceberg_aggnonce;

        secp256k1_pubkey group_pk, cosigner_pk, output_pk;
        secp256k1_keypair cosigner_keypair;
        secp256k1_xonly_pubkey agg_xonly, output_xonly;
        secp256k1_musig_keyagg_cache keyagg_cache;
        secp256k1_musig_secnonce cosigner_secnonce;
        secp256k1_musig_pubnonce cosigner_pubnonce, group_pubnonce;
        const secp256k1_musig_pubnonce *all_pubnonces[2];
        secp256k1_musig_aggnonce cosigner_aggnonce, full_aggnonce;
        secp256k1_musig_session session;
        secp256k1_musig_partial_sig group_psig, cosigner_psig;
        const secp256k1_musig_partial_sig *musig_psigs[2];

        unsigned char seed[32], msg[32], seckey[32], secrand[32], sid[32];
        unsigned char tweak[32], sig[64];
        unsigned int k, step;

        testrand256(seed);
        testrand256(msg);
        testrand256(seckey);
        testrand256(secrand);

        for (k = 1; k <= N; k++) {
            share_ptrs[k - 1] = &shares[k - 1];
        }
        CHECK(secp256k1_iceberg_shares_gen(CTX, share_ptrs, N, T, seed) == 1);

        for (k = 1; k <= N; k++) {
            CHECK(secp256k1_iceberg_pubshare_gen(CTX, &pubshares[k - 1], &shares[k - 1], NULL) == 1);
            pubshare_ptrs[k - 1] = &pubshares[k - 1];
        }
        CHECK(secp256k1_iceberg_pubkey_agg(CTX, &group_pk, pubshare_ptrs, MU, N, T) == 1);

        iceberg_test_cosigner_key(&cosigner_keypair, &cosigner_pk, &agg_xonly, &keyagg_cache,
                                  &group_pk, seckey);

        /* Tweak the OUTER aggregate, which is where a Taproot output comes
         * from. The group never learns it happened: nothing below this point
         * passes the tweak to an Iceberg call. */
        for (step = 0; step < 2; step++) {
            unsigned char kind = plans[plan][step];
            if (kind == 2) {
                continue;                    /* this plan applies only one tweak */
            }
            testrand256(tweak);
            if (kind == 0) {
                CHECK(secp256k1_musig_pubkey_ec_tweak_add(CTX, &output_pk, &keyagg_cache, tweak) == 1);
            } else {
                CHECK(secp256k1_musig_pubkey_xonly_tweak_add(CTX, &output_pk, &keyagg_cache, tweak) == 1);
            }
        }
        CHECK(secp256k1_xonly_pubkey_from_pubkey(CTX, &output_xonly, NULL, &output_pk) == 1);

        /** round 1, exactly as untweaked **/
        iceberg_test_cosigner_nonce(&cosigner_secnonce, &cosigner_pubnonce, &cosigner_aggnonce,
                                   secrand, seckey, &cosigner_pk, msg, &keyagg_cache);
        memset(sid, 0x3e, sizeof(sid));
        for (k = 1; k <= N; k++) {
            CHECK(secp256k1_iceberg_nonce_gen(CTX, &nonces[k - 1], &shares[k - 1], NULL, sid) == 1);
            nonce_ptrs[k - 1] = &nonces[k - 1];
        }
        CHECK(secp256k1_iceberg_nonce_agg(CTX, &group_pubnonce, &iceberg_aggnonce,
                                          nonce_ptrs, MU, N, T, &group_pk) == 1);
        all_pubnonces[0] = &group_pubnonce;
        all_pubnonces[1] = &cosigner_pubnonce;
        CHECK(secp256k1_musig_nonce_agg(CTX, &full_aggnonce, all_pubnonces, 2) == 1);
        CHECK(secp256k1_musig_nonce_process(CTX, &session, &full_aggnonce, msg, &keyagg_cache) == 1);

        /** round 2 **/
        for (k = 1; k <= T; k++) {
            CHECK(secp256k1_iceberg_partial_sign(CTX, &psigs[k - 1], &shares[k - 1], NULL, sid, nonce_ptrs, MU, &group_pk, &keyagg_cache, msg, &cosigner_aggnonce) == 1);
            psig_ptrs[k - 1] = &psigs[k - 1];
        }
        CHECK(secp256k1_iceberg_partial_sig_agg(CTX, &group_psig, psig_ptrs, T, N, T) == 1);
        CHECK(secp256k1_musig_partial_sign(CTX, &cosigner_psig, &cosigner_secnonce,
                                           &cosigner_keypair, &keyagg_cache, &session) == 1);
        musig_psigs[0] = &group_psig;
        musig_psigs[1] = &cosigner_psig;
        CHECK(secp256k1_musig_partial_sig_agg(CTX, sig, &session, musig_psigs, 2) == 1);

        /* Verifies under the TWEAKED key, and not under the untweaked one --
         * the second half matters, because a signature that verified under both
         * would mean the tweak had not reached the challenge at all. */
        CHECK(secp256k1_schnorrsig_verify(CTX, sig, msg, 32, &output_xonly) == 1);
        CHECK(secp256k1_schnorrsig_verify(CTX, sig, msg, 32, &agg_xonly) == 0);
    }
}

REPEAT_TEST(run_iceberg_tweak_test)
REPEAT_TEST(run_iceberg_e2e_test)
REPEAT_TEST(run_iceberg_interpolate_test)
REPEAT_TEST(run_iceberg_batch_inverse_test)
REPEAT_TEST(run_iceberg_pss_test)
REPEAT_TEST(run_iceberg_vpss_test)
REPEAT_TEST(run_iceberg_vpss_quorum_test)
REPEAT_TEST(run_iceberg_keygen_test)

/* The dealer's output, pinned to a fixed answer.
 *
 * Nothing else pins it. run_iceberg_vectors_test never calls shares_gen; it
 * rebuilds shares from the per-subset seeds the vectors already carry, and
 * every other test is self-consistent, so a change to the derivation moves all
 * of them together and none of them notices. Without this test, changing the t
 * byte of the dealer's preimage to t + 1 is caught by nothing.
 *
 * The digest is over the five serialized shares of one deal, in participant
 * order. Regenerating it after a deliberate change is easy and almost always the
 * wrong thing to do: a serialized share is a wire format two implementations
 * have to agree on byte for byte, so a change here is a change to that format
 * and the reference implementation has to move with it. */
static void run_iceberg_dealer_kat_test(void) {
    enum { N = 5, T = 3 };
    static const unsigned char expected[32] = {
        0x74, 0xf0, 0xec, 0x3f, 0xec, 0xbf, 0x47, 0xae,
        0x81, 0xbf, 0xec, 0x45, 0xdd, 0x01, 0xe2, 0x12,
        0xf5, 0x30, 0xd1, 0x1c, 0xf4, 0x7e, 0x89, 0x1a,
        0x7d, 0x19, 0xb5, 0x14, 0x71, 0xb8, 0xed, 0x09
    };
    secp256k1_iceberg_share shares[N];
    secp256k1_iceberg_share *ptrs[N];
    secp256k1_sha256 sha;
    unsigned char seed[32], buf[SECP256K1_ICEBERG_SHARE_MAX_LEN], digest[32];
    unsigned int k;
    size_t len;

    if (!iceberg_test_fits(N)) {
        return;
    }
    memset(seed, 0xa7, sizeof(seed));
    for (k = 1; k <= N; k++) {
        ptrs[k - 1] = &shares[k - 1];
    }
    CHECK(secp256k1_iceberg_shares_gen(CTX, ptrs, N, T, seed) == 1);

    secp256k1_sha256_initialize(&sha);
    for (k = 1; k <= N; k++) {
        len = sizeof(buf);
        CHECK(secp256k1_iceberg_share_serialize(CTX, buf, &len, &shares[k - 1]) == 1);
        CHECK(len == 4 + 32 * secp256k1_rss_binom(N - 1, T - 1));
        /* The header gets its own assertion: a wrong version, group, threshold
         * or index gives a clearer failure here than a digest ever will. */
        CHECK(buf[0] == 1 && buf[1] == N && buf[2] == T && buf[3] == k);
        secp256k1_sha256_write(secp256k1_get_hash_context(CTX), &sha, buf, len);
    }
    secp256k1_sha256_finalize(secp256k1_get_hash_context(CTX), &sha, digest);
    CHECK(secp256k1_memcmp_var(digest, expected, sizeof(digest)) == 0);
}

/* An index the group does not contain must be refused by whatever knows the
 * group size.
 *
 * Each check must bound against the group's own n, not the compile-time
 * maximum. The parsers let the band n < k <= 10 through deliberately, having no
 * way to know n, which leaves these calls as the only place it can be stopped.
 *
 * One group of ten is dealt and then five of its members, one of them
 * participant 7, are presented to calls told the group is five. Dealing a single
 * group is what makes this a test of the index check and not of the degree
 * check: every point really does lie on the same degree t-1 polynomial, so a
 * build that bounds by the maximum finds nothing else to object to and hands
 * back the ten-member group's key to a caller who believes it has five.
 *
 * Each rejection is paired with the same call at n = 10, which must succeed. A
 * test that only checks for 0 cannot tell a working bound from a broken set. */
static void run_iceberg_foreign_index_test(void) {
    enum { N = 10, T = 3, MU = 2 * T - 1, CLAIMED = 5 };
    secp256k1_iceberg_share shares[N];
    secp256k1_iceberg_share *share_ptrs[N];
    secp256k1_iceberg_pubshare pubshares[N];
    const secp256k1_iceberg_pubshare *quorum_pubshares[MU];
    secp256k1_iceberg_pubnonce nonces[N];
    const secp256k1_iceberg_pubnonce *quorum_nonces[MU], *inside_nonces[MU];
    secp256k1_iceberg_partial_sig psigs[T];
    const secp256k1_iceberg_partial_sig *psig_ptrs[T];
    secp256k1_musig_keyagg_cache keyagg_cache;
    secp256k1_musig_aggnonce cosigner_aggnonce;
    secp256k1_musig_pubnonce cosigner_pubnonce, group_pubnonce;
    secp256k1_musig_secnonce cosigner_secnonce;
    secp256k1_musig_partial_sig musig_psig;
    secp256k1_keypair cosigner_keypair;
    secp256k1_xonly_pubkey agg_xonly;
    secp256k1_pubkey group_pk, again, cosigner_pk;
    unsigned char seed[32], seckey[32], secrand[32], sid[32], msg[32];
    /* Four members the claimed group of five contains, and one it does not. */
    const unsigned int members[MU] = { 1, 2, 3, 4, 7 };
    /* The t who go on to sign, participant 7 among them. */
    const unsigned int signers[T] = { 1, 2, 7 };
    /* A second quorum, every member of which the claimed group does contain. */
    const unsigned int inside[MU] = { 1, 2, 3, 4, 5 };
    unsigned int k;
    size_t i;

    if (!iceberg_test_fits(N)) {
        return;
    }
    memset(seed, 0x41, sizeof(seed));
    memset(seckey, 0x31, sizeof(seckey));
    memset(secrand, 0x77, sizeof(secrand));
    memset(sid, 0x53, sizeof(sid));
    memset(msg, 0x64, sizeof(msg));

    for (k = 1; k <= N; k++) {
        share_ptrs[k - 1] = &shares[k - 1];
    }
    CHECK(secp256k1_iceberg_shares_gen(CTX, share_ptrs, N, T, seed) == 1);
    for (k = 1; k <= N; k++) {
        CHECK(secp256k1_iceberg_pubshare_gen(CTX, &pubshares[k - 1], &shares[k - 1], NULL) == 1);
    }
    for (i = 0; i < MU; i++) {
        quorum_pubshares[i] = &pubshares[members[i] - 1];
    }

    /* Aggregation. The same five public shares, the same degree check. */
    CHECK(secp256k1_iceberg_pubkey_agg(CTX, &group_pk, quorum_pubshares, MU, N, T) == 1);
    CHECK(secp256k1_iceberg_pubkey_agg(CTX, &again, quorum_pubshares, MU, CLAIMED, T) == 0);

    iceberg_test_cosigner_key(&cosigner_keypair, &cosigner_pk, &agg_xonly, &keyagg_cache,
                              &group_pk, seckey);
    iceberg_test_cosigner_nonce(&cosigner_secnonce, &cosigner_pubnonce, &cosigner_aggnonce,
                               secrand, seckey, &cosigner_pk, msg, &keyagg_cache);

    for (k = 1; k <= N; k++) {
        CHECK(secp256k1_iceberg_nonce_gen(CTX, &nonces[k - 1], &shares[k - 1], NULL, sid) == 1);
    }
    for (i = 0; i < MU; i++) {
        quorum_nonces[i] = &nonces[members[i] - 1];
        inside_nonces[i] = &nonces[inside[i] - 1];
    }

    /* Round one. */
    CHECK(secp256k1_iceberg_nonce_agg(CTX, &group_pubnonce, NULL,
                                      quorum_nonces, MU, N, T, &group_pk) == 1);
    CHECK(secp256k1_iceberg_nonce_agg(CTX, &group_pubnonce, NULL,
                                      quorum_nonces, MU, CLAIMED, T, &group_pk) == 0);

    for (i = 0; i < T; i++) {
        k = signers[i];
        CHECK(secp256k1_iceberg_partial_sign(CTX, &psigs[i], &shares[k - 1], NULL, sid,
                                             quorum_nonces, MU, &group_pk, &keyagg_cache,
                                             msg, &cosigner_aggnonce) == 1);
        psig_ptrs[i] = &psigs[i];
    }

    /* Verification refuses twice over, and for two different reasons: first on
     * an index inside the set of contributions, then, with a quorum the claimed
     * group does contain, on the public share's own index. */
    CHECK(secp256k1_iceberg_partial_sig_verify(CTX, &psigs[0], &pubshares[signers[0] - 1],
                                               quorum_nonces, MU, N, T, &group_pk,
                                               &keyagg_cache, msg, &cosigner_aggnonce) == 1);
    CHECK(secp256k1_iceberg_partial_sig_verify(CTX, &psigs[0], &pubshares[signers[0] - 1],
                                               quorum_nonces, MU, CLAIMED, T, &group_pk,
                                               &keyagg_cache, msg, &cosigner_aggnonce) == 0);
    /* And participant 7's own share, checked against participant 7, over a
     * quorum the claimed group does contain, so that the contribution indices
     * cannot be what rejects it and the public share's own index is left as the
     * only thing that can. Participant 7 can sign over a set it is absent from:
     * that is the property partial_sign is built around. */
    {
        secp256k1_iceberg_partial_sig seven;
        CHECK(secp256k1_iceberg_partial_sign(CTX, &seven, &shares[6], NULL, sid,
                                             inside_nonces, MU, &group_pk, &keyagg_cache,
                                             msg, &cosigner_aggnonce) == 1);
        CHECK(secp256k1_iceberg_partial_sig_verify(CTX, &seven, &pubshares[6],
                                                   inside_nonces, MU, N, T, &group_pk,
                                                   &keyagg_cache, msg, &cosigner_aggnonce) == 1);
        CHECK(secp256k1_iceberg_partial_sig_verify(CTX, &seven, &pubshares[6],
                                                   inside_nonces, MU, CLAIMED, T, &group_pk,
                                                   &keyagg_cache, msg, &cosigner_aggnonce) == 0);
    }

    /* And aggregation of the signature shares, the last place it could get in. */
    CHECK(secp256k1_iceberg_partial_sig_agg(CTX, &musig_psig, psig_ptrs, T, N, T) == 1);
    CHECK(secp256k1_iceberg_partial_sig_agg(CTX, &musig_psig, psig_ptrs, T, CLAIMED, T) == 0);

    /* An index can also be wrong by being repeated, which makes the
     * interpolation singular and is how a caller most easily passes fewer
     * distinct participants than it believes it has. Every call that walks a set
     * of indices has to catch it; only pubkey_agg was tested for it. */
    {
        const secp256k1_iceberg_pubnonce *repeated[MU];
        const secp256k1_iceberg_partial_sig *repeated_psigs[T];

        for (i = 0; i < MU; i++) {
            repeated[i] = quorum_nonces[i];
        }
        repeated[MU - 1] = repeated[0];
        CHECK(secp256k1_iceberg_nonce_agg(CTX, &group_pubnonce, NULL,
                                          repeated, MU, N, T, &group_pk) == 0);
        CHECK(secp256k1_iceberg_partial_sig_verify(CTX, &psigs[0], &pubshares[signers[0] - 1],
                                                   repeated, MU, N, T, &group_pk,
                                                   &keyagg_cache, msg, &cosigner_aggnonce) == 0);
        for (i = 0; i < T; i++) {
            repeated_psigs[i] = psig_ptrs[i];
        }
        repeated_psigs[T - 1] = repeated_psigs[0];
        CHECK(secp256k1_iceberg_partial_sig_agg(CTX, &musig_psig, repeated_psigs, T, N, T) == 0);
    }
}

/* Every contribution at infinity, which is the only way to reach nonce_agg's
 * last refusal. The degree check passes, because the zero polynomial has every
 * degree; the group's pair then comes out as the point at infinity, which a
 * MuSig2 public nonce has no encoding for.
 *
 * Which makes this the place to say what a refused call leaves behind. Nothing
 * that loads: the aggnonce keeps the zero tag from the memset at the top of the
 * call, so the serializer refuses it rather than handing back an aggregate the
 * caller never got a 1 for. */
static void run_iceberg_infinity_nonce_test(void) {
    enum { N = 5, T = 3, MU = 2 * T - 1 };
    secp256k1_iceberg_pubnonce nonces[MU];
    const secp256k1_iceberg_pubnonce *ptrs[MU];
    secp256k1_iceberg_aggnonce refused;
    secp256k1_musig_pubnonce group_pubnonce;
    secp256k1_pubkey group_pk;
    unsigned char in67[67], out66[66], seckey[32];
    size_t i;

    memset(seckey, 0x9d, sizeof(seckey));
    CHECK(secp256k1_ec_pubkey_create(CTX, &group_pk, seckey) == 1);

    /* An all-zero point is how the 33-byte encoding spells infinity, so these
     * parse rather than being refused one at a time. */
    memset(in67, 0, sizeof(in67));
    for (i = 0; i < MU; i++) {
        in67[0] = (unsigned char)(i + 1);
        CHECK(secp256k1_iceberg_pubnonce_parse(CTX, &nonces[i], in67) == 1);
        ptrs[i] = &nonces[i];
    }

    memset(&refused, 0xab, sizeof(refused));
    CHECK(secp256k1_iceberg_nonce_agg(CTX, &group_pubnonce, &refused,
                                      ptrs, MU, N, T, &group_pk) == 0);
    CHECK_ILLEGAL(CTX, secp256k1_iceberg_aggnonce_serialize(CTX, out66, &refused));
}

/* Every documented bound that nothing else here reaches, at the severity the
 * header documents for it. The distinction is the module's one departure from the
 * library's convention and it is load-bearing: a count that arrives from a peer
 * returns 0, and the group's own n and t abort, so a caller can tell "they sent
 * me a bad set" from "I have a bug" without a debugger.
 *
 * The upper bounds are covered by run_iceberg_null_entry_test, which needs them
 * to keep its own sweep unreachable. The lower bounds were covered nowhere, and
 * neither was the static context, which three calls document and musig's own
 * suite tests for its equivalents. */
static void run_iceberg_bounds_test(void) {
    enum { N = 5, T = 3, MU = 2 * T - 1 };
    secp256k1_iceberg_share shares[N];
    secp256k1_iceberg_share *share_ptrs[N];
    secp256k1_iceberg_pubshare pubshares[N], scratch_pubshare;
    const secp256k1_iceberg_pubshare *pubshare_ptrs[N + 1];
    secp256k1_iceberg_pubnonce pubnonces[N], scratch_pubnonce;
    const secp256k1_iceberg_pubnonce *pubnonce_ptrs[N + 1];
    secp256k1_iceberg_partial_sig psigs[T], scratch_psig;
    const secp256k1_iceberg_partial_sig *psig_ptrs[N + 1];
    secp256k1_musig_keyagg_cache keyagg_cache;
    secp256k1_musig_aggnonce cosigner_aggnonce;
    secp256k1_musig_pubnonce cosigner_pubnonce, musig_pubnonce;
    secp256k1_musig_secnonce cosigner_secnonce;
    secp256k1_musig_partial_sig musig_psig;
    secp256k1_keypair cosigner_keypair;
    secp256k1_xonly_pubkey agg_xonly;
    secp256k1_pubkey group_pk, scratch_pk, cosigner_pk;
    unsigned char seed[32], seckey[32], secrand[32], sid[32], msg[32];
    size_t i;

    if (!iceberg_test_fits(N)) {
        return;
    }
    memset(seed, 0x5e, sizeof(seed));
    memset(seckey, 0x2b, sizeof(seckey));
    memset(secrand, 0x6f, sizeof(secrand));
    memset(sid, 0x3d, sizeof(sid));
    memset(msg, 0x71, sizeof(msg));
    for (i = 0; i < N; i++) {
        share_ptrs[i] = &shares[i];
        pubshare_ptrs[i] = &pubshares[i];
        pubnonce_ptrs[i] = &pubnonces[i];
    }
    CHECK(secp256k1_iceberg_shares_gen(CTX, share_ptrs, N, T, seed) == 1);
    for (i = 0; i < N; i++) {
        CHECK(secp256k1_iceberg_pubshare_gen(CTX, &pubshares[i], &shares[i], NULL) == 1);
        CHECK(secp256k1_iceberg_nonce_gen(CTX, &pubnonces[i], &shares[i], NULL, sid) == 1);
    }
    CHECK(secp256k1_iceberg_pubkey_agg(CTX, &group_pk, pubshare_ptrs, MU, N, T) == 1);
    iceberg_test_cosigner_key(&cosigner_keypair, &cosigner_pk, &agg_xonly, &keyagg_cache,
                              &group_pk, seckey);
    iceberg_test_cosigner_nonce(&cosigner_secnonce, &cosigner_pubnonce, &cosigner_aggnonce,
                               secrand, seckey, &cosigner_pk, msg, &keyagg_cache);
    for (i = 0; i < T; i++) {
        CHECK(secp256k1_iceberg_partial_sign(CTX, &psigs[i], &shares[i], NULL, sid,
                                             pubnonce_ptrs, MU, &group_pk, &keyagg_cache,
                                             msg, &cosigner_aggnonce) == 1);
        psig_ptrs[i] = &psigs[i];
    }
    /* The entry past the group is null in each array, which is what makes the
     * count bound the reason for the refusal. A duplicate there would be caught
     * by the repeated-index check instead, and the bound could be deleted with
     * the suite still passing; a null one reaches the sweep and aborts. */
    pubshare_ptrs[N] = NULL;
    pubnonce_ptrs[N] = NULL;
    for (i = T; i < N + 1; i++) {
        psig_ptrs[i] = NULL;
    }

    /* How many contributions turned up is a fact about the group, so every call
     * that takes a count returns 0 rather than aborting: too few of them, and
     * more of them than the group holds, which is one contribution arriving
     * twice. */
    CHECK(secp256k1_iceberg_partial_sign(CTX, &scratch_psig, &shares[0], NULL, sid,
                                         pubnonce_ptrs, MU - 1, &group_pk, &keyagg_cache,
                                         msg, &cosigner_aggnonce) == 0);
    CHECK(secp256k1_iceberg_partial_sig_verify(CTX, &psigs[0], &pubshares[0], pubnonce_ptrs,
                                               MU - 1, N, T, &group_pk, &keyagg_cache, msg,
                                               &cosigner_aggnonce) == 0);
    CHECK(secp256k1_iceberg_nonce_agg(CTX, &musig_pubnonce, NULL,
                                      pubnonce_ptrs, MU - 1, N, T, &group_pk) == 0);
    CHECK(secp256k1_iceberg_nonce_agg(CTX, &musig_pubnonce, NULL,
                                      pubnonce_ptrs, N + 1, N, T, &group_pk) == 0);
    CHECK(secp256k1_iceberg_pubkey_agg(CTX, &scratch_pk, pubshare_ptrs, MU - 1, N, T) == 0);
    CHECK(secp256k1_iceberg_pubkey_agg(CTX, &scratch_pk, pubshare_ptrs, N + 1, N, T) == 0);
    CHECK(secp256k1_iceberg_partial_sig_agg(CTX, &musig_psig, psig_ptrs, T - 1, N, T) == 0);
    CHECK(secp256k1_iceberg_partial_sig_agg(CTX, &musig_psig, psig_ptrs, N + 1, N, T) == 0);

    /* A threshold above (n+1)/2, which no group can have: 2t-1 would not fit.
     * Every call that takes t checks it before the count, so each one can be
     * asked in isolation. */
    CHECK_ILLEGAL(CTX, secp256k1_iceberg_pubkey_agg(CTX, &scratch_pk, pubshare_ptrs,
                                                    MU, N, (N + 1) / 2 + 1));
    CHECK_ILLEGAL(CTX, secp256k1_iceberg_nonce_agg(CTX, &musig_pubnonce, NULL,
                                                   pubnonce_ptrs, MU, N,
                                                   (N + 1) / 2 + 1, &group_pk));
    CHECK_ILLEGAL(CTX, secp256k1_iceberg_partial_sig_agg(CTX, &musig_psig, psig_ptrs,
                                                         (N + 1) / 2 + 1, N,
                                                         (N + 1) / 2 + 1));
    CHECK_ILLEGAL(CTX, secp256k1_iceberg_shares_gen(CTX, share_ptrs, N, (N + 1) / 2 + 1, seed));

    /* The three calls whose Args line says "not secp256k1_context_static". Each
     * multiplies by the generator, which that context has no table for. */
    CHECK_ILLEGAL(STATIC_CTX, secp256k1_iceberg_pubshare_gen(STATIC_CTX, &scratch_pubshare,
                                                             &shares[0], NULL));
    CHECK_ILLEGAL(STATIC_CTX, secp256k1_iceberg_nonce_gen(STATIC_CTX, &scratch_pubnonce,
                                                          &shares[0], NULL, sid));
    CHECK_ILLEGAL(STATIC_CTX, secp256k1_iceberg_partial_sign(STATIC_CTX, &scratch_psig,
                                                             &shares[0], NULL, sid,
                                                             pubnonce_ptrs, MU, &group_pk,
                                                             &keyagg_cache, msg,
                                                             &cosigner_aggnonce));
}

/* A null entry in a caller-supplied array.
 *
 * Every function here takes its contributions as an array of pointers, and a
 * coordinator that assembles one from a map of who has answered can leave a
 * hole in it. The sweep for null entries is the only thing that can object, so
 * everything is built and left well formed before any entry is nulled: a
 * zeroed object would be caught earlier by a magic-byte check inside a load
 * helper instead. The failing calls write to scratch out-params because a call
 * that fails still zeroes its own output first. */
static void run_iceberg_null_entry_test(void) {
    enum { N = 5, T = 3, MU = 2 * T - 1 };
    secp256k1_iceberg_share shares[N];
    secp256k1_iceberg_share *share_ptrs[N];
    secp256k1_iceberg_pubshare pubshares[N];
    const secp256k1_iceberg_pubshare *pubshare_ptrs[N];
    secp256k1_iceberg_pubnonce pubnonces[N];
    const secp256k1_iceberg_pubnonce *pubnonce_ptrs[SECP256K1_ICEBERG_MAX_PARTICIPANTS];
    secp256k1_iceberg_partial_sig psigs[T], scratch_psig;
    const secp256k1_iceberg_partial_sig *psig_ptrs[T];
    secp256k1_musig_keyagg_cache keyagg_cache;
    secp256k1_musig_aggnonce cosigner_aggnonce;
    secp256k1_musig_pubnonce cosigner_pubnonce, musig_pubnonce;
    secp256k1_musig_secnonce cosigner_secnonce;
    secp256k1_musig_partial_sig musig_psig;
    secp256k1_keypair cosigner_keypair;
    secp256k1_xonly_pubkey agg_xonly;
    secp256k1_pubkey group_pk, scratch_pk, cosigner_pk;
    const secp256k1_pubkey *pubkeys[2];
    unsigned char seed[32], seckey[32], secrand[32], sid[32], msg[32];
    size_t i;

    if (!iceberg_test_fits(N)) {
        return;
    }
    memset(seed, 0x7c, sizeof(seed));
    memset(seckey, 0x31, sizeof(seckey));
    memset(secrand, 0x77, sizeof(secrand));
    memset(sid, 0x11, sizeof(sid));
    memset(msg, 0x22, sizeof(msg));
    for (i = 0; i < N; i++) {
        share_ptrs[i] = &shares[i];
        pubshare_ptrs[i] = &pubshares[i];
        pubnonce_ptrs[i] = &pubnonces[i];
    }
    /* Past the group, left null on purpose: a count that reaches them is a
     * count that should have been refused before the sweep ran. */
    for (i = N; i < SECP256K1_ICEBERG_MAX_PARTICIPANTS; i++) {
        pubnonce_ptrs[i] = NULL;
    }
    for (i = 0; i < T; i++) {
        psig_ptrs[i] = &psigs[i];
    }

    /* The dealer sweeps before it writes, so the real deal below is unaffected. */
    share_ptrs[2] = NULL;
    CHECK_ILLEGAL(CTX, secp256k1_iceberg_shares_gen(CTX, share_ptrs, N, T, seed));
    share_ptrs[2] = &shares[2];

    CHECK(secp256k1_iceberg_shares_gen(CTX, share_ptrs, N, T, seed) == 1);
    for (i = 0; i < N; i++) {
        CHECK(secp256k1_iceberg_pubshare_gen(CTX, &pubshares[i], &shares[i], NULL) == 1);
    }
    CHECK(secp256k1_iceberg_pubkey_agg(CTX, &group_pk, pubshare_ptrs, MU, N, T) == 1);

    iceberg_test_cosigner_key(&cosigner_keypair, &cosigner_pk, &agg_xonly, &keyagg_cache,
                              &group_pk, seckey);
    iceberg_test_cosigner_nonce(&cosigner_secnonce, &cosigner_pubnonce, &cosigner_aggnonce,
                               secrand, seckey, &cosigner_pk, msg, &keyagg_cache);
    for (i = 0; i < N; i++) {
        CHECK(secp256k1_iceberg_nonce_gen(CTX, &pubnonces[i], &shares[i], NULL, sid) == 1);
    }
    for (i = 0; i < T; i++) {
        /* nonce_agg belongs in this sweep too: its count bound is what keeps the
         * loop below inside an array the caller sized from n. */
        CHECK(secp256k1_iceberg_nonce_agg(CTX, &musig_pubnonce, NULL, pubnonce_ptrs,
                                          N + 1, N, T, &group_pk) == 0);
        CHECK(secp256k1_iceberg_partial_sign(CTX, &psigs[i], &shares[i], NULL, sid,
                                             pubnonce_ptrs, MU, &group_pk, &keyagg_cache,
                                             msg, &cosigner_aggnonce) == 1);
    }

    pubshare_ptrs[2] = NULL;
    CHECK_ILLEGAL(CTX, secp256k1_iceberg_pubkey_agg(CTX, &scratch_pk, pubshare_ptrs, MU, N, T));
    pubshare_ptrs[2] = &pubshares[2];

    /* keyagg_check walks a list too, and its own is the cosigners' rather than
     * the group's, so it needs its own turn. */
    pubkeys[1] = NULL;
    CHECK_ILLEGAL(CTX, secp256k1_iceberg_keyagg_check(CTX, &keyagg_cache, pubkeys, 2, &group_pk));
    pubkeys[1] = &cosigner_pk;

    pubnonce_ptrs[2] = NULL;
    CHECK_ILLEGAL(CTX, secp256k1_iceberg_nonce_agg(CTX, &musig_pubnonce, NULL,
                                                   pubnonce_ptrs, MU, N, T, &group_pk));
    CHECK_ILLEGAL(CTX, secp256k1_iceberg_partial_sign(CTX, &scratch_psig, &shares[0], NULL,
                                                      sid, pubnonce_ptrs, MU, &group_pk,
                                                      &keyagg_cache, msg, &cosigner_aggnonce));
    CHECK_ILLEGAL(CTX, secp256k1_iceberg_partial_sig_verify(CTX, &psigs[0], &pubshares[0],
                                                            pubnonce_ptrs, MU, N, T, &group_pk,
                                                            &keyagg_cache, msg, &cosigner_aggnonce));
    pubnonce_ptrs[2] = &pubnonces[2];

    psig_ptrs[1] = NULL;
    CHECK_ILLEGAL(CTX, secp256k1_iceberg_partial_sig_agg(CTX, &musig_psig, psig_ptrs, T, N, T));
    psig_ptrs[1] = &psigs[1];

    /* A count larger than the group is peer-influenced rather than a caller
     * bug, so these return 0 instead. The distinction is what stops the sweep
     * above from being reachable with a count it cannot walk.
     *
     * The first pair passes a count just past the group, with the entries past
     * it null: that is the case the header's promise is about, and the one the
     * sweep would otherwise reach first. The second pair passes a count past the
     * compile-time bound too, which the same `> n` refuses: there is no
     * separate check against MAX_PARTICIPANTS here, because n comes off the
     * caller's own share and cannot exceed it. Both pairs are the one mechanism,
     * approached from two distances. */
    CHECK(secp256k1_iceberg_partial_sign(CTX, &scratch_psig, &shares[0], NULL, sid,
                                         pubnonce_ptrs, N + 1, &group_pk, &keyagg_cache,
                                         msg, &cosigner_aggnonce) == 0);
    CHECK(secp256k1_iceberg_partial_sig_verify(CTX, &psigs[0], &pubshares[0], pubnonce_ptrs,
                                               N + 1, N, T, &group_pk, &keyagg_cache, msg,
                                               &cosigner_aggnonce) == 0);
    CHECK(secp256k1_iceberg_partial_sign(CTX, &scratch_psig, &shares[0], NULL, sid,
                                         pubnonce_ptrs, SECP256K1_ICEBERG_MAX_PARTICIPANTS + 1,
                                         &group_pk, &keyagg_cache, msg, &cosigner_aggnonce) == 0);
    CHECK(secp256k1_iceberg_partial_sig_verify(CTX, &psigs[0], &pubshares[0], pubnonce_ptrs,
                                               SECP256K1_ICEBERG_MAX_PARTICIPANTS + 1, N, T,
                                               &group_pk, &keyagg_cache, msg,
                                               &cosigner_aggnonce) == 0);
}

static const struct tf_test_entry tests_iceberg[] = {
    CASE1(run_iceberg_from_roots_test),
    CASE1(run_iceberg_div_root_test),
    CASE1(run_iceberg_lagrange_eval_test),
    CASE1(run_iceberg_lagrange_basis_test),
    CASE1(run_iceberg_interpolate_test),
    CASE1(run_iceberg_batch_inverse_test),
    CASE1(run_iceberg_binom_test),
    CASE1(run_iceberg_subset_rank_test),
    CASE1(run_iceberg_prf_test),
    CASE1(run_iceberg_midstate_test),
    CASE1(run_iceberg_keyagg_check_test),
    CASE1(run_iceberg_pss_test),
    CASE1(run_iceberg_vpss_test),
    CASE1(run_iceberg_vpss_quorum_test),
    CASE1(run_iceberg_keygen_test),
    CASE1(run_iceberg_keygen_api_test),
    CASE1(run_iceberg_dealer_kat_test),
    CASE1(run_iceberg_foreign_index_test),
    CASE1(run_iceberg_infinity_nonce_test),
    CASE1(run_iceberg_bounds_test),
    CASE1(run_iceberg_null_entry_test),
    CASE1(run_iceberg_wire_test),
    CASE1(run_iceberg_vectors_test),
    CASE1(run_iceberg_keygen_cheat_test),
    CASE1(run_iceberg_e2e_test),
    CASE1(run_iceberg_c1_property_test),
    CASE1(run_iceberg_parser_fuzz_test),
    CASE1(run_iceberg_tweak_test),
};

#endif /* SECP256K1_MODULE_ICEBERG_TESTS_IMPL_H */
