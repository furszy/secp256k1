/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ICEBERG_RSS_H
#define SECP256K1_MODULE_ICEBERG_RSS_H

#include <stdint.h>

#include "../../hash.h"
#include "../../scalar.h"
#include "../../../include/secp256k1_iceberg.h"
#include "scalar_poly.h"

/* Replicated secret sharing, and the pseudorandom sharing built on top of it.
 *
 * The setup gives every (t-1)-subset of participants its own random seed, held
 * by everyone outside that subset. A coalition of t-1 participants therefore
 * holds every seed but one, the one named after the coalition itself, and
 * that single unknown scalar is the scheme's entire security margin.
 *
 * From those seeds, any label w yields a fresh Shamir sharing with no
 * communication at all:
 *
 *     f_w(x) = sum over subsets a of  H(phi_a, w) * L_a(x)
 *
 * L_a is one at zero and zero on every member of a, so f_w(0) is just the sum
 * of the hashes, and participant k can evaluate f_w(k) alone: the terms it
 * lacks the seeds for are exactly the terms L_a(k) sends to zero. That is what
 * makes deterministic, stateless nonces possible.
 *
 * Of the three lower layers this is the only one that handles a secret:
 * scalar_poly only has values passed through it and vpss sees none at all.
 * Above it, keygen deals the seeds and session derives nonces from them, so the
 * clearing discipline is theirs too. Seeds and the values derived from them are
 * secret; participant indices, subset structure and every Lagrange weight are
 * public, so work driven by those may be variable time. */

/* Derived bounds at ten participants. A quorum of 2t-1 cannot exceed the group,
 * so t is at most (n+1)/2, which is 5; and the number of size-(t-1) subsets is
 * largest at that maximum t, which is C(10, 4). C89 cannot evaluate a binomial
 * at preprocessing time, so both are written out; the tests recompute them with
 * secp256k1_rss_binom. */
#define SECP256K1_ICEBERG_MAX_T 5
#define SECP256K1_ICEBERG_MAX_SUBSETS 210

/* These three constants are the participant bound worked out by hand, so the
 * compiler cannot see that they belong together. Raising the bound without
 * recomputing them sizes the opaque types for one group and deals another, which
 * overruns a share at run time instead of failing to build, so raising it is
 * refused below. Lowering it is allowed: the suite checks all three against
 * every configuration the new bound can express (tests_impl.h,
 * run_iceberg_binom_test) and says which one is wrong. Drawing that distinction
 * at preprocessing time is not possible, since C89 cannot evaluate a binomial. */
#if SECP256K1_ICEBERG_MAX_PARTICIPANTS > 10
#error "MAX_T and MAX_SUBSETS here, and MAX_SEEDS in secp256k1_iceberg.h, are written out for ten participants. Recompute all three before raising the bound."
#endif

/* Lowering the bound is worth doing for a build that will only ever run small
 * groups: at five participants a share is 200 bytes rather than 4040. Lower
 * SECP256K1_ICEBERG_MAX_SEEDS to C(n-1, (n+1)/2 - 1) along with it, and MAX_T
 * and MAX_SUBSETS above to match.
 *
 * Ten reaches every configuration the scheme can express up to 4-of-10, which is
 * also the largest that clears the n >= 3t-2 bound a deployment needs.
 *
 * The same growth sizes the module's stack frames, which at ten participants
 * come to nearly twice the largest frame anywhere in the musig module. The
 * figures move with the compiler, so measure rather than assume:
 *
 *   gcc -fstack-usage -O2 -c src/secp256k1.c -I. -Isrc -Iinclude $(module defines)
 *   sort -t$'\t' -k2 -rn secp256k1.su | head
 *
 * TODO: sizing every share for the compile-time maximum is what makes the bound
 * an ABI decision. A secp256k1_iceberg_share_size(n, t) with caller-provided
 * storage, the shape secp256k1_preallocated.h already uses, would let a group
 * pay for the configuration it runs and would end that. */

/* The number of summands in a participant's evaluation is the number of seeds
 * it holds. */
#define SECP256K1_ICEBERG_MAX_SUMMANDS SECP256K1_ICEBERG_MAX_SEEDS

/* The weights for a whole share are inverted in one batch, so the batch bound
 * has to cover a participant's seed count. */
#if SECP256K1_ICEBERG_MAX_SUMMANDS > SECP256K1_SCALARPOLY_MAX_BATCH
#error "SECP256K1_SCALARPOLY_MAX_BATCH is too small for the per-participant seed count"
#endif

/* A quorum interpolates through one point per member, so the point bound has to
 * cover the group. */
#if SECP256K1_ICEBERG_MAX_PARTICIPANTS > SECP256K1_SCALARPOLY_MAX_POINTS
#error "SECP256K1_SCALARPOLY_MAX_POINTS is too small for the participant bound"
#endif

/* A subset of participants as a bitmask, with bit j set when participant j
 * belongs. Participants are numbered from one, so bit zero is always clear. */
typedef uint16_t secp256k1_rss_subset;

/* Binomial coefficient, for arguments within the compile-time bound. */
static uint32_t secp256k1_rss_binom(unsigned int n, unsigned int size);

/* Position of a subset in lexicographic order over all size-`size` subsets of
 * {1..n}, and its inverse. At n = 5, size = 2 the order is
 *
 *     {1,2} {1,3} {1,4} {1,5} {2,3} {2,4} {2,5} {3,4} {3,5} {4,5}
 *       0     1     2     3     4     5     6     7     8     9
 *
 * so {2,3} ranks 4. Neither function enumerates that list: ranking sums the
 * binomials counting the subsets that come before, and unranking walks the same
 * sum backwards.
 *
 * The ordering fixes the layout of a serialized share and which Lagrange weight
 * pairs with which seed, so it is consensus-critical between implementations.
 * The example above is written out because the reference's own docstring gives
 * one that is off by one. `rank` here is a position in a list, unrelated to the
 * rank of a matrix, which is the other thing the word means around this scheme. */
static uint32_t secp256k1_rss_subset_rank(unsigned int n, unsigned int size, secp256k1_rss_subset subset);
static secp256k1_rss_subset secp256k1_rss_subset_unrank(unsigned int n, unsigned int size, uint32_t rank);

/* r <- H(seed32 || w) as a scalar, using the "VPSS/prf" tag. Secret in, secret
 * out. The reduction into the scalar field is unconditional, matching the
 * reference implementation. */
static void secp256k1_rss_prf(const secp256k1_hash_ctx *hash_ctx, secp256k1_scalar *r, const unsigned char *seed32, const unsigned char *w, size_t wlen);

/* weights[i] <- L_a(k) for the i'th subset a that participant k is outside of,
 * in ascending rank order: the scalar its seed for a gets multiplied by, using
 * the L_a defined at the top of this file. Public data throughout, so this is
 * variable time and its result can be cached. Writes C(n-1, t-1) entries and
 * returns that count. */
static size_t secp256k1_rss_lagrange_weights_var(secp256k1_scalar *weights, unsigned int n, unsigned int t, unsigned int k);

/* r <- f_w(k), the participant's share of the sharing labeled w.
 *
 * `seeds` is num 32-byte seeds and `weights` the matching output of
 * secp256k1_rss_lagrange_weights_var, in the same order. Constant time in the
 * seed values; the loop bound and access pattern depend only on public
 * structure. */
static void secp256k1_rss_eval(const secp256k1_hash_ctx *hash_ctx, secp256k1_scalar *r, const unsigned char *seeds, const secp256k1_scalar *weights, size_t num, const unsigned char *w, size_t wlen);

#endif /* SECP256K1_MODULE_ICEBERG_RSS_H */
