/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ICEBERG_SCALAR_POLY_H
#define SECP256K1_MODULE_ICEBERG_SCALAR_POLY_H

#include "../../scalar.h"

/* Polynomials over the scalar field, represented as dense coefficient arrays
 * with coeff[i] the coefficient of x^i.
 *
 * This layer knows nothing about elliptic curves, hashing, or threshold
 * signing. It is a separate file so the Lagrange machinery can be audited
 * against the paper on its own.
 *
 * Everything is variable time in the indices, which are participant numbers and
 * therefore public. Coefficient values are touched with constant-time scalar
 * operations, with one exception: every routine that inverts ends at
 * secp256k1_scalar_inverse_var and is variable time in the value it inverts.
 * That is lagrange_eval_var directly, and lagrange_basis_var and interpolate_at0
 * through inverse_batch_var. What they invert is always a Lagrange denominator,
 * built from indices alone. A secret may pass through interpolate_at0's vals and
 * through the multiply-and-add routines; a secret must never reach an
 * inversion. */

/* An interpolation may involve at most this many points. Participant counts are
 * bounded far below this by the C(n, t-1) share blowup; the slack costs only
 * stack space in the basis computation. */
#define SECP256K1_SCALARPOLY_MAX_POINTS 16

/* A batch inversion may involve at most this many scalars. It is not the point
 * bound: the largest batch is one weight per seed a participant holds, which is
 * C(n-1, t-1) and an order of magnitude larger. The consumer checks its own
 * bound against this one at compile time. */
#define SECP256K1_SCALARPOLY_MAX_BATCH 128

/* coeffs[0..m] <- prod_i (x - roots[i]), monic, so coeffs[m] is one.
 * roots must be distinct and hold m entries; coeffs must hold m+1. */
static void secp256k1_scalarpoly_from_roots_var(secp256k1_scalar *coeffs, const unsigned char *roots, size_t m);

/* q[0..m-1] <- a(x) / (x - root), for monic a of degree m with a(root) == 0.
 * The remainder is checked under VERIFY; a caller passing a root that is not a
 * root has a bug, not a runtime error. */
static void secp256k1_scalarpoly_div_root_var(secp256k1_scalar *q, const secp256k1_scalar *a, size_t m, unsigned char root);

/* r <- prod_{i in idx, i != exclude} (i - at) / (i - exclude).
 *
 * One function covers both places Lagrange weights appear:
 *
 *   exclude = 0, at = k   gives L_a(k), the replicated-sharing weight that
 *                         vanishes on every member of the set a
 *   exclude = j, at = 0   gives lambda_j, the weight that reconstructs f(0)
 *
 * They look unrelated in the papers and are the same product.
 *
 * The one-weight form. Anything computing many weights at once goes
 * through lagrange_parts_var below instead and inverts them in a batch, so the
 * one caller of this is on_degree_var, which needs a handful. */
static void secp256k1_scalarpoly_lagrange_eval_var(secp256k1_scalar *r, const unsigned char *idx, size_t m, unsigned int exclude, unsigned int at);

/* The same weight, left as a fraction: num/den, with no inversion performed.
 * Inverting dominates the cost of a weight, so a caller computing many at once
 * should collect the denominators and invert the batch. */
static void secp256k1_scalarpoly_lagrange_parts_var(secp256k1_scalar *num, secp256k1_scalar *den, const unsigned char *idx, size_t m, unsigned int exclude, unsigned int at);

/* basis[j*m + i] <- coefficient of x^i in the jth Lagrange basis polynomial for
 * the node set idx. Needed only by the degree check, which inspects the high
 * coefficients; the point evaluations above are cheaper for everything else. */
static void secp256k1_scalarpoly_lagrange_basis_var(secp256k1_scalar *basis, const unsigned char *idx, size_t m);

/* r <- sum_j lambda_j * vals[j], the interpolation of the given points at zero.
 * idx is public and drives variable-time work; vals may be secret. */
static void secp256k1_scalarpoly_interpolate_at0(secp256k1_scalar *r, const unsigned char *idx, const secp256k1_scalar *vals, size_t m);

/* Do the m points (idx[i], vals[i]) lie on one polynomial of degree at most
 * t-1? The first t of them fix that polynomial, so the question is only whether
 * the other m-t agree with it, and at m == t there is nothing to ask.
 *
 * Both idx and vals must be public: this is variable time in the values, and it
 * exists to check contributions that have already been published. */
static int secp256k1_scalarpoly_on_degree_var(const unsigned char *idx, const secp256k1_scalar *vals, size_t m, size_t t);

/* r[0..len-1] <- a[i]^-1, using one field inversion for the whole batch.
 * All inputs must be non-zero. r and a may alias. */
static void secp256k1_scalarpoly_inverse_batch_var(secp256k1_scalar *r, const secp256k1_scalar *a, size_t len);

#endif /* SECP256K1_MODULE_ICEBERG_SCALAR_POLY_H */
