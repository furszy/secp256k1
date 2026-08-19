/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ICEBERG_VPSS_H
#define SECP256K1_MODULE_ICEBERG_VPSS_H

#include "../../../include/secp256k1.h"
#include "../../group.h"
#include "../../scalar.h"

/* Verifiable pseudorandom secret sharing: the part that runs in the group.
 *
 * No secret enters this file. Everything here operates on published commitments
 * and public participant indices, so there is nothing to leak and every routine
 * is free to be variable time.
 *
 * Two operations, both consequences of the fact that Lagrange interpolation
 * uses nothing but addition and multiplication by known scalars, and therefore
 * survives being carried into the group:
 *
 *   verify  - honest shares are evaluations of one degree t-1 polynomial, so
 *             interpolating the published commitments must yield zero for every
 *             coefficient above x^(t-1). A participant who publishes anything
 *             else raises the degree and is caught.
 *
 *   combine - the same interpolation, evaluated at zero, gives the commitment
 *             to the shared secret. Any valid quorum produces the same point. */

/* 1 if the m commitments are consistent with a polynomial of degree at most
 * t-1, 0 otherwise, with two edges the mathematics does not have. Below t this
 * returns 0, although a set that small always lies on such a polynomial: there
 * is nothing to test, and a degree check is the wrong place to fail open. At
 * exactly t it returns 1 without testing anything, because t points fix the
 * polynomial and leave no high coefficient over. Only m > t proves something.
 *
 * idx holds m distinct participant indices and points their commitments, which
 * may include the point at infinity. Soundness needs m >= 2t-1, so that at least
 * t of the points are honest and pin the true polynomial. Enforcing it is the
 * caller's job; this routine checks the degree and nothing else.
 *
 * On the paths that reach the transcript the points are normalized in place,
 * following the convention of the serialization helpers this shares with the
 * musig module; the two early returns above leave them alone. */
static int secp256k1_vpss_verify_var(const secp256k1_context *ctx, const unsigned char *idx, secp256k1_ge *points, size_t m, unsigned int t);

/* The interpolated commitment polynomial, evaluated at `at`.
 *
 * At zero this is the group's aggregate, which is what aggregation wants. At a
 * participant's own index it is what that participant's contribution must have
 * been, which is how a signer checks that a set of contributions it was handed
 * belongs to the session it thinks it is in, without having to be one of the
 * contributors, since it may have been offline when they were produced. */
static int secp256k1_vpss_eval_at_var(const secp256k1_context *ctx, secp256k1_gej *r, const unsigned char *idx, const secp256k1_ge *points, size_t m, unsigned int at);

/* r <- sum_j lambda_j * points[j], the same interpolation evaluated at zero:
 * the commitment to the shared secret.
 *
 * Returns 1. The int is the return of secp256k1_ecmult_multi_var underneath,
 * which with the current implementation can only fail on a callback that fails,
 * and the callback here cannot. Callers check it anyway, as the musig module
 * does at the same call for the same reason: the day somebody hands that
 * multiexponentiation a scratch space, it can fail. */
static int secp256k1_vpss_combine_var(const secp256k1_context *ctx, secp256k1_gej *r, const unsigned char *idx, const secp256k1_ge *points, size_t m);

#endif /* SECP256K1_MODULE_ICEBERG_VPSS_H */
