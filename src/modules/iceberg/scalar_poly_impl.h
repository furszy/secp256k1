/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ICEBERG_SCALAR_POLY_IMPL_H
#define SECP256K1_MODULE_ICEBERG_SCALAR_POLY_IMPL_H

#include "scalar_poly.h"

#include "../../scalar.h"
#include "../../util.h"

/* Participant indices are small positive integers, but differences between them
 * are signed. Accumulating those differences in the scalar field instead of in
 * a C integer keeps us out of overflow-analysis territory entirely: with indices
 * up to 255 and sixteen points, an integer product would reach 2^120. */
static void secp256k1_scalarpoly_small_diff(secp256k1_scalar *r, unsigned int a, unsigned int b) {
    if (a >= b) {
        secp256k1_scalar_set_int(r, a - b);
    } else {
        secp256k1_scalar_set_int(r, b - a);
        secp256k1_scalar_negate(r, r);
    }
}

static void secp256k1_scalarpoly_from_roots_var(secp256k1_scalar *coeffs, const unsigned char *roots, size_t m) {
    secp256k1_scalar neg_root, term;
    size_t i, j;

    VERIFY_CHECK(m <= SECP256K1_SCALARPOLY_MAX_POINTS);

    /* Start from the constant polynomial 1 and multiply in one root at a time.
     * Multiplying by (x - r) shifts every coefficient up and subtracts r times
     * the original, so we walk downwards to avoid clobbering what we still need. */
    secp256k1_scalar_set_int(&coeffs[0], 1);
    for (i = 0; i < m; i++) {
        secp256k1_scalarpoly_small_diff(&neg_root, 0, roots[i]);
        coeffs[i + 1] = coeffs[i];
        for (j = i; j > 0; j--) {
            secp256k1_scalar_mul(&term, &coeffs[j], &neg_root);
            secp256k1_scalar_add(&coeffs[j], &coeffs[j - 1], &term);
        }
        secp256k1_scalar_mul(&coeffs[0], &coeffs[0], &neg_root);
    }
}

static void secp256k1_scalarpoly_div_root_var(secp256k1_scalar *q, const secp256k1_scalar *a, size_t m, unsigned char root) {
    secp256k1_scalar r, term;
    size_t i;

    VERIFY_CHECK(m >= 1 && m <= SECP256K1_SCALARPOLY_MAX_POINTS);
    secp256k1_scalar_set_int(&r, root);

    /* Synthetic division: q[i-1] = a[i] + root*q[i], seeded with the leading
     * coefficient. What is left over is a(root), so the division is exact
     * precisely when root is a root of a; whether a is monic plays no part. */
    q[m - 1] = a[m];
    for (i = m - 1; i > 0; i--) {
        secp256k1_scalar_mul(&term, &q[i], &r);
        secp256k1_scalar_add(&q[i - 1], &a[i], &term);
    }

#ifdef VERIFY
    /* The remainder must vanish. If it does not, the caller passed a value that
     * is not a root of a, which no correct call site can do. */
    secp256k1_scalar_mul(&term, &q[0], &r);
    secp256k1_scalar_add(&term, &term, &a[0]);
    VERIFY_CHECK(secp256k1_scalar_is_zero(&term));
#endif
}

static void secp256k1_scalarpoly_lagrange_parts_var(secp256k1_scalar *num, secp256k1_scalar *den, const unsigned char *idx, size_t m, unsigned int exclude, unsigned int at) {
    secp256k1_scalar factor;
    size_t i;

    secp256k1_scalar_set_int(num, 1);
    secp256k1_scalar_set_int(den, 1);
    for (i = 0; i < m; i++) {
        if (idx[i] == exclude) {
            continue;
        }
        secp256k1_scalarpoly_small_diff(&factor, idx[i], at);
        secp256k1_scalar_mul(num, num, &factor);
        secp256k1_scalarpoly_small_diff(&factor, idx[i], exclude);
        secp256k1_scalar_mul(den, den, &factor);
    }
}

static void secp256k1_scalarpoly_lagrange_eval_var(secp256k1_scalar *r, const unsigned char *idx, size_t m, unsigned int exclude, unsigned int at) {
    secp256k1_scalar numerator, denominator;

    secp256k1_scalarpoly_lagrange_parts_var(&numerator, &denominator, idx, m, exclude, at);

    /* Distinct indices make every factor non-zero.
     * secp256k1_scalar_inverse_var maps zero to zero instead of failing, so a
     * duplicate index would otherwise produce a silently wrong weight. */
    VERIFY_CHECK(!secp256k1_scalar_is_zero(&denominator));
    secp256k1_scalar_inverse_var(&denominator, &denominator);
    secp256k1_scalar_mul(r, &numerator, &denominator);
}

static int secp256k1_scalarpoly_on_degree_var(const unsigned char *idx, const secp256k1_scalar *vals, size_t m, size_t t) {
    size_t j, k;

    VERIFY_CHECK(t >= 1 && m >= t);

    for (k = t; k < m; k++) {
        secp256k1_scalar expected, weight, term;

        secp256k1_scalar_set_int(&expected, 0);
        for (j = 0; j < t; j++) {
            /* The weight of node j in the interpolant of the first t points,
             * evaluated at the point being tested. idx[k] is not one of those
             * nodes, since the caller has already refused a repeated index. */
            secp256k1_scalarpoly_lagrange_eval_var(&weight, idx, t, idx[j], idx[k]);
            secp256k1_scalar_mul(&term, &weight, &vals[j]);
            secp256k1_scalar_add(&expected, &expected, &term);
        }
        if (!secp256k1_scalar_eq(&expected, &vals[k])) {
            return 0;
        }
    }
    return 1;
}

static void secp256k1_scalarpoly_lagrange_basis_var(secp256k1_scalar *basis, const unsigned char *idx, size_t m) {
    secp256k1_scalar master[SECP256K1_SCALARPOLY_MAX_POINTS + 1];
    secp256k1_scalar denominators[SECP256K1_SCALARPOLY_MAX_POINTS];
    secp256k1_scalar factor;
    size_t j, i;

    VERIFY_CHECK(m >= 1 && m <= SECP256K1_SCALARPOLY_MAX_POINTS);

    /* Fill the tail as well as the m entries set in the loop below. Only the
     * first m are ever read, but inverse_batch_var accepts a len up to
     * SECP256K1_SCALARPOLY_MAX_BATCH and GCC cannot see that m is bounded by
     * the smaller SECP256K1_SCALARPOLY_MAX_POINTS, so it warns on the
     * partially filled array. */
    for (j = 0; j < SECP256K1_SCALARPOLY_MAX_POINTS; j++) {
        secp256k1_scalar_set_int(&denominators[j], 1);
    }

    /* Every basis polynomial is the master polynomial with one root removed, so
     * build the master once and divide it down m times, instead of forming m
     * products from scratch. */
    secp256k1_scalarpoly_from_roots_var(master, idx, m);
    for (j = 0; j < m; j++) {
        secp256k1_scalarpoly_div_root_var(&basis[j * m], master, m, idx[j]);
        secp256k1_scalar_set_int(&denominators[j], 1);
        for (i = 0; i < m; i++) {
            if (i == j) {
                continue;
            }
            secp256k1_scalarpoly_small_diff(&factor, idx[j], idx[i]);
            secp256k1_scalar_mul(&denominators[j], &denominators[j], &factor);
        }
    }

    secp256k1_scalarpoly_inverse_batch_var(denominators, denominators, m);
    for (j = 0; j < m; j++) {
        for (i = 0; i < m; i++) {
            secp256k1_scalar_mul(&basis[j * m + i], &basis[j * m + i], &denominators[j]);
        }
    }
}

static void secp256k1_scalarpoly_interpolate_at0(secp256k1_scalar *r, const unsigned char *idx, const secp256k1_scalar *vals, size_t m) {
    secp256k1_scalar numerators[SECP256K1_SCALARPOLY_MAX_POINTS];
    secp256k1_scalar denominators[SECP256K1_SCALARPOLY_MAX_POINTS];
    secp256k1_scalar term;
    size_t j;

    VERIFY_CHECK(m >= 1 && m <= SECP256K1_SCALARPOLY_MAX_POINTS);

    /* Fill the tail as well: only the first m entries are read, but GCC cannot
     * see that and warns on the partially filled array. */
    for (j = 0; j < SECP256K1_SCALARPOLY_MAX_POINTS; j++) {
        secp256k1_scalar_set_int(&denominators[j], 1);
    }

    /* One inversion for the whole quorum rather than one per weight. */
    for (j = 0; j < m; j++) {
        secp256k1_scalarpoly_lagrange_parts_var(&numerators[j], &denominators[j],
                                                idx, m, idx[j], 0);
    }
    secp256k1_scalarpoly_inverse_batch_var(denominators, denominators, m);

    secp256k1_scalar_set_int(r, 0);
    for (j = 0; j < m; j++) {
        secp256k1_scalar_mul(&term, &numerators[j], &denominators[j]);
        secp256k1_scalar_mul(&term, &term, &vals[j]);
        secp256k1_scalar_add(r, r, &term);
    }
    secp256k1_scalar_clear(&term);
}

static void secp256k1_scalarpoly_inverse_batch_var(secp256k1_scalar *r, const secp256k1_scalar *a, size_t len) {
    secp256k1_scalar prefix[SECP256K1_SCALARPOLY_MAX_BATCH];
    secp256k1_scalar running;
    size_t i;

    VERIFY_CHECK(len >= 1 && len <= SECP256K1_SCALARPOLY_MAX_BATCH);

    /* Montgomery's trick: invert the product of everything once, then peel the
     * individual inverses off using the running prefix products. */
    prefix[0] = a[0];
    for (i = 1; i < len; i++) {
        secp256k1_scalar_mul(&prefix[i], &prefix[i - 1], &a[i]);
    }
    VERIFY_CHECK(!secp256k1_scalar_is_zero(&prefix[len - 1]));
    secp256k1_scalar_inverse_var(&running, &prefix[len - 1]);

    for (i = len - 1; i > 0; i--) {
        secp256k1_scalar this_inverse;
        secp256k1_scalar_mul(&this_inverse, &running, &prefix[i - 1]);
        secp256k1_scalar_mul(&running, &running, &a[i]);
        r[i] = this_inverse;
    }
    r[0] = running;
}

#endif /* SECP256K1_MODULE_ICEBERG_SCALAR_POLY_IMPL_H */
