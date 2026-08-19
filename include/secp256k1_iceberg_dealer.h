#ifndef SECP256K1_ICEBERG_DEALER_H
#define SECP256K1_ICEBERG_DEALER_H

#include "secp256k1_iceberg.h"

#ifdef __cplusplus
extern "C" {
#endif

/** A trusted dealer for Iceberg shares.
 *
 *  This header is deliberately separate from secp256k1_iceberg.h and is not
 *  installed. Including the module's own header does not offer you a dealer,
 *  because for the duration of the call below one machine holds everything
 *  needed to reconstruct the group's private key, which is the situation a
 *  threshold scheme exists to avoid.
 *
 *  It is here so that the tests, the benchmarks and the example have shares to
 *  work with. It is also usable where one party is already trusted with the
 *  whole key, which is a real if narrow case. Anything else wants a distributed
 *  key generation: the same shares, assembled without the key ever existing in
 *  one place. This module does not provide one.
 *
 *  Nothing in the signing API depends on how a share was produced. A share
 *  arrives through secp256k1_iceberg_share_parse, so an externally generated
 *  one, from a DKG or from another implementation, is used exactly the same
 *  way.
 */

/** Deal a group's shares from a single seed.
 *
 *  The seed is the group's private key in all but name until this returns.
 *  Erase it afterwards, and do not derive it from anything reproducible.
 *
 *  Returns: 1 on success.
 *  Args:     ctx: pointer to a context object
 *  Out:   shares: array of n pointers to share objects, participant k at k-1
 *  In:         n: number of participants, 1 to
 *                 SECP256K1_ICEBERG_MAX_PARTICIPANTS
 *              t: threshold, at least 1 and at most (n+1)/2, since a quorum of
 *                 2t-1 has to fit in the group. So 2-of-2 and 3-of-4 are
 *                 inexpressible
 *         seed32: 32 bytes of uniformly random data
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_iceberg_shares_gen(
    const secp256k1_context *ctx,
    secp256k1_iceberg_share * const *shares,
    unsigned int n,
    unsigned int t,
    const unsigned char *seed32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(5);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_ICEBERG_DEALER_H */
