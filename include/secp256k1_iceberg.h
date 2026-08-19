#ifndef SECP256K1_ICEBERG_H
#define SECP256K1_ICEBERG_H

#include "secp256k1_musig.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/** This module implements Iceberg, a threshold scheme that lets a group of
 *  parties stand in for a single MuSig2 (BIP 327) participant.
 *
 *  WARNING: EXPERIMENTAL. Neither the scheme nor this implementation has been
 *  reviewed by anyone outside the project, and should not be used to protect
 *  anything of value.
 *
 *  The group produces one ordinary MuSig2 public nonce and one ordinary MuSig2
 *  partial signature, so cosigners cannot tell a group is involved and need no
 *  changes.
 *
 *  The order of calls, once per group and then once per signature:
 *
 *      setup      a distributed key generation produces one share each, then
 *                 pubshare_gen and pubkey_agg give the group's public key,
 *                 which goes into musig_pubkey_agg beside the cosigners'
 *      round 1    each member of the quorum runs nonce_gen; nonce_agg turns
 *                 those into one ordinary musig_pubnonce, and from there
 *                 upwards this is plain MuSig2
 *      round 2    each member runs partial_sign, which takes the message, the
 *                 cosigners' nonce and the round-one contributions;
 *                 partial_sig_agg turns the results into one ordinary
 *                 musig_partial_sig
 *
 *  You can find an example demonstrating the iceberg module in
 *  examples/iceberg.c. Further notes on API usage can be found in
 *  doc/iceberg.md.
 *
 *  Nonces are derived from a session label, sid32 below, rather than stored,
 *  so no signer holds a secret nonce between the two rounds. A label is a
 *  32-byte value the caller chooses, one per signing attempt; it is public and
 *  it need not be random, but it must never be used twice. That is narrower
 *  than keeping no state at all: a member still has to remember which labels it
 *  has already answered under. Choosing labels is the one thing this API cannot
 *  do for you, so read the note on secp256k1_iceberg_partial_sign before
 *  writing any of this.
 *
 *  Three things constrain how this can be used:
 *
 *  1. Both rounds need a quorum of 2t-1 members online, of whom up to t-1 may
 *     be corrupt. Since 2t-1 members have to exist, the threshold is at most
 *     half the group rounded up: 2-of-3 and 3-of-5 can be expressed where
 *     2-of-2 and 3-of-4 cannot. Constraint 3 then rules out 2-of-3 and 3-of-5
 *     as well, leaving 2-of-4 as the smallest usable group.
 *
 *  2. Messages between participants must travel over authenticated channels, and
 *     a contribution must be accepted only from the member its index names.
 *
 *     Every check below works by outnumbering the at most t-1 corrupt members
 *     with t honest ones, so that count has to be real, and this library cannot
 *     take it for you. It can tell that an index names a member of the group and
 *     that no two contributions claim the same one. It cannot tell who sent
 *     anything, and no check on the values could: the values of both rounds lie
 *     on a polynomial of degree t-1, so once t of them are public, anyone can
 *     compute the rest. A contribution that verifies proves the value is right,
 *     which is a public property, not that the named member produced it.
 *
 *     What that costs if it is skipped: an adversary supplying t of the 2t-1
 *     chooses the group's nonce. It picks a polynomial through the t-1 honest
 *     points it has to match, which leaves a coefficient free, and computes its
 *     own points on that. Every check here then passes.
 *
 *  3. The group must agree what it is signing before anyone answers, and
 *     agreeing while up to t-1 members misbehave needs n >= 3t-2 members to
 *     exist: 4 for a threshold of 2, 7 for 3, 10 for 4. Nothing here checks
 *     that, because it is a property of the group rather than of the
 *     arithmetic. It is still the bound to size a deployment with.
 */

/** Maximum number of participants in a group.
 *
 *  A participant holds one 32-byte seed per (t-1)-subset it is not a member of,
 *  so both storage and signing cost grow as C(n-1, t-1): 2 seeds at 2-of-3, 6 at
 *  3-of-5, 126 at 5-of-10.
 *
 *  It sizes two of the opaque types below, so it is part of this library's ABI
 *  and not something one member of a group can change on its own.
 */
#define SECP256K1_ICEBERG_MAX_PARTICIPANTS 10

/** Largest number of seeds one participant can hold, C(9, 4): the maximum of
 *  C(n-1, t-1) over every expressible configuration, since a quorum of 2t-1 has
 *  to fit in the group and so t is at most (n+1)/2.
 *
 *  This is the number that makes a group expensive: it sizes two of the opaque
 *  types below, and the module's largest stack frames with them.
 */
#define SECP256K1_ICEBERG_MAX_SEEDS 126

/** Largest buffer secp256k1_iceberg_share_serialize can need. A share of a
 *  particular group serializes to 4 + 32*C(n-1, t-1) bytes, which is smaller
 *  for every configuration except the largest; use this to size a fixed buffer
 *  without computing binomials. */
#define SECP256K1_ICEBERG_SHARE_MAX_LEN (4 + 32 * SECP256K1_ICEBERG_MAX_SEEDS)

/** Opaque data structures
 *
 *  The layout inside these is implementation defined and not portable between
 *  platforms or versions. Use the serialization and parsing functions to move
 *  them between machines or to storage. They contain no pointers, so they can
 *  be copied and moved. But a copy of a share is another copy of the secret,
 *  and erasing one means erasing all of them.
 *
 *  A stray pointer or an uninitialized struct is caught rather than used.
 *
 *  Every participant has an index in 1..n, assigned when the group is dealt. It
 *  travels inside the share and inside every object derived from one, so the
 *  aggregation functions can tell contributions apart, and a contribution
 *  separated from its index is not usable.
 *
 *  The index is a claim the object makes about itself. This library checks only
 *  that it names a member the group has: everything above n is refused, and
 *  within 1..n nothing here tells a genuine contribution from one an adversary
 *  wrote. Binding it to a member is constraint 2 above.
 */

/** Opaque data structure holding a participant's long-term secret share.
 *
 *  This is the material to guard and to back up, and it is not one number: it
 *  is a collection of 32-byte seeds, one for every group of t-1 participants
 *  that this participant is NOT a member of.
 *
 *  There is no resharing here, so a compromise or a change of membership means
 *  dealing the group again from scratch.
 *
 *  Guaranteed to be 4040 bytes in size: sized for the worst case the
 *  compile-time maximum allows, whatever n and t you actually use. Serializing
 *  writes only the seeds in use.
 */
typedef struct secp256k1_iceberg_share {
    unsigned char data[8 + 32 * SECP256K1_ICEBERG_MAX_SEEDS];
} secp256k1_iceberg_share;

/** Opaque data structure holding the Lagrange weights derived from a share.
 *
 *  Despite traveling with the share, this contains NO secret material. The
 *  weights depend only on participant indices and subset structure, both
 *  public, so nothing here needs protecting. It exists purely so that signing
 *  does not repeat the work, and it can be discarded and rebuilt at any time --
 *  which is the only way to move one, since it has no serialized form.
 */
typedef struct secp256k1_iceberg_share_cache {
    unsigned char data[8 + 32 * SECP256K1_ICEBERG_MAX_SEEDS];
} secp256k1_iceberg_share_cache;

/** Opaque data structure holding one participant's public key share.
 *
 *  A commitment to the participant's key share: the point you get by
 *  multiplying that share by the generator, plus the index it belongs to. It
 *  reveals nothing about the share and is meant to be published. This is what
 *  the group aggregates into its public key, and what lets everyone check that
 *  nobody published a wrong one.
 *
 *  Guaranteed to be 69 bytes in size. Serializes to 34 bytes.
 */
typedef struct secp256k1_iceberg_pubshare {
    unsigned char data[69];
} secp256k1_iceberg_pubshare;

/** Derive the Lagrange weights for a share.
 *
 *  An optimization, not a requirement. Three calls need these weights --
 *  secp256k1_iceberg_pubshare_gen, secp256k1_iceberg_nonce_gen and
 *  secp256k1_iceberg_partial_sign, and each accepts NULL and recomputes them,
 *  at the cost of one scalar inversion and multiplications growing as
 *  C(n-1, t-1). Build one if a participant signs often enough to care.
 *
 *  The weights depend on n, t and the participant index and on nothing else, so
 *  a cache is checked against those three rather than against the seeds. One
 *  built for a different participant, threshold or group size calls the illegal
 *  callback. One built for a different group of the same shape is accepted: it
 *  holds the same weights the share would have derived.
 *
 *  Returns: 1 on success. A malformed share calls the illegal callback.
 *  Args:    ctx: pointer to a context object
 *  Out:   cache: pointer to a cache object to initialize
 *  In:    share: the share to derive weights for
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_iceberg_share_cache_create(
    const secp256k1_context *ctx,
    secp256k1_iceberg_share_cache *cache,
    const secp256k1_iceberg_share *share
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Serialize a share. Writes 4 + 32*C(n-1, t-1) bytes.
 *
 *  The encoding is a version byte, then n, then t, then this participant's
 *  index, then the seeds. Only the seeds are secret. The three before them are
 *  what makes the seeds interpretable (their number is C(n-1, t-1), and which
 *  subset each belongs to follows from n, t and the index), so a caller that
 *  needs any of the three reads it here, off its own buffer.
 *
 *  On entry outlen is the size of the buffer; on return it is the number of
 *  bytes this share needs, whether or not they fitted. So a short buffer costs
 *  a second call rather than a guess, or size it at
 *  SECP256K1_ICEBERG_SHARE_MAX_LEN and never ask. A malformed share has no
 *  length to report and sets outlen to zero, so a caller looping on it stops
 *  rather than asking for the same buffer forever.
 *
 *  Returns: 1 on success, 0 if the buffer is too small. A malformed share
 *           calls the illegal callback.
 *  Args:     ctx: pointer to a context object
 *  Out:      out: buffer to write to
 *  In/Out: outlen: buffer size in, bytes needed out
 *  In:     share: the share to serialize
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_iceberg_share_serialize(
    const secp256k1_context *ctx,
    unsigned char *out,
    size_t *outlen,
    const secp256k1_iceberg_share *share
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Parse a share.
 *
 *  Returns: 1 on success, 0 if the input is malformed.
 *  Args:     ctx: pointer to a context object
 *  Out:    share: the share to initialize
 *  In:        in: serialized share
 *          inlen: its length
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_iceberg_share_parse(
    const secp256k1_context *ctx,
    secp256k1_iceberg_share *share,
    const unsigned char *in,
    size_t inlen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Compute this participant's public key share.
 *
 *  Returns: 1 on success. A malformed share calls the illegal callback.
 *  Args:      ctx: pointer to a context object (not secp256k1_context_static)
 *  Out:  pubshare: the public key share
 *  In:      share: this participant's share
 *           cache: its Lagrange weights, or NULL to recompute them
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_iceberg_pubshare_gen(
    const secp256k1_context *ctx,
    secp256k1_iceberg_pubshare *pubshare,
    const secp256k1_iceberg_share *share,
    const secp256k1_iceberg_share_cache *cache
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Serialize a public key share to 34 bytes.
 *
 *  Returns: 1, or 0 on a malformed public share, which is a caller error and
 *           also calls the illegal callback.
 *  Args:      ctx: pointer to a context object
 *  Out:     out34: pointer to a 34-byte array to write to
 *  In:   pubshare: the public key share to serialize
 */
SECP256K1_API int secp256k1_iceberg_pubshare_serialize(
    const secp256k1_context *ctx,
    unsigned char *out34,
    const secp256k1_iceberg_pubshare *pubshare
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Parse a public key share from 34 bytes.
 *
 *  Returns: 1 on success, 0 if the input does not encode a valid share.
 *  Args:      ctx: pointer to a context object
 *  Out:  pubshare: the public key share to initialize
 *  In:       in34: pointer to a 34-byte serialized share
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_iceberg_pubshare_parse(
    const secp256k1_context *ctx,
    secp256k1_iceberg_pubshare *pubshare,
    const unsigned char *in34
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Verify public key shares and combine them into the group public key.
 *
 *  Checks that the shares lie on a polynomial of degree at most t-1 and then
 *  interpolates them. A participant who published anything else raises the
 *  degree and is caught here, though the check proves only that the set is
 *  inconsistent, not which member is at fault.
 *
 *  Soundness needs at least t honest points present to pin the true polynomial,
 *  which is where the quorum of 2t-1 comes from: with at most t-1 members
 *  corrupt, 2t-1 contributions leave t honest ones, and t points fix a
 *  polynomial of degree t-1. Those t honest points have to be real: this call
 *  refuses an index above n, and constraint 2 is the caller's half.
 *
 *  The result is an ordinary public key. Pass it to secp256k1_musig_pubkey_agg
 *  alongside the cosigners' keys exactly as if it belonged to a single signer.
 *
 *  Returns: 1 on success, 0 if there are fewer than 2t-1 shares or more than
 *           the group size, if the shares are inconsistent, if two carry the
 *           same index, or in the vanishingly unlikely case that they combine
 *           to the point at infinity.
 *  Args:          ctx: pointer to a context object
 *  Out:     group_pk: the group's public key
 *  In:     pubshares: array of pointers to public key shares
 *        n_pubshares: how many
 *                  n: the group size the shares were dealt for. A share
 *                     carrying an index above it is rejected: no member sits
 *                     there, so nothing could have authenticated it
 *                  t: the threshold, at least 1 and at most (n+1)/2. An n or
 *                     a t outside its range is a caller bug and calls the
 *                     illegal callback
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_iceberg_pubkey_agg(
    const secp256k1_context *ctx,
    secp256k1_pubkey *group_pk,
    const secp256k1_iceberg_pubshare * const *pubshares,
    size_t n_pubshares,
    unsigned int n,
    unsigned int t
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Opaque data structure holding one participant's nonce contribution.
 *
 *  Guaranteed to be 133 bytes in size. Serialized and parsed with
 *  secp256k1_iceberg_pubnonce_serialize and secp256k1_iceberg_pubnonce_parse.
 */
typedef struct secp256k1_iceberg_pubnonce {
    unsigned char data[133];
} secp256k1_iceberg_pubnonce;

/** Opaque data structure holding the group's combined nonce.
 *
 *  This is the group's internal nonce pair (R1, R2'), before the nesting
 *  coefficient is applied. What goes up to the cosigners is an ordinary
 *  secp256k1_musig_pubnonce instead.
 *
 *  It is here for an implementation checking its own arithmetic, which needs the
 *  first 66 bytes of the b1 preimage and can get them nowhere else: the published
 *  pair has already had b1 applied and does not yield them back. The coefficient
 *  is
 *  b1 = H_Iceberg/noncecoef(R1 || R2' || P), where P is the group's public key
 *  and each point uses the 33-byte encoding MuSig2 uses for aggregate nonces.
 *  The published pair is (R1, b1*R2'): only the second point is scaled, because
 *  the coefficient enters as b1^(i-1).
 *
 *  No call here takes one as input, so the serializer below is the only one
 *  that reads it. It is also the only object you can decline to receive:
 *  secp256k1_iceberg_nonce_agg writes it if you want it and skips it if you
 *  pass NULL.
 *
 *  Guaranteed to be 132 bytes in size. Serialized and parsed with
 *  secp256k1_iceberg_aggnonce_serialize and secp256k1_iceberg_aggnonce_parse.
 */
typedef struct secp256k1_iceberg_aggnonce {
    unsigned char data[132];
} secp256k1_iceberg_aggnonce;

/** Opaque data structure holding one participant's signature share.
 *
 *  Guaranteed to be 37 bytes in size. Serialized and parsed with
 *  secp256k1_iceberg_partial_sig_serialize and
 *  secp256k1_iceberg_partial_sig_parse.
 */
typedef struct secp256k1_iceberg_partial_sig {
    unsigned char data[37];
} secp256k1_iceberg_partial_sig;

/** Serialize and parse the round-one and round-two objects.
 *
 *      pubnonce     67 bytes    a member's nonce contribution, index and two points
 *      aggnonce     66 bytes    the group's internal aggregate, no index
 *      partial_sig  33 bytes    a member's signature share, index and one scalar
 *
 *  A contribution and a signature share carry their participant index because
 *  everything that consumes them is indexed; an aggregate belongs to the group
 *  rather than to a member and so has none, which is the whole of the 67-versus-
 *  66 difference. Points use the 33-byte encoding MuSig2 uses for aggregate
 *  nonces, all zero for the point at infinity. The encoding has room for it,
 *  though secp256k1_iceberg_nonce_agg refuses to emit one.
 *
 *  Parsing rejects an index outside 1..SECP256K1_ICEBERG_MAX_PARTICIPANTS, a
 *  point that is not on the curve, and a signature share that is not a scalar
 *  below the group order. The parsers do not know the group size, so an index
 *  of 9 parses in a group of 5 and is caught when something that does know n
 *  tries to use it. None of these is a security boundary on its own, since a
 *  well-formed lie passes all of them, but each turns a value that would fail
 *  later into one that fails here.
 *
 *  Returns: for a parser, 1 on success and 0 if the encoding is invalid, which
 *           is an ordinary thing for bytes off a network to be. For a
 *           serializer, 1, or 0 on a malformed object, which is a caller error
 *           and also calls the illegal callback.
 *  Args:   ctx: pointer to a context object
 *  Out/In: the object and the fixed-size buffer named in each declaration
 */
SECP256K1_API int secp256k1_iceberg_pubnonce_serialize(
    const secp256k1_context *ctx,
    unsigned char *out67,
    const secp256k1_iceberg_pubnonce *pubnonce
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_iceberg_pubnonce_parse(
    const secp256k1_context *ctx,
    secp256k1_iceberg_pubnonce *pubnonce,
    const unsigned char *in67
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

SECP256K1_API int secp256k1_iceberg_aggnonce_serialize(
    const secp256k1_context *ctx,
    unsigned char *out66,
    const secp256k1_iceberg_aggnonce *aggnonce
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_iceberg_aggnonce_parse(
    const secp256k1_context *ctx,
    secp256k1_iceberg_aggnonce *aggnonce,
    const unsigned char *in66
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

SECP256K1_API int secp256k1_iceberg_partial_sig_serialize(
    const secp256k1_context *ctx,
    unsigned char *out33,
    const secp256k1_iceberg_partial_sig *partial_sig
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_iceberg_partial_sig_parse(
    const secp256k1_context *ctx,
    secp256k1_iceberg_partial_sig *partial_sig,
    const unsigned char *in33
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Derive this participant's nonce contribution for a session.
 *
 *  Depends on the share and the session label and nothing else: no message, no
 *  cosigner nonce, no key aggregation cache. That is what lets this round run
 *  before the message exists, which is the property the whole scheme is built
 *  around, and it is why a member absent from this round is not shut out of the
 *  next one: its contribution is determined, so it can work out what it would
 *  have been. There is no secret nonce object to hold between the rounds --
 *  round two recomputes the value from the share and the same label.
 *
 *  Returns: 1 on success. A malformed share calls the illegal callback.
 *  Args:      ctx: pointer to a context object (not secp256k1_context_static)
 *  Out:  pubnonce: this participant's contribution, to publish
 *  In:      share: this participant's share
 *           cache: its Lagrange weights, or NULL to recompute them
 *           sid32: the session label
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_iceberg_nonce_gen(
    const secp256k1_context *ctx,
    secp256k1_iceberg_pubnonce *pubnonce,
    const secp256k1_iceberg_share *share,
    const secp256k1_iceberg_share_cache *cache,
    const unsigned char *sid32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3)
  SECP256K1_ARG_NONNULL(5);

/** Verify nonce contributions and combine them.
 *
 *  Checks both nonce sharings the way key aggregation checks the key sharing,
 *  and for the same reason, then interpolates them into one ordinary MuSig2
 *  public nonce. From that nonce upwards this is plain MuSig2.
 *
 *  Returns: 1 on success, 0 if there are fewer than 2t-1 contributions or more
 *           than the group size, if they are inconsistent, if two carry the
 *           same index, or if the group's nonce comes out at infinity.
 *  Args:            ctx: pointer to a context object
 *  Out:  musig_pubnonce: the group's nonce, to publish to the cosigners
 *               aggnonce: the group's internal nonce, or NULL if you do not
 *                         want it. Nothing in this API consumes one
 *  In:        pubnonces: the contributions
 *           n_pubnonces: how many
 *                     n: the group size. A contribution carrying an index
 *                        above it is rejected
 *                     t: the threshold, at least 1 and at most (n+1)/2. An n
 *                        or a t outside its range is a caller bug and calls
 *                        the illegal callback
 *              group_pk: the group's public key. It feeds the nesting
 *                        coefficient, so round two must be given the same one
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_iceberg_nonce_agg(
    const secp256k1_context *ctx,
    secp256k1_musig_pubnonce *musig_pubnonce,
    secp256k1_iceberg_aggnonce *aggnonce,
    const secp256k1_iceberg_pubnonce * const *pubnonces,
    size_t n_pubnonces,
    unsigned int n,
    unsigned int t,
    const secp256k1_pubkey *group_pk
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2)
  SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(8);

/** Does this key aggregation cache aggregate this list, and is the group in it?
 *
 *  Run this once, where the cache is built, and not once per session: the key
 *  set belongs to the channel while a session belongs to a single signing
 *  attempt.
 *
 *  secp256k1_iceberg_partial_sign takes the group's public key and the outer
 *  cache as two separate arguments and nothing ties them together, because
 *  nothing can: a cache records the hash of the key list, not the list, so
 *  membership is not a question it can answer. Passing a cache built over some
 *  other set of cosigners produces a well-formed coefficient for a key that is
 *  not in the aggregation, a signature share that is useless, and a spent session
 *  label, which is the part that matters. Retrying under that label with
 *  the right cache is then the attack, self-inflicted.
 *
 *  MuSig2's own partial_sign asks for no key list, because there a wrong cache
 *  costs a nonce rather than a label.
 *
 *  Tweaks are fine. The list hash is fixed when the keys are aggregated and no
 *  tweak touches it, so a cache carrying taproot tweaks still passes.
 *
 *  Returns: 1 if keyagg_cache aggregates exactly this list of public keys, in
 *           this order, and group_pk is one of them. 0 if it aggregates some
 *           other list, or if group_pk is not in it. A malformed cache or public
 *           key is a caller bug rather than an answer, and calls the illegal
 *           callback as it does everywhere else in this module: neither has a
 *           wire format, so neither can have arrived from a peer
 *  Args:            ctx: pointer to a context object
 *  In:     keyagg_cache: the outer MuSig2 key aggregation cache to check
 *               pubkeys: the keys it should have been built from, in the order
 *                        they were passed to secp256k1_musig_pubkey_agg
 *             n_pubkeys: how many, at least 1
 *              group_pk: the group's public key, which must be one of them
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_iceberg_keyagg_check(
    const secp256k1_context *ctx,
    const secp256k1_musig_keyagg_cache *keyagg_cache,
    const secp256k1_pubkey * const *pubkeys,
    size_t n_pubkeys,
    const secp256k1_pubkey *group_pk
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3)
  SECP256K1_ARG_NONNULL(5);

/** Produce this participant's signature share.
 *
 *  A participant makes its own three secrets alone: both nonce scalars and its
 *  key share follow from its share and the label, with nobody else involved. What
 *  it cannot make alone is the group's aggregate nonce, which is a value at zero
 *  and so takes t points, and that aggregate is hashed into two of the
 *  coefficients those secrets get multiplied by. Hence the round-one
 *  contributions in the argument list below.
 *
 *  It takes the message and the cosigners' nonce for the same reason, and
 *  recomputes the challenge from them. It also adds the group's own nonce
 *  internally, so "the aggregate nonce includes my contribution" holds by
 *  construction rather than by assumption.
 *
 *  The rule this function cannot enforce for you: never call it twice with the
 *  same sid32. Not "never with the same message": never twice, whatever else you
 *  change. A participant's three secrets are fixed by the label alone and
 *  everything else in the signing equation is a coefficient over public values,
 *  so two answers under one label are two equations in three unknowns and three
 *  are three, at which point the key share falls out by elimination.
 *
 *  Half of that is yours: a member can refuse to answer twice if it remembers
 *  what it has answered under, which means durable storage that is never rolled
 *  back, because this library holds nothing between calls. Recording the label
 *  is enough, and it is all that is enough: the label is one signing attempt,
 *  so a retry is a new label rather than a second answer under the old one. The
 *  other half is the group's: two members must not answer one label on different
 *  messages, which no member can detect, since what the others were shown is not
 *  something the protocol tells it. That is constraint 3 at the top of this file.
 *  Where the label is a commitment number and an attempt counter, both halves
 *  come from machinery the surrounding protocol runs anyway, and
 *  examples/iceberg.c shows the member's half.
 *
 *  What it does check: it builds the group's aggregate from the contributions
 *  rather than accepting one, because the nesting coefficient is a hash of that
 *  aggregate and a coordinator free to invent it would hold a coefficient it
 *  could vary at will. It then interpolates the set and compares the result at
 *  this participant's own index against the contribution it derives locally,
 *  which ties the set to the label being signed under. Otherwise a consistent
 *  sharing from a different session would pass. It also counts the signer among
 *  the honest points of constraint 2: a set assembled by somebody else has to
 *  agree with this participant's own share as well as with the rest. The
 *  participant need not be one of the contributors, since it holds the share
 *  that determines what its own contribution would have been either way.
 *
 *  Returns: 1 on success, 0 if there are fewer than 2t-1 contributions or more
 *           than the group size, if two carry the same index, or if the set is
 *           inconsistent or belongs to another session. The group size is not an
 *           argument here: it comes off the caller's own share. A malformed
 *           share, or a share cache built for a different participant, calls the
 *           illegal callback
 *  Args:            ctx: pointer to a context object (not
 *                        secp256k1_context_static)
 *  Out:     partial_sig: the signature share to publish
 *  In:            share: this participant's share
 *                 cache: its Lagrange weights, or NULL to recompute them
 *                 sid32: the session label, the same one round one used
 *             pubnonces: the group's own round-one contributions, one per
 *                        member. Not the cosigners', which arrive already
 *                        aggregated as cosigner_aggnonce below. Pass every valid
 *                        one you have; any qualifying set gives the same result,
 *                        so members need not agree on which
 *           n_pubnonces: how many, at least 2t-1 and at most the group size
 *              group_pk: the group's public key, the one round one was given
 *          keyagg_cache: the outer MuSig2 key aggregation cache
 *                 msg32: the message being signed
 *     cosigner_aggnonce: the cosigners' aggregate nonce, theirs alone. Not the
 *                        other group members', and not including the group's
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_iceberg_partial_sign(
    const secp256k1_context *ctx,
    secp256k1_iceberg_partial_sig *partial_sig,
    const secp256k1_iceberg_share *share,
    const secp256k1_iceberg_share_cache *cache,
    const unsigned char *sid32,
    const secp256k1_iceberg_pubnonce * const *pubnonces,
    size_t n_pubnonces,
    const secp256k1_pubkey *group_pk,
    const secp256k1_musig_keyagg_cache *keyagg_cache,
    const unsigned char *msg32,
    const secp256k1_musig_aggnonce *cosigner_aggnonce
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3)
  SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(8)
  SECP256K1_ARG_NONNULL(9) SECP256K1_ARG_NONNULL(10) SECP256K1_ARG_NONNULL(11);

/** Check one signature share against what its author published.
 *
 *  Verifies s_k*G == +-(R1,k + b0*b1*R2,k) + e*a*g*gacc*D_k, the equation
 *  secp256k1_iceberg_partial_sign solves. Without this,
 *  secp256k1_iceberg_partial_sig_agg turns one bad share into a signature that
 *  fails to verify with nothing to say why.
 *
 *  The participant's nonce is read off the contributions rather than passed in.
 *  They determine one polynomial per nonce, and its value at that index is what
 *  the participant's contribution had to be, so this also works for a member
 *  that sat out round one and published no contribution of its own.
 *
 *  What a 0 means, and what it does not. It means this share does not satisfy
 *  that equation against this pubnonce and this public share. It does not name a
 *  culprit. A MuSig2 partial signature is forgeable by anyone who knows the
 *  session's public values, so a share that fails here may have been written by
 *  somebody other than the participant it is attributed to. Assigning blame is a
 *  stronger claim and needs an honest-supermajority quorum: 3t-2 members
 *  online at once, rather than the 2t-1 this scheme otherwise requires. Use this
 *  to find out that a signing attempt will fail before spending an aggregation
 *  on it, and to narrow where to look. Do not use it as evidence against a
 *  member.
 *
 *  A 0 also does not distinguish a bad share from bad inputs. The same answer
 *  comes back if the message or the cosigners' aggregate nonce differs from the
 *  one the signer had. The set of contributions is the exception: any qualifying
 *  set from the session determines the same polynomial, so it need not be the
 *  set the signer used.
 *
 *  Every other argument must be the one secp256k1_iceberg_partial_sign was
 *  given. The public share is what names the participant, and a signature share
 *  carrying a different index is refused rather than verified against its own,
 *  which catches the two arguments being drawn from different members.
 *
 *  Returns: 1 if the share satisfies the equation, 0 otherwise, including a
 *           contribution count outside 2t-1..n, and including a malformed
 *           partial_sig, which is the object being examined. A malformed
 *           pubshare, key aggregation cache, group key or cosigner aggregate is
 *           the caller's own and calls the illegal callback
 *  Args:                ctx: pointer to a context object
 *  In:          partial_sig: the signature share to check
 *                  pubshare: the public share of the participant it is
 *                            attributed to, which is what says which one that is
 *                 pubnonces: a qualifying set from the same session. It need not
 *                            be the set the signer used: any consistent 2t-1
 *                            determine the same polynomial
 *               n_pubnonces: how many, at least 2t-1 and at most n
 *                         n: the group size. A contribution carrying an index
 *                            above it is rejected
 *                         t: the threshold, at least 1 and at most (n+1)/2. An
 *                            n or a t outside its range is a caller bug and
 *                            calls the illegal callback
 *                  group_pk: the group's aggregate public key
 *              keyagg_cache: the MuSig2 cache for the outer session
 *                     msg32: the message being signed
 *         cosigner_aggnonce: the cosigners' aggregate nonce
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_iceberg_partial_sig_verify(
    const secp256k1_context *ctx,
    const secp256k1_iceberg_partial_sig *partial_sig,
    const secp256k1_iceberg_pubshare *pubshare,
    const secp256k1_iceberg_pubnonce * const *pubnonces,
    size_t n_pubnonces,
    unsigned int n,
    unsigned int t,
    const secp256k1_pubkey *group_pk,
    const secp256k1_musig_keyagg_cache *keyagg_cache,
    const unsigned char *msg32,
    const secp256k1_musig_aggnonce *cosigner_aggnonce
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3)
  SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(8) SECP256K1_ARG_NONNULL(9)
  SECP256K1_ARG_NONNULL(10) SECP256K1_ARG_NONNULL(11);

/** Combine signature shares into one MuSig2 partial signature.
 *
 *  Interpolation needs t points and the quorum bound exists only for the degree
 *  check, so unlike the nonce round this takes t rather than 2t-1. The scheme
 *  as specified keeps 2t-1 online throughout regardless; this call simply does
 *  not need them all to have answered.
 *
 *  The result is an ordinary MuSig2 partial signature. Pass it to
 *  secp256k1_musig_partial_sig_agg with the cosigners' partial signatures.
 *
 *  Given more than t shares, this refuses a set that contradicts itself. The
 *  shares of one session lie on a polynomial of degree t-1, as the contributions
 *  of the nonce round do, so anything past the t needed to interpolate is a
 *  second opinion and is treated as one. Passing a spare share is therefore
 *  worth something, and can turn a call that would have succeeded into one that
 *  fails: at exactly t there is nothing to disagree with, and a bad share is
 *  aggregated into a signature that fails later without naming a share.
 *
 *  This is not verification. It says the shares agree with each other, not that
 *  they are the ones the members would have produced, and it cannot tell you
 *  which of them is the odd one out. secp256k1_iceberg_partial_sig_verify
 *  answers both, one share at a time, against the public share it names.
 *
 *  Returns: 1 on success, 0 if there are fewer than t shares or more than the
 *           group size, if a share carries an out-of-range index, if two carry
 *           the same one, or if more than t shares are given and they do not
 *           lie on one polynomial of degree t-1.
 *  Args:                 ctx: pointer to a context object
 *  Out:    musig_partial_sig: the group's partial signature
 *  In:           partial_sigs: the signature shares. An uninitialized one calls
 *                              the illegal callback;
 *                              a share off the wire is fine, since
 *                              secp256k1_iceberg_partial_sig_parse writes the
 *                              same tag secp256k1_iceberg_partial_sign does
 *              n_partial_sigs: how many
 *                           n: the group size. A share carrying an index above
 *                              it is rejected
 *                           t: the threshold, at least 1 and at most (n+1)/2.
 *                              An n or a t outside its range is a caller bug
 *                              and calls the illegal callback
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_iceberg_partial_sig_agg(
    const secp256k1_context *ctx,
    secp256k1_musig_partial_sig *musig_partial_sig,
    const secp256k1_iceberg_partial_sig * const *partial_sigs,
    size_t n_partial_sigs,
    unsigned int n,
    unsigned int t
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_ICEBERG_H */
