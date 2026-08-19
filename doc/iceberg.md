Notes on the iceberg module API
===============================

The following sections contain additional notes on the API of the iceberg
module (`include/secp256k1_iceberg.h`). A usage example can be found in
`examples/iceberg.c`, which runs the whole flow and narrates it.

**This module is experimental.** It builds by default here, which is a
development convenience rather than a statement that it is ready. Iceberg has a
security proof, by reduction to NestedMuSig2's unforgeability, but it is in an
anonymous conference submission that is still a working draft, and at the two
nonces BIP-327 fixes that reduction holds in the algebraic group model rather
than the plain random oracle model. The proof also assumes a property no library
can provide (that a session label is used once, group-wide) and the known
ways to lose a key all live in exactly that assumption. Do not put money behind
this module.

Iceberg lets a *t*-of-*n* group act as a single MuSig2 participant. From outside,
the result is an ordinary BIP-340 signature: nothing in it records that a group
was involved, or how large the group was.

## The objects

Two APIs are in play and about a dozen nouns between them. MuSig2's, which this
module does not replace:

| name | type | made by | secret? | size |
|---|---|---|---|---|
| key aggregation cache | `musig_keyagg_cache` | anyone, from the signers' public keys | no | opaque |
| secret nonce | `musig_secnonce` | a signer, once per session | **yes, and it must survive between the rounds** | never serialized |
| public nonce | `musig_pubnonce` | a signer | no | 66 B |
| aggregate nonce | `musig_aggnonce` | anyone | no | 66 B |
| partial signature | `musig_partial_sig` | a signer | no | 32 B |

And Iceberg's, which exist entirely inside the group:

| name | type | made by | secret? | size |
|---|---|---|---|---|
| share | `iceberg_share` | the dealer, once | **yes, and it is the only _secret_ anyone stores** | 4 + 32*C(n-1, t-1) B |
| share cache | `iceberg_share_cache` | a participant | no: Lagrange weights, which depend only on which participant you are | opaque |
| public share | `iceberg_pubshare` | a participant | no | 34 B |
| nonce contribution | `iceberg_pubnonce` | a participant, per session | no | 67 B |
| group nonce | `iceberg_aggnonce` | nobody has to: no call takes one as input, so pass `NULL` unless you want it for logging | no | 66 B |
| signature share | `iceberg_partial_sig` | a participant, per session | no | 33 B |

Two names are close and the objects are not. The group produces a MuSig2 **partial signature**, built
out of Iceberg **signature shares**, one per participant. Likewise a participant
makes a **nonce contribution**, and the group turns `2t-1` of them into one
ordinary MuSig2 **public nonce**.

Those two conversions are the seam. `iceberg_nonce_agg` emits a
`musig_pubnonce` and `iceberg_partial_sig_agg` emits a `musig_partial_sig`;
everything above them is ordinary MuSig2 that knows nothing about a group, and
everything below is this module.

## Three roles

Three roles appear here, and they run different code:

| role | runs | trusted? |
|---|---|---|
| **participant** | `iceberg_*` calls. Holds a share, never the key. There are *n* of them | with its own share only |
| **coordinator** | moves messages, calls the `_agg` functions | **no.** Every check in the module assumes it is hostile |
| **cosigner** | plain `musig_*` calls, and knows nothing about the group | as any MuSig2 signer |

A participant may also act as the coordinator; nothing changes if it does,
because the coordinator has no privileges to abuse.

## How many people, and when

Two different counts:

- **Round one needs `2t-1` participants.** Not because the secret needs that
  many, but because the group verifies its own nonce contributions, and that
  check is error detection.

  A contribution is a point on a polynomial of degree `t-1`, and **any `t`
  points lie on some polynomial of that degree**, including `t` an adversary
  chose. So a quorum of `t` does not weaken the check, it empties it. Every
  point past `t` is one more constraint a liar has to satisfy, and outnumbering
  `t-1` liars takes `t-1` of them:

      t + (t-1) = 2t-1

  Read as coding theory it is the same statement: detecting `e` errors in a code
  of dimension `t` needs `t+e` symbols. The `3t-2` under "Not implemented" is
  this formula with correction, `t+2e`, in place of detection. Note that the
  `n >= 3t-2` deployment bound below is a *different* result that happens to be
  the same number: one is Reed-Solomon correction, the other is Byzantine
  agreement, and neither implies the other.
- **Round two needs `2t-1` too**, and they need not be the ones who took part in
  round one. The paper's Table II gives the signing quorum as `2t-1` online
  members for every threshold, and the honest majority that number represents
  does not stop applying halfway through a session.

  A member that was offline for round one can still take part: it holds the
  share that determines what its contribution would have been, so it can verify
  the set it is handed and sign against it. That is the property the
  deterministic nonces exist to buy, and it is why `partial_sign` does not
  insist on finding your own contribution in the set; see "API misuse".

  `t` appears in round two only as the interpolation degree; the arithmetic
  that turns signature shares back into one signature needs `t` points. Reading
  that as "round two needs `t` people" is the mistake to avoid.

Since `2t-1` participants must exist, `2t-1 <= n`, so:

    t <= (n+1)/2

This is a hard structural limit, not a performance note. **2-of-2, 3-of-3,
3-of-4, 4-of-5, 4-of-6 and 6-of-10 cannot be expressed at all.**
`secp256k1_iceberg_shares_gen` refuses them at setup rather than mishandling
them later; see the failure table under "API misuse" for what refusing means.

Sizes, since a share is a bundle of seeds and grows quickly. Both rounds want
`2t-1` members online; the third column is the smaller number the *arithmetic* of
step 10 needs, which is a degree and not a quorum.

**These are expressible configurations, not recommended ones.** A separate bound
applies to deployment: agreeing on the live state with up to `t-1` faulty members
is Byzantine agreement, which needs `n >= 3(t-1)+1 = 3t-2`. That gives 2-of-4,
3-of-7, 4-of-10, 5-of-13 as the smallest deployable groups, and **five of the
seven rows below fall short of it**. The signature scheme is correct at all of
them, since the arithmetic does not know how many faults the surrounding
agreement survives, but a group sized from this table alone will be too small for the
consensus the scheme assumes. See the deployment constraints in
`include/secp256k1_iceberg.h`.

Note where the two bounds meet. 5-of-13 needs more participants than
`SECP256K1_ICEBERG_MAX_PARTICIPANTS` allows, so at the maximum of 10 the
largest threshold that is both expressible and deployable is **4-of-10**. The
table below goes past that line, and so do the benchmark and the tests: 5-of-9
and 5-of-10 are there to show the cost curve, not because a group should be
sized that way.

`SECP256K1_ICEBERG_MAX_PARTICIPANTS` is 10. It sizes two of the opaque types and
the largest stack frames in the module, all of which grow as `C(n-1, t-1)`, so it
is part of the ABI and not something one member of a group changes on its own. A
build that will only ever run small groups can lower it, and gets a 200-byte share
instead of a 4040-byte one at five participants; `src/modules/iceberg/rss.h`
beside the `#error` says which three derived values have to be lowered with it,
and `run_iceberg_binom_test` recomputes all three and names the one that is wrong.
Raising it is refused at compile time. `rss.h` also carries the command that
measures the stack frames, rather than a number, because the number moves with the
compiler. None of that is in the public header: a caller of the installed library
has no `rss.h`, no test suite and no `src/` to run it against.

| config | quorum `2t-1` | shares that interpolate | seeds in the group | seeds per participant | serialized share |
|---|---|---|---|---|---|
| 2-of-3 | 3 | 2 | 3 | 2 | 68 B |
| 2-of-4 | 3 | 2 | 4 | 3 | 100 B |
| 3-of-5 | 5 | 3 | 10 | 6 | 196 B |
| 3-of-7 | 5 | 3 | 21 | 15 | 484 B |
| 4-of-7 | 7 | 4 | 35 | 20 | 644 B |
| 5-of-9 | 9 | 5 | 126 | 70 | 2244 B |
| 5-of-10 | 9 | 5 | 210 | 126 | 4036 B |

Everything that crosses the network serializes: a share to `4 + 32*C(n-1, t-1)`
bytes, a public share to 34, a nonce contribution to 67 and a signature share to
33. The group's aggregate nonce serializes to 66 as well, but it is not on that
list: nothing receives one. Those bytes are the start of the b1 preimage, and
they are there for an implementation checking its arithmetic against this one.

The public share, the nonce contribution and the signature share each carry the
participant index they belong to, which is the extra byte in each. The group's
aggregate nonce does not, since it belongs to the group rather than to a member,
which is exactly why it is 66 bytes and a contribution is 67.

The group's seed count is `C(n, t-1)` and each participant holds
`C(n-1, t-1)` of them. The bounds derived from
`SECP256K1_ICEBERG_MAX_PARTICIPANTS` (`SECP256K1_ICEBERG_MAX_SEEDS` here, and
`MAX_T` and `MAX_SUBSETS` in `rss.h`) are written out by hand because C89
cannot evaluate a binomial at preprocessing time. The test suite recomputes each
of them and fails on a wrong line.

## The flow

    participant k                coordinator                    cosigner
    (one of n)                   (untrusted)                    (plain musig2)
    -------------                -----------                    --------------

    SETUP, once. A dealer runs shares_gen and is then not needed again.
      iceberg_shares_gen  -> one share each     [_dealer.h, not installed]
      iceberg_pubshare_gen -> iceberg_pubkey_agg -> the group's public key

    KEY AGGREGATION. The group is now one public key among several.
      musig_pubkey_agg([group_pk, cosigner_pk, ...]) -> keyagg_cache
      optionally musig_pubkey_xonly_tweak_add / _ec_tweak_add

    === ROUND ONE ================================ needs 2t-1 participants ===

    Neither side waits on the other. iceberg_nonce_gen needs only the share
    and the label; musig_nonce_gen is an ordinary MuSig2 call and takes
    whatever it usually takes. Drawn side by side for that reason.

      iceberg_nonce_gen(share, sid32)              musig_nonce_gen
                     --- pubnonce (67 B) -->
                                 <-- pubnonce ------
                                 iceberg_nonce_agg
                                   verifies 2t-1 of them, interpolates
                                   -> one ordinary musig pubnonce
                                 musig_nonce_agg([group, cosigners])
                                                  --- aggnonce -->
                                                     musig_nonce_process

    ------------------------------------------------------------------------
      THE GAP. No secret nonce survives this line. A participant's nonces
      are a function of (share, sid), and it is handed the sid again, so a
      crash here costs it nothing and there is no secret to lose, leak or
      duplicate. That is narrower than "stores nothing": it must still
      remember which labels it has answered under, and restoring a backup
      from before that record is exactly the exploitable case.
    ------------------------------------------------------------------------

    === ROUND TWO ============================ needs 2t-1 again, any of n ===

    The message appears here for the first time, which is the point: the
    group commits to a nonce before knowing what it will sign.

                                 --- msg, the round-one pubnonces -->
      iceberg_partial_sign(share, sid32, msg, the contributions, ...)
        derives the group's aggregate from the contributions rather than
        accepting one, checks they are a single sharing of degree t-1, and
        compares their value at its own index against the contribution it
        derives for itself. So it signs against the aggregate the group
        really formed. A member that sat round one out can still sign.
                     --- partial sig (33 B) -->
                                 iceberg_partial_sig_agg
                                   -> one ordinary musig partial sig
                                                     musig_partial_sign
                                 <-- partial sig ---
                                 musig_partial_sig_agg -> 64-byte signature

    schnorrsig_verify accepts it under the (possibly tweaked) aggregate key.

## Signing, as a list

1. **Dealer**: `secp256k1_iceberg_shares_gen`, from
   `include/secp256k1_iceberg_dealer.h`, then hand each participant its share
   and forget the seed. That header is separate and is not installed, because a
   trusted dealer is not something the library offers for deployment; see
   "API misuse" below. A distributed key generation replaces this step and
   nothing downstream changes.
2. **Each participant**: `secp256k1_iceberg_pubshare_gen`, publish the result.
3. **Anyone**: `secp256k1_iceberg_pubkey_agg` over any `2t-1` public shares.
   This checks they agree, so a participant that published a wrong one is
   caught here rather than at signing time.
4. **Anyone**: `secp256k1_musig_pubkey_agg` with the group's public key and the
   cosigners', then optionally `secp256k1_musig_pubkey_xonly_tweak_add` and
   `secp256k1_musig_pubkey_ec_tweak_add`.
5. **Each of `2t-1` participants**: `secp256k1_iceberg_nonce_gen`, over the
   session label alone. Publish the result. Nothing here depends on the
   message or on the cosigners, so this can run before either exists.
6. **Cosigners**, independently and in either order: `secp256k1_musig_nonce_gen`,
   then `secp256k1_musig_nonce_agg` over the cosigners' nonces alone.
7. **Coordinator**: `secp256k1_iceberg_nonce_agg`, which verifies and
   interpolates them into one ordinary MuSig2 public nonce.
8. **Coordinator**: `secp256k1_musig_nonce_agg` over that and the cosigners',
   then `secp256k1_musig_nonce_process`.
9. **Participants**, not necessarily the ones from step 5:
   `secp256k1_iceberg_partial_sign`, given the group's own round-one
   contributions, not an aggregate of them and not the cosigners', the same
   label, and now the message. This is where the message enters and the only
   place it appears in the API. Each call needs all `2t-1` contributions from
   step 5 and returns 0 with fewer, and the scheme wants `2t-1` members online
   here as in round one; step 10 then interpolates from as few as `t` of the
   resulting shares. Before calling it, each signer checks its own record that it
   has not answered under this label already; the library cannot do that for it,
   because it holds nothing between calls.
10. **Coordinator**: `secp256k1_iceberg_partial_sig_agg`, giving one MuSig2
    partial signature. Hand it more than `t` shares and it degree-checks them,
    which above the threshold catches a set that contradicts itself; at exactly
    `t` there is nothing to disagree with.
11. **Cosigners**: `secp256k1_musig_partial_sign` as usual.
12. **Coordinator**: `secp256k1_musig_partial_sig_agg`, then
    `secp256k1_schnorrsig_verify`.

Steps 1 to 4 happen once per group, and `secp256k1_iceberg_keyagg_check` belongs
with step 4: it confirms the outer cache aggregates the key list you think it
does, which is a fact about the channel rather than about this attempt. Steps 5
to 12 are one signing session.

## API misuse

The musig module's three rules apply here too: unique nonces, never copy or
serialize a `secp256k1_musig_secnonce`, and never read or write an opaque struct
directly. Iceberg adds its own, and the reasons are specific.

**How a call refuses, before anything else.** A function returns 0 when the
values it was handed do not work together: an inconsistent set of shares, a
malformed encoding, a contribution derived under some other label. The illegal
callback, which aborts the process unless the caller has installed its own with
`secp256k1_context_set_illegal_callback`, is reserved for a bug in the calling
code: a null pointer, an uninitialized opaque struct, a group shape the scheme
cannot express.

How many contributions turned up is neither. It is a fact about the group,
influenced by whichever peers answered, so every call that takes a count returns
0 rather than aborting:

| call | a bad count does what |
|---|---|
| `iceberg_shares_gen` | aborts: `n` outside `1..10`, or `t` outside `1..(n+1)/2`. These are the group's shape, not a count |
| `iceberg_pubkey_agg` | returns 0: fewer than `2t-1` public shares, or more than `n` |
| `iceberg_nonce_agg` | returns 0: fewer than `2t-1` contributions, or more than `n` |
| `iceberg_partial_sig_agg` | returns 0: fewer than `t` shares or more than `n`. A share that never came from `partial_sign` still aborts, that one being an uninitialized struct |
| `iceberg_partial_sign` | returns 0: it checks the same `2t-1` bound while deriving the aggregate |
| `iceberg_partial_sig_verify` | returns 0: same reason, and it derives the same aggregate |

A member that waits for a deadline and aggregates whatever arrived is therefore
doing something the API supports, rather than something that kills its process
the first time a peer is asleep.

**Where n and t come from.** `iceberg_partial_sign` reads them off the caller's
own share and never asks. The four calls that take them as arguments should be
given the same values; a member that keeps only a serialized share can read them
from it, since the encoding is `version | n | t | index | seeds`. It matters most
for `t`: understate it and the degree check still runs, against a lower degree,
and proves less. Nothing cross-checks the four calls against each other.

**You supply the session label, and the rule about it is yours to enforce.** Every participant's secret nonces are a
deterministic function of its seeds and the label, and the seeds never change,
so a label reused under two different messages produces two answers in which
`k1`, `k2` and `d` are identical while `b0` and `e` have moved. Three such
answers are three linear equations in those three unknowns, and solving them
recovers a key share.

Concretely, the caller must guarantee both halves:

- **one answer per member per label.** A member can enforce this alone, but not
  from anything the library holds; it keeps nothing between calls. It needs
  durable storage of its own: one 32-byte field per participant holding the last
  label it signed under, and a rule that a new label must be strictly greater.
  `may_sign_under` in `examples/iceberg.c` does exactly that.
  Restore it with the share; a record rolled back to an old backup is a member
  that will answer twice.
- **one message per label across the whole group**: the members must agree on
  what they are signing before any of them answers.

The library sees one call at a time and holds nothing between them, so it can
enforce neither. Neither can any
individual participant: a coordinator can show three *different* members three
*different* messages under one label, and each one signs exactly once, refuses
nothing, and detects nothing, because nothing in the protocol tells a member
that somebody else saw this label too. **Per-participant discipline is therefore
not a substitute for group agreement**, which is why the scheme's security model
assumes a consensus its deployment already runs.

*Why the label cannot simply be derived from the message, which would close all
of this:* round one has to run before the message exists. In Lightning the
nonce is exchanged a full round-trip before the commitment transaction is
assembled, so a label binding the message could not be computed when it is
needed. The intended label is the channel's commitment number, plus a counter
for retries under it. A label bound to the message is possible where the message
*is* known early, but it costs the message-independent first round, which is a different setting from the one this
module assumes. The module takes any 32 bytes and offers no derivation, because
the right label depends on the deployment, and the wrong one costs a key share.

**`secp256k1_iceberg_partial_sign` takes the group's own round-one
contributions, not an aggregate of them.** This is not an optimisation
opportunity. The nesting coefficient is a hash of the group's aggregate nonce,
so a coordinator free to invent that aggregate gets a coefficient it can vary at
will: three invented aggregates under one correctly-bound label again give
three equations in the same three unknowns. The aggregate is therefore derived
from contributions that must pass the degree check together, and then the
interpolated polynomial is evaluated at the signer's own index to get the nonce
shares it signs with. It signs against the aggregate the group actually formed,
whether or not it was one of the members who helped form it.

It does *not* require the signer's own round-one contribution to be present and
unaltered in the set. That would be strictly stronger against an unauthenticated
transport, and it would lock out a member who was offline during round one --
the exact failure the deterministic nonces exist to survive. With the
authenticated transport the scheme assumes anyway it is unnecessary: among
`2t-1` contributions with at most `t-1` corruptions, at least `t` are honest,
and `t` points already pin a degree `t-1` polynomial.

**A tweak belongs to the outer session and must not be applied twice.** The
module is correct here and needs nothing from the caller. No Iceberg call takes
a tweak because `secp256k1_musig_nonce_process` sets
the tweak term aside and `secp256k1_musig_partial_sig_agg` adds it in once, at
the top. The group's shares carry the key coefficient and not the tweak.

**`secp256k1_iceberg_shares_gen` is a trusted dealer, and lives outside the
installed API for that reason.** For the duration of that one call, one machine
holds enough to reconstruct the group's private key, which is the situation a
threshold scheme exists to avoid. It is fine for testing, and fine where one
party is already trusted with the whole key. It is not fine otherwise, and this
module does not provide a distributed key generation.

It is declared in `include/secp256k1_iceberg_dealer.h`, which is in the tree so
the tests, the benchmarks and the example have shares to work with, and is not
installed. Including `secp256k1_iceberg.h` does not offer you a dealer. Nothing
in the signing API cares how a share was produced: one arrives through
`secp256k1_iceberg_share_parse`, so a share from a DKG or from another
implementation is used identically.

## What is stored, and for how long

| object | who holds it | lifetime | secret? |
|---|---|---|---|
| `iceberg_share` | one participant | forever | **yes** |
| `iceberg_share_cache` | one participant | optional, derived from the share | no |
| `iceberg_pubshare` | published | forever | no |
| session label (`sid32`) | anyone | one session, and a record that it was used, for as long as the group lives | no |
| `iceberg_pubnonce` | published | one session | no |
| `iceberg_aggnonce` | coordinator | one session | no |
| `iceberg_partial_sig` | published | one session | no |

Nothing marked secret above needs to survive a reboot except the share,
which is why `examples/iceberg.c` wipes every participant between the two rounds
and rebuilds them from storage. That is the property Iceberg exists for: a FROST
signer must keep a secret nonce alive across the same gap, and losing it,
restoring an old copy over it, or running two instances of the signer are all
catastrophic.

It does not follow that a participant is stateless, and the table does not say
so. A member must also remember **which labels it has already answered under**.
That record is not secret and so is not listed above, but it is not optional: restoring a backup taken before it
was written is the one restore that is dangerous. A signer with no memory can
also be talked into signing a superseded channel state, which in Lightning costs
it the channel.

The share cache holds no secrets despite being derived from a share: it is
Lagrange weights, which depend only on which participant it is. It has no
serialized form and does not need one; passing `NULL` wherever a cache is
accepted rebuilds it. `bench_iceberg` prints what that costs, along with the
rest of the module; the figure moves with the machine.

## Not implemented

- **Naming the liar.** `secp256k1_iceberg_partial_sig_verify` ships, so a share
  can be checked against the commitments it claims to come from, and a failed
  signature need not be a mystery. What it does not do is assign blame: a 0
  means that share does not satisfy the equation, not that its author cheated,
  because MuSig2 partial signatures are forgeable. Naming the liar is error
  *correction* rather than detection, and correction needs `t+2e` points where
  detection needed `t+e`, so `3t-2` online at once, against `2t-1` for
  signing. That is usually more people than the group has, which is why the
  function is documented as detection and stops there.
- **Distributed key generation.** See above.
