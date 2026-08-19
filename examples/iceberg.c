/*************************************************************************
 * To the extent possible under law, the author(s) have dedicated all    *
 * copyright and related and neighboring rights to the software in this  *
 * file to the public domain worldwide. This software is distributed     *
 * without any warranty. For the CC0 Public Domain Dedication, see       *
 * EXAMPLES_COPYING or https://creativecommons.org/publicdomain/zero/1.0 *
 *************************************************************************/

/** A 3-of-7 group signing beside an ordinary MuSig2 cosigner.
 *
 *  The group behaves as one MuSig2 participant, and the finished signature is
 *  an ordinary BIP-340 signature that records nothing about the group.
 *
 *  Three roles appear below and they run different code, which is the thing
 *  worth keeping straight while reading:
 *
 *    participant  holds a share, produces a nonce and a signature share, and
 *                 never sees the whole key. There are seven of them.
 *    coordinator  moves messages around and combines them. Untrusted: every
 *                 check here assumes it is hostile.
 *    cosigner     an ordinary MuSig2 signer that knows nothing about any of
 *                 this and calls the plain musig API.
 *
 *  The participants are wiped between the two rounds and rebuilt from storage,
 *  because no secret nonce survives that gap; see reboot_participants for what
 *  does survive it, which is not nothing. One call is made that is expected to
 *  fail, in refusals_are_refused.
 *
 *  See also include/secp256k1_iceberg.h and doc/iceberg.md.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_musig.h>
#include <secp256k1_iceberg.h>
/* The trusted dealer lives in its own header, and is not part of the installed
 * API. See the note at the top of it. */
#include <secp256k1_iceberg_dealer.h>

#include "examples_util.h"

#define N 7              /* participants in the group */
#define T 3              /* how many of them can sign */
#define MU (2 * T - 1)   /* how many must take part in round one */

/* One participant's memory: one secret, and one note to itself.
 *
 * The share is the secret and never changes. `answered` is the highest session
 * label this participant has signed under. The library does not know about it and
 * could not, since it holds nothing between calls, but answering twice under one
 * label gives away the key share, so somebody has to remember, and the somebody
 * is the caller. */
struct participant {
    secp256k1_iceberg_share share;
    unsigned char answered[32];
};

/* The same participant's disk. A reboot loses the struct above, not this one,
 * and both fields have to come back. See reboot_participants. */
struct storage {
    unsigned char share_bytes[SECP256K1_ICEBERG_SHARE_MAX_LEN];
    size_t share_len;
    unsigned char answered_bytes[32];
};

/* The threshold side. Set up once, then unchanged for the life of the group. */
struct group {
    struct participant member[N];
    struct storage disk[N];
    secp256k1_iceberg_pubshare pubshare[N];
    secp256k1_pubkey pubkey;
};

/* The other side: an ordinary MuSig2 signer, which knows nothing about any of
 * the above. Everything it holds is its own, including the secret nonce that
 * the group deliberately does not have an equivalent of. */
struct cosigner {
    secp256k1_keypair keypair;
    secp256k1_pubkey pubkey;
    secp256k1_musig_secnonce secnonce;
};

/* What the two of them add up to. Computed once, at key aggregation, and the
 * only thing a verifier ever sees. */
struct shared_key {
    secp256k1_musig_keyagg_cache keyagg_cache;
    secp256k1_xonly_pubkey output;
};

/* One attempt at one signature. Everything here is public. */
struct signing_session {
    unsigned char sid[32];
    secp256k1_iceberg_pubnonce contribution[MU];
    const secp256k1_iceberg_pubnonce *contribution_ptr[MU];
    secp256k1_musig_pubnonce group_nonce;      /* the group's, after interpolating */
    secp256k1_musig_pubnonce cosigner_nonce;   /* the cosigner's, as published */
    secp256k1_musig_aggnonce cosigner_aggnonce;  /* the cosigners' alone */
    secp256k1_musig_session musig_session;
};

static void heading(const char *text) {
    printf("\n%s\n", text);
}

static void step(const char *text) {
    printf("  %-55s", text);
    fflush(stdout);
}

/* Deal the shares and publish the group's key.
 *
 * This is a trusted dealer: for the length of one call, this machine holds
 * enough to reconstruct the group's private key. Acceptable for testing, and
 * where one party is trusted already. A distributed key generation produces
 * the same shares without that moment ever existing, and this module does not
 * provide one. */
static int deal_shares(const secp256k1_context *ctx, struct group *group) {
    secp256k1_iceberg_share *share_ptr[N];
    const secp256k1_iceberg_pubshare *pubshare_ptr[N];
    unsigned char seed[32];
    unsigned int k;
    int ok;

    step("Dealing shares (secp256k1_iceberg_shares_gen)");
    if (!fill_random(seed, sizeof(seed))) {
        return 0;
    }
    for (k = 0; k < N; k++) {
        share_ptr[k] = &group->member[k].share;
    }
    ok = secp256k1_iceberg_shares_gen(ctx, share_ptr, N, T, seed);
    secure_erase(seed, sizeof(seed));
    if (!ok) {
        return 0;
    }
    printf("ok\n");

    /* A share is one seed per (t-1)-subset that leaves this participant out,
     * so it is large and grows quickly with the group. Each participant keeps
     * its own and nothing else. */
    step("Storing them (secp256k1_iceberg_share_serialize)");
    for (k = 0; k < N; k++) {
        group->disk[k].share_len = sizeof(group->disk[k].share_bytes);
        if (!secp256k1_iceberg_share_serialize(ctx, group->disk[k].share_bytes,
                                               &group->disk[k].share_len, &group->member[k].share)) {
            return 0;
        }
        /* Nothing answered yet, so the lowest possible label. Do this once, at
         * dealing; doing it again later throws the protection away. */
        memset(group->member[k].answered, 0, sizeof(group->member[k].answered));
        memcpy(group->disk[k].answered_bytes, group->member[k].answered, 32);
    }
    printf("ok, %lu bytes each\n", (unsigned long)group->disk[0].share_len);

    step("Group public key (secp256k1_iceberg_pubkey_agg)");
    for (k = 0; k < N; k++) {
        if (!secp256k1_iceberg_pubshare_gen(ctx, &group->pubshare[k], &group->member[k].share, NULL)) {
            return 0;
        }
        pubshare_ptr[k] = &group->pubshare[k];
    }
    /* 2t-1 public shares are more than the key needs, since t of them already
     * determine it, and the surplus is the point: they have to agree, so a
     * participant that published a wrong one is caught now rather than at
     * signing time. */
    if (!secp256k1_iceberg_pubkey_agg(ctx, &group->pubkey, pubshare_ptr, MU, N, T)) {
        return 0;
    }
    printf("ok\n");
    return 1;
}

/* Aggregate the group's key with the cosigner's, and tweak the result.
 *
 * Nothing below this point knows that one of the two keys is a group. The
 * tweak belongs to this outer session: musig_nonce_process sets its term aside
 * and musig_partial_sig_agg adds it once, at the top. No Iceberg call is even
 * told the tweak happened, which is what stops it being counted twice. */
static int aggregate_keys(const secp256k1_context *ctx, struct group *group, struct cosigner *cosigner, struct shared_key *shared) {
    const secp256k1_pubkey *pubkeys[2];
    secp256k1_pubkey output_pk;
    unsigned char taptweak[32];
    unsigned char seckey[32];
    int ok;

    step("Cosigner keypair (secp256k1_keypair_create)");
    ok = fill_random(seckey, sizeof(seckey))
         && secp256k1_keypair_create(ctx, &cosigner->keypair, seckey)
         && secp256k1_keypair_pub(ctx, &cosigner->pubkey, &cosigner->keypair);
    /* The keypair holds everything needed from here on, so the raw key does not
     * outlive this call; secp256k1_keypair_sec brings it back when required. */
    secure_erase(seckey, sizeof(seckey));
    if (!ok) {
        return 0;
    }
    printf("ok\n");

    step("Aggregating (secp256k1_musig_pubkey_agg)");
    pubkeys[0] = &group->pubkey;
    pubkeys[1] = &cosigner->pubkey;
    if (!secp256k1_musig_pubkey_agg(ctx, NULL, &shared->keyagg_cache, pubkeys, 2)) {
        return 0;
    }
    printf("ok\n");

    /* The cache records the hash of the key list, not the list, so nothing ties
     * it to the group's key later. Run this once, here, rather than trusting a
     * cache round two cannot check. */
    step("Checking the cache (secp256k1_iceberg_keyagg_check)");
    if (!secp256k1_iceberg_keyagg_check(ctx, &shared->keyagg_cache, pubkeys, 2,
                                        &group->pubkey)) {
        return 0;
    }
    printf("ok\n");

    step("Tweaking (secp256k1_musig_pubkey_xonly_tweak_add)");
    if (!fill_random(taptweak, sizeof(taptweak))
        || !secp256k1_musig_pubkey_xonly_tweak_add(ctx, &output_pk, &shared->keyagg_cache, taptweak)
        || !secp256k1_xonly_pubkey_from_pubkey(ctx, &shared->output, NULL, &output_pk)) {
        return 0;
    }
    printf("ok\n");
    return 1;
}

/* Round one, the group's half. Note the arguments: a share and a label. No
 * message, no cosigner, nothing from anybody else. */
static int group_round_one(const secp256k1_context *ctx, struct group *group,
                           struct signing_session *session) {
    unsigned int k;

    /* The label is the most delicate value in the scheme, and it is the
     * caller's to choose. Every participant's secret nonces are a function of
     * (its seeds, this label), and the seeds never change, so whoever picks the
     * label picks everyone's secrets.
     *
     * Here it is a fixed byte string, which is fine for an example and wrong
     * for anything else. In Lightning it is the commitment number: unique,
     * strictly increasing over the channel's life, and known before the
     * transaction is assembled, which is what lets this round run at all,
     * since the message does not exist yet. */
    step("Choosing the session label");
    memset(session->sid, 0x2c, sizeof(session->sid));
    printf("ok, ");
    print_hex(session->sid, 4);

    step("Participant nonces (secp256k1_iceberg_nonce_gen)");
    for (k = 0; k < MU; k++) {
        if (!secp256k1_iceberg_nonce_gen(ctx, &session->contribution[k], &group->member[k].share, NULL, session->sid)) {
            return 0;
        }
        session->contribution_ptr[k] = &session->contribution[k];
    }
    printf("ok, %d of the %d participants\n", MU, N);

    /* Verification, not addition. The contributions are points on a degree
     * t-1 polynomial in the exponent; this checks that they lie on one and
     * then interpolates. It is most of what the group costs, and it is what
     * stops a single participant biasing the group's nonce.
     *
     * NULL is the group's internal aggregate, which nothing takes back. */
    step("Combining them (secp256k1_iceberg_nonce_agg)");
    if (!secp256k1_iceberg_nonce_agg(ctx, &session->group_nonce, NULL,
                                     session->contribution_ptr, MU, N, T, &group->pubkey)) {
        return 0;
    }
    printf("ok\n");
    return 1;
}

/* Round one, the cosigner's half. Ordinary MuSig2, and it does not know a group
 * exists. Runs before, after or alongside the function above. */
static int cosigner_round_one(const secp256k1_context *ctx, struct cosigner *cosigner, struct shared_key *shared,
                              struct signing_session *session, const unsigned char *msg32) {
    const secp256k1_musig_pubnonce *just_the_cosigner[1];
    unsigned char secrand[32];
    unsigned char seckey[32];
    int ok;

    step("Cosigner nonce (secp256k1_musig_nonce_gen)");
    ok = fill_random(secrand, sizeof(secrand))
         && secp256k1_keypair_sec(ctx, seckey, &cosigner->keypair)
         && secp256k1_musig_nonce_gen(ctx, &cosigner->secnonce, &session->cosigner_nonce,
                                      secrand, seckey, &cosigner->pubkey,
                                      msg32, &shared->keyagg_cache, NULL);
    secure_erase(secrand, sizeof(secrand));
    secure_erase(seckey, sizeof(seckey));
    if (!ok) {
        return 0;
    }

    /* Round two needs the cosigners' aggregate on its own, separately from the
     * one that includes the group. With one cosigner it is an aggregate of one,
     * which is not a special case anywhere. */
    just_the_cosigner[0] = &session->cosigner_nonce;
    if (!secp256k1_musig_nonce_agg(ctx, &session->cosigner_aggnonce, just_the_cosigner, 1)) {
        return 0;
    }
    printf("ok\n");
    return 1;
}

/* Both halves have published. Combine them into the session everybody signs
 * against, which is where the message finally enters. */
static int open_session(const secp256k1_context *ctx, struct shared_key *shared,
                        struct signing_session *session, const unsigned char *msg32) {
    const secp256k1_musig_pubnonce *both[2];
    secp256k1_musig_aggnonce full_aggnonce;

    step("Session (secp256k1_musig_nonce_process)");
    both[0] = &session->group_nonce;
    both[1] = &session->cosigner_nonce;
    if (!secp256k1_musig_nonce_agg(ctx, &full_aggnonce, both, 2)
        || !secp256k1_musig_nonce_process(ctx, &session->musig_session, &full_aggnonce,
                                          msg32, &shared->keyagg_cache)) {
        return 0;
    }
    printf("ok\n");
    return 1;
}

/* Forget the secret nonces, then rebuild from disk.
 *
 * A FROST signer has to keep a secret nonce alive across this line, and losing
 * it, restoring an old backup over it, or running two copies of the signer are
 * each catastrophic. An Iceberg participant keeps no secret nonce at all: its
 * nonces are a function of its share and the label, both of which it is given
 * again.
 *
 * That property is narrower than "keeps no state".
 * A participant still has to remember which labels it has already answered
 * under, because two answers under one label are two equations in its three
 * secrets and three are enough to recover its key share. That bookkeeping is
 * not secret, and it is not optional; it is simply not this library's, since
 * only the group as a whole can decide which message a label belongs to.
 *
 * So wipe the secrets and prove that much. Skip the parse below and the next
 * call is handed a wiped share, whose magic fails an ARG_CHECK, so it aborts
 * through the illegal callback rather than returning 0. */
static int reboot_participants(const secp256k1_context *ctx, struct group *group) {
    unsigned int k;

    step("Wiping every participant's secret material");
    for (k = 0; k < N; k++) {
        secure_erase(&group->member[k], sizeof(group->member[k]));
    }
    printf("ok\n");

    step("Rebuilding (secp256k1_iceberg_share_parse)");
    for (k = 0; k < N; k++) {
        if (!secp256k1_iceberg_share_parse(ctx, &group->member[k].share,
                                           group->disk[k].share_bytes,
                                           group->disk[k].share_len)) {
            return 0;
        }
        memcpy(group->member[k].answered, group->disk[k].answered_bytes, 32);
    }
    printf("ok\n");

    /* Note what came back besides the share: `answered`. That record is not
     * secret, which is why it sits on the same disk in the clear, and it is
     * not optional, which is why it is restored here rather than left at zero.
     * A participant that forgets it will answer twice. */
    return 1;
}

/* One label, one answer: the half of the rule a participant can enforce alone.
 *
 * The library cannot do this for you. It holds nothing between calls, so "have I
 * answered under this label before?" is a question only the caller's storage can
 * answer. Here that storage is one 32-byte field per participant and the rule is
 * that a label must be strictly greater than the last one signed under, which is
 * free when the label is a counter. It refuses a repeat outright rather than
 * asking whether the repeat was harmless: a label is one signing attempt, so an
 * honest retry arrives under a new label and never needs the exception.
 *
 * The record reaches disk here, before the caller has a share to publish. A
 * crash between signing and storing is the same as never having stored, and the
 * next boot answers the label again.
 *
 * The other half of the rule, that no two participants answer one label on
 * different messages, cannot be checked here or anywhere else inside a
 * participant, because it is a fact about what other people were shown. See
 * doc/iceberg.md. */
static int may_sign_under(struct participant *member, struct storage *disk, const unsigned char *sid32) {
    if (memcmp(sid32, member->answered, 32) <= 0) {
        return 0;
    }
    memcpy(member->answered, sid32, 32);
    memcpy(disk->answered_bytes, member->answered, 32);
    return 1;
}

/* The group's half of round two, signed by participants first, first+1 and
 * first+2.
 *
 * Taking `first` is not generality for its own sake. The point of the scheme is
 * that any t of them will do, so main runs this twice with different people and
 * compares the two signatures.
 *
 * Any t of the seven, and not only the five who were in round one. The last
 * section of main proves that by having a participant who sat round one out
 * sign anyway. What each signer does need is the whole round-one set to check
 * against, which is a different count from the number of signers. */
static int group_signs(const secp256k1_context *ctx, struct group *group,
                       struct shared_key *shared, struct signing_session *session,
                       unsigned int first, const unsigned char *msg32,
                       secp256k1_musig_partial_sig *group_partial_sig) {
    secp256k1_iceberg_partial_sig sig_share[T];
    const secp256k1_iceberg_partial_sig *sig_share_ptr[T];
    unsigned int k;

    /* Note what this takes: the group's own round-one contributions, not an
     * aggregate of them, and not the cosigners', which arrive separately and
     * already aggregated. Do not read that as an optimization waiting to happen.
     * The nesting coefficient is a hash of the group's aggregate nonce, so a
     * coordinator free to invent that aggregate has a coefficient it can vary at
     * will, and three invented aggregates under one label give three equations in
     * the same three unknowns, and the third is the key. So the aggregate is
     * derived here from the contributions instead. */
    step("Signature shares (secp256k1_iceberg_partial_sign)");
    for (k = 0; k < T; k++) {
        if (!may_sign_under(&group->member[first + k], &group->disk[first + k], session->sid)) {
            printf("refused: participant %d has already answered under this label\n",
                   first + k + 1);
            return 0;
        }
        /* The signer derives the aggregate from the contributions, then checks
         * the polynomial they determine against the contribution it derives for
         * itself, which ties the set to this label. It need not have been one of
         * the contributors. */
        if (!secp256k1_iceberg_partial_sign(ctx, &sig_share[k], &group->member[first + k].share, NULL,
                                            session->sid, session->contribution_ptr, MU,
                                            &group->pubkey, &shared->keyagg_cache,
                                            msg32, &session->cosigner_aggnonce)) {
            return 0;
        }
        sig_share_ptr[k] = &sig_share[k];
    }
    printf("ok, from participants %d, %d and %d\n", first + 1, first + 2, first + 3);

    /* Optional, and the coordinator's to decide on. Skipping it costs nothing
     * until a share is bad, at which point the final signature simply fails
     * BIP-340 and says nothing about which of the three caused it. Checking
     * costs about what producing a share costs, per share.
     *
     * That is with exactly t shares, which is what this collects. Hand
     * secp256k1_iceberg_partial_sig_agg one more than it needs and it refuses a
     * set that disagrees with itself, cheaply and without naming anybody, for
     * the same reason pubkey_agg can above: past the threshold there is a spare
     * point to check against.
     *
     * It answers "is this share bad", not "who is lying". A share that fails
     * here may have been written by somebody other than the member it names,
     * and the same 0 comes back if this machine has the wrong message. */
    step("Checking them (secp256k1_iceberg_partial_sig_verify)");
    for (k = 0; k < T; k++) {
        if (!secp256k1_iceberg_partial_sig_verify(ctx, &sig_share[k], &group->pubshare[first + k],
                                                  session->contribution_ptr, MU, N, T,
                                                  &group->pubkey, &shared->keyagg_cache, msg32,
                                                  &session->cosigner_aggnonce)) {
            printf("share from participant %d does not check out\n", first + k + 1);
            return 0;
        }
    }
    printf("ok, all %d\n", T);

    step("Combining (secp256k1_iceberg_partial_sig_agg)");
    if (!secp256k1_iceberg_partial_sig_agg(ctx, group_partial_sig, sig_share_ptr, T, N, T)) {
        return 0;
    }
    printf("ok\n");
    return 1;
}

/* The cosigner's half, which happens exactly once.
 *
 * secp256k1_musig_partial_sign consumes the secret nonce, zeroing it on
 * the way out, precisely so that signing twice with it is not something a
 * caller can do by accident. Which quorum the group fielded is not the
 * cosigner's business and does not change its answer. */
static int cosigner_signs(const secp256k1_context *ctx, struct cosigner *cosigner,
                          struct shared_key *shared, struct signing_session *session,
                          secp256k1_musig_partial_sig *cosigner_partial_sig) {
    step("Cosigner's share (secp256k1_musig_partial_sign)");
    if (!secp256k1_musig_partial_sign(ctx, cosigner_partial_sig, &cosigner->secnonce,
                                      &cosigner->keypair, &shared->keyagg_cache,
                                      &session->musig_session)) {
        return 0;
    }
    printf("ok\n");
    return 1;
}

/* One group share plus one cosigner share makes an ordinary MuSig2 signature. */
static int combine(const secp256k1_context *ctx, struct signing_session *session,
                   const secp256k1_musig_partial_sig *group_partial_sig,
                   const secp256k1_musig_partial_sig *cosigner_partial_sig,
                   unsigned char *sig64) {
    const secp256k1_musig_partial_sig *both[2];

    step("Final signature (secp256k1_musig_partial_sig_agg)");
    both[0] = group_partial_sig;
    both[1] = cosigner_partial_sig;
    if (!secp256k1_musig_partial_sig_agg(ctx, sig64, &session->musig_session, both, 2)) {
        return 0;
    }
    printf("ok\n");
    return 1;
}

/* One call that must be refused and one that must not, with the reason beside
 * each.
 *
 * The refusal below is a load-bearing security check that looks like a bug from
 * outside; the call after it is the case that looks refusable and must not
 * be. */
static int refusals_are_refused(const secp256k1_context *ctx, struct group *group,
                                struct shared_key *shared, struct signing_session *session,
                                const unsigned char *msg32) {
    secp256k1_iceberg_partial_sig sig_share;

    step("Signing over contributions from another session");
    {
        /* The contributions below are a real sharing, internally consistent
         * and passing the degree check, but they were produced under a
         * different label. Accepting them would give whoever supplied them a
         * coefficient in the signing equation that this participant cannot
         * check, which is worth a signature share to an adversary and nothing
         * to anybody else.
         *
         * The signer catches it by interpolating the contributions and
         * evaluating the result at its own index: the polynomial does not pass
         * through the contribution it derives locally for the label it is
         * signing under. */
        secp256k1_iceberg_pubnonce elsewhere[MU];
        const secp256k1_iceberg_pubnonce *elsewhere_ptrs[MU];
        unsigned char other_sid[32];
        unsigned int k;

        memcpy(other_sid, session->sid, sizeof(other_sid));
        other_sid[0] ^= 1;
        for (k = 0; k < MU; k++) {
            if (!secp256k1_iceberg_nonce_gen(ctx, &elsewhere[k], &group->member[k].share,
                                             NULL, other_sid)) {
                return 0;
            }
            elsewhere_ptrs[k] = &elsewhere[k];
        }
        /* The set is a perfectly good sharing. What it is not is a sharing of
         * *this* label, and only the signer can tell, because only the signer
         * holds the share that says what its own contribution should have
         * been. */
        if (secp256k1_iceberg_partial_sign(ctx, &sig_share, &group->member[0].share, NULL,
                                           session->sid, elsewhere_ptrs, MU, &group->pubkey,
                                           &shared->keyagg_cache, msg32,
                                           &session->cosigner_aggnonce)) {
            printf("FAILED: it signed, and it should not have\n");
            return 0;
        }
    }
    printf("refused, correctly\n");

    /* The other half of that check is a thing it must NOT cost. */
    step("Signing by a member who sat round one out");
    {
        /* Participants 6 and 7 were not among the 2t-1 who produced nonces.
         * They can still sign, because a contribution is a function of the
         * share and the label, so an absent member can derive what its
         * contribution would have been and check the polynomial against it
         * without ever having been one of the contributors.
         *
         * This is the property that lets a quorum change between the rounds,
         * which is most of why the scheme works this way: keys sit in
         * cold storage and members are routinely absent rather than hostile. */
        if (!secp256k1_iceberg_partial_sign(ctx, &sig_share, &group->member[N - 1].share, NULL,
                                            session->sid, session->contribution_ptr, MU,
                                            &group->pubkey, &shared->keyagg_cache, msg32,
                                            &session->cosigner_aggnonce)) {
            printf("FAILED: it refused, and it should not have\n");
            return 0;
        }
    }
    printf("signed, correctly\n");
    return 1;
}

static void print_caveats(void) {
    heading("WHAT THIS EXAMPLE IS NOT");
    printf("  A trusted dealer deals the shares. Real deployments want a\n");
    printf("  distributed key generation, which this module does not provide.\n");
    printf("\n");
    printf("  Everything is passed as structs in one process. The wire formats\n");
    printf("  exist: 34 bytes for a public share, 67 for a nonce contribution,\n");
    printf("  33 for a signature share. Nothing here uses them, so the\n");
    printf("  network is the part you still have to write.\n");
    printf("\n");
    printf("  Structs in one process also satisfy constraint 2 for free. Over a\n");
    printf("  network the channel must be authenticated and a contribution taken\n");
    printf("  only from the member its index names; without that, an adversary\n");
    printf("  supplying t of the 2t-1 picks the group's nonce and every check\n");
    printf("  here still passes.\n");
    printf("\n");
    printf("  Verifying a share tells you whether it satisfies the equation,\n");
    printf("  not who is at fault: partial signatures are forgeable, so a share\n");
    printf("  that fails may have been written by somebody else.\n");
    printf("\n");
    printf("  may_sign_under above is half the rule, and the easy half: it\n");
    printf("  stops one participant answering twice. Nothing anywhere stops two\n");
    printf("  participants answering one label on different messages. Two answers\n");
    printf("  under one label are two equations in a participant's three\n");
    printf("  secrets; three recover its key share.\n");
    printf("\n");
    printf("  The label is an argument, rather than something derived from the\n");
    printf("  message, because round one has to run before the message exists.\n");
    printf("  In Lightning the nonce is fixed a round-trip before the\n");
    printf("  transaction is assembled, and the commitment number is what\n");
    printf("  Lightning supplies instead.\n");
    printf("\n");
    printf("  So half of that discipline is yours, never answering twice under\n");
    printf("  one label, and half is the group's: agree which message a label\n");
    printf("  belongs to before anyone answers. The unforgeability proof, which\n");
    printf("  is not yet peer-reviewed, assumes both. See doc/iceberg.md.\n");
}

int main(void) {
    secp256k1_context *ctx;
    struct group group;
    struct cosigner cosigner;
    struct shared_key shared;
    struct signing_session session;
    unsigned char msg[32] = "this_could_be_the_hash_of_a_msg";
    secp256k1_musig_partial_sig group_partial_sig, cosigner_partial_sig;
    unsigned char sig[64], sig_from_the_others[64];
    unsigned int k;
    int ok;

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    printf("Iceberg: a %d-of-%d group signing as one MuSig2 participant.\n\n", T, N);
    printf("  round one needs %d of the %d participants; round two needs %d\n", MU, N, MU);
    printf("  online again, not necessarily the same ones, and combines %d\n", T);
    printf("  signature shares. See doc/iceberg.md for why those differ.\n");

    heading("Setup: once, by a dealer who is then not needed again");
    ok = deal_shares(ctx, &group);

    if (ok) {
        heading("Key aggregation: the group is now just a public key");
        ok = aggregate_keys(ctx, &group, &cosigner, &shared);
    }
    if (ok) {
        /* The two halves are written in this order because something has to
         * go first on the page. Swap the two calls and the example still
         * passes, since neither needs anything the other produces, which is why
         * two Iceberg groups can sign with each other. */
        heading("Round one: needs 2t-1 participants, in no particular order");
        ok = group_round_one(ctx, &group, &session)
             && cosigner_round_one(ctx, &cosigner, &shared, &session, msg)
             && open_session(ctx, &shared, &session, msg);
    }
    if (ok) {
        heading("The gap: every participant forgets its secret nonces");
        ok = reboot_participants(ctx, &group);
    }
    if (ok) {
        heading("Round two: t shares, from any members, not just round one's");
        ok = group_signs(ctx, &group, &shared, &session, 0, msg, &group_partial_sig)
             && cosigner_signs(ctx, &cosigner, &shared, &session, &cosigner_partial_sig)
             && combine(ctx, &session, &group_partial_sig, &cosigner_partial_sig, sig);
    }
    if (ok) {
        step("Verifying (secp256k1_schnorrsig_verify)");
        ok = secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &shared.output);
        if (ok) {
            printf("ok\n    ");
            print_hex(sig, sizeof(sig));
            printf("    An ordinary BIP-340 signature. Nothing in it records a group.\n");
        }
    }
    if (ok) {
        heading("The same signature, from different people");
        /* Participants 4, 5 and 6 this time, with no overlap with 1, 2 and 3, and
         * 6 was not in round one either. Both of those matter. Disjoint,
         * because nobody may answer twice under one label. The library holds
         * nothing between calls and cannot detect that, so may_sign_under above
         * is what refuses it. And 6 absent from round one, because a member that
         * was away can still work out what its contribution would have been.
         *
         * Only the group signs again. The cosigner's share is reused, since it
         * has one secret nonce and spending it twice would be nonce reuse. */
        ok = group_signs(ctx, &group, &shared, &session, T, msg, &group_partial_sig)
             && combine(ctx, &session, &group_partial_sig, &cosigner_partial_sig, sig_from_the_others);
    }
    if (ok) {
        step("Comparing the two signatures");
        ok = memcmp(sig, sig_from_the_others, sizeof(sig)) == 0;
        printf(ok ? "byte-identical\n" : "the two quorums disagreed\n");
    }
    if (ok) {
        heading("What the module checks, and what it leaves to you");
        ok = refusals_are_refused(ctx, &group, &shared, &session, msg);
    }
    if (!ok) {
        printf("FAILED\n");
    }
    print_caveats();

    /* Clear the secrets: a bug elsewhere that leaks memory, or an OS that swaps
     * it to disk, should not find them lying around. The group's shares are the
     * long-term secret here, and the cosigner's keypair and secret nonce are
     * the rest. */
    for (k = 0; k < N; k++) {
        secure_erase(&group.member[k], sizeof(group.member[k]));
        secure_erase(&group.disk[k], sizeof(group.disk[k]));
    }
    secure_erase(&cosigner, sizeof(cosigner));
    secp256k1_context_destroy(ctx);
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
