#!/usr/bin/env python3
"""Generate src/modules/iceberg/vectors.h from the Python reference.

    git clone https://github.com/nkohen/Iceberg.git
    git -C Iceberg checkout 7b55ef6dc0dd6e11d1c14cb3bc0a675ff3487cce
    ./tools/test_vectors_iceberg_generate.py Iceberg > src/modules/iceberg/vectors.h

That commit is "Fixed nonce generation security", Nadav Kohen, 12 January 2026.
It is named here because vectors.h is the only thing in this repository that
cannot be rebuilt from what the repository contains, and because a dozen comments
in the module assert agreement with "the reference" as a correctness property. The
reference is not vendored: it is not ours, and pinning a copy would hide it
drifting.

There are no published test vectors for Iceberg, so these are produced by
running the reference implementation and recording what it does. That makes
them a cross-implementation check and not an authority: if both implementations
are wrong in the same way, these vectors agree with the mistake. What they do
catch is the case that matters most here, where one of the two drifts.

Two things about the reference have to be worked around, and both are recorded
in its own notes:

  * eval_lagrange removes an element from the set it is passed, which is the
    caller's set. Anything calling it twice with the same set gets a different
    answer the second time. Every call below hands it a copy.

  * all_lagrange_coefficients does polynomial division in numpy float64. It is
    correct up to a quorum of 18 and silently wrong from 19, because the
    constant term of the product is the quorum's factorial and 19! is past
    2^53. It is replaced below with exact integer arithmetic.

The seeds are derived from a fixed string rather than taken from the reference's
own key_gen, which uses the system random source. That is what makes the vectors
reproducible; it also means the seeds have to be laid out in the same order the
C module expects, which is lexicographic order of the (t-1)-subsets.
"""

import hashlib
import itertools
import sys
import textwrap


def combinations_in_rank_order(n, size):
    """The subsets, in the order secp256k1_rss_subset_unrank produces them.

    That function walks the members upward and takes a binomial-sized block at
    each step, which is plain lexicographic order on the ascending member list,
    the same order itertools produces. The whole seed layout depends on it.
    """
    return [set(c) for c in itertools.combinations(range(1, n + 1), size)]


def exact_lagrange_coefficients(indices, modulus):
    """all_lagrange_coefficients, over the integers instead of float64.

    For each j, the basis polynomial that is 1 at j and 0 at every other index,
    as coefficients from the constant term upward.

    A guard rather than a fix: the largest configuration below has a quorum of
    9, where the reference's float64 path is still exact, so this changes no
    emitted byte today. It is what keeps that true if a larger one is added.
    """
    def poly_mul(a, b):
        out = [0] * (len(a) + len(b) - 1)
        for i, x in enumerate(a):
            for j, y in enumerate(b):
                out[i + j] = (out[i + j] + x * y) % modulus
        return out

    def poly_eval(coeffs, x):
        total = 0
        for c in reversed(coeffs):
            total = (total * x + c) % modulus
        return total

    result = {}
    for j in sorted(indices):
        basis = [1]
        for index in sorted(indices):
            if index != j:
                basis = poly_mul(basis, [(-index) % modulus, 1])
        inverse = pow(poly_eval(basis, j), -1, modulus)
        result[j] = [(c * inverse) % modulus for c in basis]
    return result


def hexbytes(data, indent):
    """A C initializer for a byte array, wrapped to fit."""
    body = ", ".join("0x%02X" % b for b in data)
    return textwrap.fill(body, width=78 - indent,
                         initial_indent=" " * indent,
                         subsequent_indent=" " * indent)


class Session:
    """One configuration, dealt and signed once, with everything recorded."""

    def __init__(self, iceberg, vpss, musig, label, n_parties, t):
        self.label = label
        self.n = n_parties
        self.t = t
        self.mu = 2 * t - 1
        self.iceberg = iceberg
        self.vpss = vpss
        self.musig = musig
        self._deal()
        self._aggregate()
        self._round_one()
        self._round_two()

    def _seed(self, rank):
        material = "iceberg test vectors|%s|%d" % (self.label, rank)
        return hashlib.sha256(material.encode()).digest()

    def _deal(self):
        """One seed per (t-1)-subset, in rank order, then the shares.

        Only the seeds go into the header. Each is held by n-(t-1)
        participants, so writing out every share would repeat most of them;
        the C side rebuilds each share from the same rank order.
        """
        subsets = combinations_in_rank_order(self.n, self.t - 1)
        self.seeds = [self._seed(rank) for rank in range(len(subsets))]

        self.shares = {}
        for k in range(1, self.n + 1):
            mine = [(seed, subset) for seed, subset in zip(self.seeds, subsets)
                    if k not in subset]
            self.shares[k] = self.vpss.RSSShare(
                [self.vpss.RSSSummand(seed, subset) for seed, subset in mine])

    def _aggregate(self):
        self.pubshares = {}
        for k in range(1, self.n + 1):
            _, pk_k = self.iceberg.key_gen(k, self.shares[k])
            self.pubshares[k] = pk_k
        quorum = [self.vpss.VPSSCommitment(k, self.pubshares[k])
                  for k in range(1, self.mu + 1)]
        self.group_pk = self.iceberg.pk_agg(self.t, self.mu, quorum)

    def _session_label(self):
        """A session label for this vector.

        The module takes any 32 bytes here, so this is an arbitrary but
        reproducible choice, not a derivation the scheme requires. Changing the
        rule changes every nonce and signature below it.
        """
        keyagg = self.musig.key_agg([self.group_pk, self.cosigner_pk])
        agg_pk32 = self.musig.bytes_from_int(self.musig.x(keyagg.Q))
        preimage = agg_pk32 + self.group_pk + b"".join(
            self.cosigner_pubnonce[33 * i:33 * (i + 1)] for i in (0, 1))
        return self.musig.tagged_hash("Iceberg/sid", self.msg + preimage)

    def _round_one(self):
        """A cosigner whose nonce and key are fixed, so this is reproducible."""
        self.msg = hashlib.sha256(("message|" + self.label).encode()).digest()

        cosigner_sk = hashlib.sha256(("cosigner|" + self.label).encode()).digest()
        self.cosigner_pk = self.musig.individual_pk(cosigner_sk)
        halves = [hashlib.sha256(("cosigner nonce %d|%s" % (i, self.label)).encode()).digest()
                  for i in (1, 2)]
        self.cosigner_pubnonce = b"".join(
            self.musig.cbytes(self.musig.point_mul(
                self.musig.G, self.musig.int_from_bytes(h) % self.musig.n))
            for h in halves)

        self.sid = self._session_label()

        self.pubnonces = {}
        for k in range(1, self.n + 1):
            _, pubnonce_k = self.iceberg.nonce_gen(k, self.shares[k], self.sid)
            self.pubnonces[k] = pubnonce_k

        quorum = [(k, self.pubnonces[k]) for k in range(1, self.mu + 1)]
        self.group_aggnonce = self.iceberg.nonce_agg(self.t, self.mu, quorum)
        self.group_pubnonce = self.iceberg.nonce_agg_ext(self.group_pk,
                                                         self.group_aggnonce)

    def _round_two(self):
        pubkeys = [self.group_pk, self.cosigner_pk]
        aggnonce = self.musig.nonce_agg([self.group_pubnonce, self.cosigner_pubnonce])
        upper = self.musig.SessionContext(aggnonce, pubkeys, [], [], self.msg)

        self.psigs = {}
        for k in range(1, self.t + 1):
            self.psigs[k] = self.iceberg.sign(k, self.shares[k], self.group_pk,
                                              self.sid, self.group_aggnonce, upper)
        self.group_psig = self.iceberg.sign_agg(
            [(k, self.psigs[k]) for k in range(1, self.t + 1)])

    def emit(self, out):
        out.append("    {")
        out.append('        "%s", %d, %d, %d, %d,'
                   % (self.label, self.n, self.t, self.mu, len(self.seeds)))
        out.append("        { /* one seed per (t-1)-subset, in rank order */")
        for seed in self.seeds:
            out.append("            {")
            out.append(hexbytes(seed, 16))
            out.append("            },")
        out.append("        },")
        for name, blob in (("group_pk", self.group_pk),
                           ("msg", self.msg),
                           ("sid", self.sid),
                           ("cosigner_pk", self.cosigner_pk),
                           ("cosigner_pubnonce", self.cosigner_pubnonce),
                           ("group_aggnonce", self.group_aggnonce),
                           ("group_pubnonce", self.group_pubnonce),
                           ("group_psig", self.group_psig)):
            out.append("        { /* %s */" % name)
            out.append(hexbytes(blob, 12))
            out.append("        },")
        out.append("        { /* pubshares, participant 1 first */")
        for k in range(1, self.n + 1):
            out.append("            {")
            out.append(hexbytes(self.pubshares[k], 16))
            out.append("            },")
        out.append("        },")
        out.append("        { /* pubnonces, the mu participants of round one */")
        for k in range(1, self.mu + 1):
            out.append("            {")
            out.append(hexbytes(self.pubnonces[k], 16))
            out.append("            },")
        out.append("        },")
        out.append("        { /* signature shares, the first t participants */")
        for k in range(1, self.t + 1):
            out.append("            {")
            out.append(hexbytes(self.psigs[k], 16))
            out.append("            },")
        out.append("        },")
        out.append("    },")


HEADER = """/**
 * Note: this file was autogenerated using test_vectors_iceberg_generate.py.
 * Do not edit. To regenerate:
 *
 *   git clone https://github.com/nkohen/Iceberg.git
 *   git -C Iceberg checkout 7b55ef6dc0dd6e11d1c14cb3bc0a675ff3487cce
 *   ./tools/test_vectors_iceberg_generate.py Iceberg > src/modules/iceberg/vectors.h
 *
 * There are no published Iceberg test vectors. These record what the reference
 * does, so they catch the two implementations drifting apart, not a mistake
 * they might both make. That makes this the one file here that cannot be rebuilt
 * from what this repository contains, which is why the commit is named.
 */

#include <stddef.h>

#define ICEBERG_VECTOR_MAX_PARTICIPANTS %d
#define ICEBERG_VECTOR_MAX_SEEDS %d

struct iceberg_session_vector {
    const char *label;
    unsigned int n;
    unsigned int t;
    unsigned int mu;
    size_t n_seeds;
    unsigned char seeds[ICEBERG_VECTOR_MAX_SEEDS][32];
    unsigned char group_pk[33];
    unsigned char msg[32];
    unsigned char sid[32];
    unsigned char cosigner_pk[33];
    unsigned char cosigner_pubnonce[66];
    unsigned char group_aggnonce[66];
    unsigned char group_pubnonce[66];
    unsigned char group_psig[32];
    unsigned char pubshares[ICEBERG_VECTOR_MAX_PARTICIPANTS][33];
    unsigned char pubnonces[ICEBERG_VECTOR_MAX_PARTICIPANTS][66];
    unsigned char psigs[ICEBERG_VECTOR_MAX_PARTICIPANTS][32];
};

static const struct iceberg_session_vector iceberg_session_vectors[] = {"""


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 1
    sys.path.insert(0, sys.argv[1])

    import musig
    import vpss
    import iceberg

    # Both workarounds described at the top of this file. They are installed
    # before anything runs, so nothing below can accidentally use the originals.
    original_eval = vpss.eval_lagrange
    vpss.eval_lagrange = lambda indices, excluding, eval_at, modulus=musig.n: \
        original_eval(set(indices), excluding, eval_at, modulus)
    iceberg.eval_lagrange = vpss.eval_lagrange
    vpss.all_lagrange_coefficients = lambda indices, modulus=musig.n: \
        exact_lagrange_coefficients(indices, modulus)

    configs = [("2of3", 3, 2), ("3of5", 5, 3), ("3of7", 7, 3),
               ("4of7", 7, 4), ("5of9", 9, 5)]
    sessions = [Session(iceberg, vpss, musig, *config) for config in configs]

    widest = max(s.n for s in sessions)
    most_seeds = max(len(s.seeds) for s in sessions)

    out = [HEADER % (widest, most_seeds)]
    for session in sessions:
        session.emit(out)
    out.append("};")
    out.append("")
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
