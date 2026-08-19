/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "secp256k1.c"
#include "../include/secp256k1.h"
#include "util.h"
#include "bench.h"
#include "modules/iceberg/bench_impl.h"

/* Small sizes, spread out enough to show the growth curve. These are not
 * deployment recommendations: all five are below the n >= 3t-2 that the
 * agreement around the scheme needs, and 4-of-7 versus 5-of-9 is here because
 * the seed count roughly triples between them, not because anyone runs it. */
static const unsigned int CONFIGS[][2] = { {3,2}, {5,3}, {7,4}, {9,5}, {10,5} };

int main(int argc, char **argv) {
    bench_iceberg_data data;
    int iters = get_iters(1000);
    size_t c;

    (void)argc; (void)argv;
    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    printf("%-22s", "");
    for (c = 0; c < sizeof(CONFIGS)/sizeof(CONFIGS[0]); c++) {
        char label[16];
        sprintf(label, "%u-of-%u", CONFIGS[c][1], CONFIGS[c][0]);
        printf("%12s", label);
    }
    printf("\n");
    printf("%-22s", "seeds per participant");
    for (c = 0; c < sizeof(CONFIGS)/sizeof(CONFIGS[0]); c++) {
        printf("%12u", secp256k1_rss_binom(CONFIGS[c][0] - 1, CONFIGS[c][1] - 1));
    }
    printf("\n\n");

    {
        /* per_sig marks the rows a signing session actually pays for, so the
         * total at the bottom comes from the same run as the rows above it
         * rather than from someone adding them up by hand. */
        struct { const char *name; void (*fn)(void*, int); int per_sig; const char *note; } benches[] = {
            { "shares_gen",        bench_iceberg_shares_gen,      0, "   (setup only)" },
            { "share_cache_create",bench_iceberg_cache_create,    0, "   (setup only)" },
            { "pubshare_gen",      bench_iceberg_pubshare_gen,    0, "   (setup only)" },
            { "pubkey_agg",        bench_iceberg_pubkey_agg,      0, "   (setup only)" },
            { "nonce_gen",         bench_iceberg_nonce_gen,       1, "" },
            { "nonce_agg",         bench_iceberg_nonce_agg,       1, "" },
            { "partial_sign",      bench_iceberg_partial_sign,    1, "" },
            { "partial_sig_agg",   bench_iceberg_partial_sig_agg, 1, "" },
            { "partial_sig_verify",bench_iceberg_partial_sig_verify, 0, "   (optional, per share)" },
            { "  degree_check",    bench_iceberg_degree_check,    0, "   (inside nonce_agg, partial_sign and partial_sig_verify)" },
            { "  interpolate",     bench_iceberg_interpolate,     0, "   (inside nonce_agg, partial_sign and partial_sig_verify)" },
            { "    lagrange_basis", bench_iceberg_lagrange_basis, 0, "   (inside degree_check)" }
        };
        double per_signature[sizeof(CONFIGS)/sizeof(CONFIGS[0])] = { 0 };
        size_t b;
        for (b = 0; b < sizeof(benches)/sizeof(benches[0]); b++) {
            printf("%-22s", benches[b].name);
            for (c = 0; c < sizeof(CONFIGS)/sizeof(CONFIGS[0]); c++) {
                int64_t begin, total;
                double each;
                int i;
                data.n = CONFIGS[c][0];
                data.t = CONFIGS[c][1];
                data.mu = 2 * data.t - 1;
                bench_iceberg_setup(&data);
                benches[b].fn(&data, 2);            /* warm up */
                begin = gettime_i64();
                for (i = 0; i < iters; i++) {
                    benches[b].fn(&data, 1);
                }
                total = gettime_i64() - begin;
                each = (double)total / iters;
                if (benches[b].per_sig) {
                    per_signature[c] += each;
                }
                printf("%9.1f us", each);
            }
            printf("%s\n", benches[b].note);
        }

        printf("\n%-22s", "per signature");
        for (c = 0; c < sizeof(CONFIGS)/sizeof(CONFIGS[0]); c++) {
            printf("%9.1f us", per_signature[c]);
        }
        printf("\n");
    }

    secp256k1_context_destroy(data.ctx);
    return EXIT_SUCCESS;
}
