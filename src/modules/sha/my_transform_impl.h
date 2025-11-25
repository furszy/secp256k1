#ifndef LIBSECP256K1_MY_TRANSFORM_IMPL_H
#define LIBSECP256K1_MY_TRANSFORM_IMPL_H

#include "../../../include/secp256k1_sha.h"

#include <stdio.h>
#include <stdint.h>

void secp256k1_sha256_transform(uint32_t *state, const unsigned char *msg, size_t rounds) {
    (void)state;
    (void)msg;
    (void)rounds;
    printf("hello from the new sha256 Transform function!\n");
}

#endif /* LIBSECP256K1_MY_TRANSFORM_IMPL_H */
