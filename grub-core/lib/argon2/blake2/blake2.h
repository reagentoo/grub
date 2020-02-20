/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */

#ifndef PORTABLE_BLAKE2_H
#define PORTABLE_BLAKE2_H

#include "../argon2.h"

#if defined(__cplusplus)
extern "C" {
#endif

enum blake2b_constant {
    BLAKE2B_BLOCKBYTES = 128,
    BLAKE2B_OUTBYTES = 64,
    BLAKE2B_KEYBYTES = 64,
    BLAKE2B_SALTBYTES = 16,
    BLAKE2B_PERSONALBYTES = 16
};

#pragma pack(push, 1)
typedef struct __blake2b_param {
    grub_uint8_t digest_length;                   /* 1 */
    grub_uint8_t key_length;                      /* 2 */
    grub_uint8_t fanout;                          /* 3 */
    grub_uint8_t depth;                           /* 4 */
    grub_uint32_t leaf_length;                    /* 8 */
    grub_uint64_t node_offset;                    /* 16 */
    grub_uint8_t node_depth;                      /* 17 */
    grub_uint8_t inner_length;                    /* 18 */
    grub_uint8_t reserved[14];                    /* 32 */
    grub_uint8_t salt[BLAKE2B_SALTBYTES];         /* 48 */
    grub_uint8_t personal[BLAKE2B_PERSONALBYTES]; /* 64 */
} blake2b_param;
#pragma pack(pop)

typedef struct __blake2b_state {
    grub_uint64_t h[8];
    grub_uint64_t t[2];
    grub_uint64_t f[2];
    grub_uint8_t buf[BLAKE2B_BLOCKBYTES];
    unsigned buflen;
    unsigned outlen;
    grub_uint8_t last_node;
} blake2b_state;

/* Ensure param structs have not been wrongly padded */
/* Poor man's static_assert */
enum {
    blake2_size_check_0 = 1 / !!(GRUB_CHAR_BIT == 8),
    blake2_size_check_2 =
        1 / !!(sizeof(blake2b_param) == sizeof(grub_uint64_t) * GRUB_CHAR_BIT)
};

/* Streaming API */
ARGON2_LOCAL int blake2b_init(blake2b_state *S, grub_size_t outlen);
ARGON2_LOCAL int blake2b_init_key(blake2b_state *S, grub_size_t outlen, const void *key,
                     grub_size_t keylen);
ARGON2_LOCAL int blake2b_init_param(blake2b_state *S, const blake2b_param *P);
ARGON2_LOCAL int blake2b_update(blake2b_state *S, const void *in, grub_size_t inlen);
ARGON2_LOCAL int blake2b_final(blake2b_state *S, void *out, grub_size_t outlen);

/* Simple API */
ARGON2_LOCAL int blake2b(void *out, grub_size_t outlen, const void *in, grub_size_t inlen,
                         const void *key, grub_size_t keylen);

/* Argon2 Team - Begin Code */
ARGON2_LOCAL int blake2b_long(void *out, grub_size_t outlen, const void *in, grub_size_t inlen);
/* Argon2 Team - End Code */

#if defined(__cplusplus)
}
#endif

#endif
