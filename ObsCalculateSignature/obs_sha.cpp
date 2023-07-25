
#include "obs_sha.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))
#define blk0L(i) (block->l[i] = (rol(block->l[i], 24) & 0xFF00FF00)     \
                  | (rol(block->l[i], 8) & 0x00FF00FF))

#define blk0B(i) (block->l[i])
#define blk(i) (block->l[i & 15] = rol(block->l[(i + 13) & 15] ^        \
                                       block->l[(i + 8) & 15] ^         \
                                       block->l[(i + 2) & 15] ^         \
                                       block->l[i & 15], 1))

#define R0_L(v, w, x, y, z, i)                                          \
    z += ((w & (x ^ y)) ^ y) + blk0L(i) + 0x5A827999 + rol(v, 5);       \
    w = rol(w, 30);
#define R0_B(v, w, x, y, z, i)                                          \
    z += ((w & (x ^ y)) ^ y) + blk0B(i) + 0x5A827999 + rol(v, 5);       \
    w = rol(w, 30);
#define R1(v, w, x, y, z, i)                                            \
    z += ((w & (x ^ y)) ^ y) + blk(i) + 0x5A827999 + rol(v, 5);         \
    w = rol(w, 30);
#define R2(v, w, x, y, z, i)                                            \
    z += (w ^ x ^ y) + blk(i) + 0x6ED9EBA1 + rol(v, 5);                 \
    w = rol(w, 30);
#define R3(v, w, x, y, z, i)                                            \
    z += (((w | x) & y) | (w & x)) + blk(i) + 0x8F1BBCDC + rol(v, 5);   \
    w = rol(w, 30);
#define R4(v, w, x, y, z, i)                                            \
    z += (w ^ x ^ y) + blk(i) + 0xCA62C1D6 + rol(v, 5);                 \
    w = rol(w, 30);

#define R0A_L(i) R0_L(a, b, c, d, e, i)
#define R0B_L(i) R0_L(b, c, d, e, a, i)
#define R0C_L(i) R0_L(c, d, e, a, b, i)
#define R0D_L(i) R0_L(d, e, a, b, c, i)
#define R0E_L(i) R0_L(e, a, b, c, d, i)

#define R0A_B(i) R0_B(a, b, c, d, e, i)
#define R0B_B(i) R0_B(b, c, d, e, a, i)
#define R0C_B(i) R0_B(c, d, e, a, b, i)
#define R0D_B(i) R0_B(d, e, a, b, c, i)
#define R0E_B(i) R0_B(e, a, b, c, d, i)

#define R1A(i) R1(a, b, c, d, e, i)
#define R1B(i) R1(b, c, d, e, a, i)
#define R1C(i) R1(c, d, e, a, b, i)
#define R1D(i) R1(d, e, a, b, c, i)
#define R1E(i) R1(e, a, b, c, d, i)

#define R2A(i) R2(a, b, c, d, e, i)
#define R2B(i) R2(b, c, d, e, a, i)
#define R2C(i) R2(c, d, e, a, b, i)
#define R2D(i) R2(d, e, a, b, c, i)
#define R2E(i) R2(e, a, b, c, d, i)

#define R3A(i) R3(a, b, c, d, e, i)
#define R3B(i) R3(b, c, d, e, a, i)
#define R3C(i) R3(c, d, e, a, b, i)
#define R3D(i) R3(d, e, a, b, c, i)
#define R3E(i) R3(e, a, b, c, d, i)

#define R4A(i) R4(a, b, c, d, e, i)
#define R4B(i) R4(b, c, d, e, a, i)
#define R4C(i) R4(c, d, e, a, b, i)
#define R4D(i) R4(d, e, a, b, c, i)
#define R4E(i) R4(e, a, b, c, d, i)

typedef struct
{
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1Context;

static void SHA1_init(SHA1Context *context)
{
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}

errno_t memset_s(void* dest, size_t destMax, int c, size_t count){
	memset(dest, c, count);
	return 0;
}

//errno_t memcpy_s(void* dest, size_t destMax, const void* src, size_t count){
//	memcpy(dest, src, count);
//	return 0;
//}

static void SHA1_transform(uint32_t state[5], const unsigned char buffer[64])
{
    uint32_t a, b, c, d, e;
    typedef union {
        unsigned char c[64];
        uint32_t l[16];
    } u;
    unsigned char w[64];
    u *block = (u *) w;
    memcpy_s(block, 64, buffer, 64);
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    static uint32_t endianness_indicator = 0x1;
    if (((unsigned char *) &endianness_indicator)[0]) {
        R0A_L( 0);
        R0E_L( 1); R0D_L( 2); R0C_L( 3); R0B_L( 4); R0A_L( 5);
        R0E_L( 6); R0D_L( 7); R0C_L( 8); R0B_L( 9); R0A_L(10);
        R0E_L(11); R0D_L(12); R0C_L(13); R0B_L(14); R0A_L(15);
    }
    else {
        R0A_B( 0);
        R0E_B( 1); R0D_B( 2); R0C_B( 3); R0B_B( 4); R0A_B( 5);
        R0E_B( 6); R0D_B( 7); R0C_B( 8); R0B_B( 9); R0A_B(10);
        R0E_B(11); R0D_B(12); R0C_B(13); R0B_B(14); R0A_B(15);
    }
    R1E(16); R1D(17); R1C(18); R1B(19); R2A(20);
    R2E(21); R2D(22); R2C(23); R2B(24); R2A(25);
    R2E(26); R2D(27); R2C(28); R2B(29); R2A(30);
    R2E(31); R2D(32); R2C(33); R2B(34); R2A(35);
    R2E(36); R2D(37); R2C(38); R2B(39); R3A(40);
    R3E(41); R3D(42); R3C(43); R3B(44); R3A(45);
    R3E(46); R3D(47); R3C(48); R3B(49); R3A(50);
    R3E(51); R3D(52); R3C(53); R3B(54); R3A(55);
    R3E(56); R3D(57); R3C(58); R3B(59); R4A(60);
    R4E(61); R4D(62); R4C(63); R4B(64); R4A(65);
    R4E(66); R4D(67); R4C(68); R4B(69); R4A(70);
    R4E(71); R4D(72); R4C(73); R4B(74); R4A(75);
    R4E(76); R4D(77); R4C(78); R4B(79);
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

static void SHA1_update(SHA1Context *context, const unsigned char *data,
                        unsigned int len)
{
    uint32_t i, j;
	errno_t err = EOK;
    j = (context->count[0] >> 3) & 63;

    if ((context->count[0] += len << 3) < (len << 3)) {
        context->count[1]++;
    }

    context->count[1] += (len >> 29);

    if ((j + len) > 63) {
		err = EOK;
		err = memcpy_s(&(context->buffer[j]), sizeof(context->buffer) - j, data, (i = 64 - j));
		if (err != EOK)
		{
			printf("SHA1_update: memcpy_s failed!\n");
		}

        SHA1_transform(context->state, context->buffer);
        for ( ; (i + 63) < len; i += 64) {
            SHA1_transform(context->state, &(data[i]));
        }
        j = 0;
    }
    else {
        i = 0;
    }

	err = EOK;
	err = memcpy_s(&(context->buffer[j]), sizeof(context->buffer) - j, &(data[i]), len - i);
	if (err != EOK)
	{
		printf("SHA1_update: memcpy_s failed!\n");
	}
}

static void SHA1_final(unsigned char digest[20], SHA1Context *context)
{
    uint32_t i;
    unsigned char finalcount[8] = {0};

    for (i = 0; i < 8; i++) {
        finalcount[i] = (unsigned char)
            ((context->count[(i >= 4 ? 0 : 1)] >>
              ((3 - (i & 3)) * 8)) & 255);
    }
    SHA1_update(context, (unsigned char *) "\200", 1);

    while ((context->count[0] & 504) != 448) {
        SHA1_update(context, (unsigned char *) "\0", 1);
    }
    SHA1_update(context, finalcount, 8);

    for (i = 0; i < 20; i++) {
        digest[i] = (unsigned char)
            ((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }
    memset_s(context->buffer, sizeof(context->buffer), 0, 64);
    memset_s(context->state, sizeof(context->state), 0, 20);
    memset_s(context->count, sizeof(context->count), 0, 8);
    memset_s(finalcount, sizeof(finalcount), 0, 8);
    SHA1_transform(context->state, context->buffer);
}

void hmac_sha1(unsigned char hmac[20], const unsigned char *key, int key_len,
               const unsigned char *message, int message_len)
{
    unsigned char kopad[64] = {0};
    unsigned char kipad[64] = {0};
    int i;
    if (key_len > 64) {
        key_len = 64;
    }
    for (i = 0; i < key_len; i++) {
        kopad[i] = key[i] ^ 0x5c;
        kipad[i] = key[i] ^ 0x36;
    }
    for ( ; i < 64; i++) {
        kopad[i] = 0 ^ 0x5c;
        kipad[i] = 0 ^ 0x36;
    }
    unsigned char digest[20];
    SHA1Context context;

    SHA1_init(&context);
    SHA1_update(&context, kipad, 64);
    SHA1_update(&context, message, message_len);
    SHA1_final(digest, &context);

    SHA1_init(&context);
    SHA1_update(&context, kopad, 64);
    SHA1_update(&context, digest, 20);
    SHA1_final(hmac, &context);
}
