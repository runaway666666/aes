#ifndef AES_CIPHER_C_H
#define AES_CIPHER_C_H

#if defined(__GNUC__) || defined(__clang__)
#define __attr_nodiscard __attribute__((warn_unused_result))
#define __attr_malloc __attribute__((malloc))
#define __attr_hot __attribute__((hot))
#define __attr_cold __attribute__((cold))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define __attr_nodiscard
#define __attr_malloc
#define __attr_hot
#define __attr_cold
#define likely(x) (x)
#define unlikely(x) (x)
#endif

#ifdef __cplusplus
#define __restrict__ __restrict
#else
#define __restrict__ restrict
#endif

#ifdef __cplusplus
#define __noexcept noexcept
#define __const_noexcept const noexcept
#else
#define __noexcept
#define __const_noexcept
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


#ifdef AES_ENABLE_PARALLEL_MODES
#include <pthread.h>
#ifndef AES_PARALLEL_THREADS
#define AES_PARALLEL_THREADS 4
#endif

typedef struct {
    void *ctx;
    const uint8_t *in;
    uint8_t *out;
    size_t len;
    size_t thread_id;
    size_t n_threads;
    void (*blockfunc)(void *, const uint8_t *, uint8_t *);
} aes_ecb_threadargs;

static void *aes_ecb_thread_worker(void *arg_) {
    aes_ecb_threadargs *arg = (aes_ecb_threadargs*)arg_;
    size_t blocks = arg->len / 16;
    for (size_t b = arg->thread_id; b < blocks; b += arg->n_threads) {
        arg->blockfunc(arg->ctx, arg->in + b*16, arg->out + b*16);
    }
    return NULL;
}

// For CBC decryption: output block[i] = Dec(in[i]) ^ in[i-1], so can be parallelized
typedef struct {
    void *ctx;
    const uint8_t *in;
    uint8_t *out;
    size_t len;
    size_t thread_id;
    size_t n_threads;
    const uint8_t *iv;
    void (*decblock)(void *, const uint8_t *, uint8_t *);
} aes_cbc_dec_threadargs;

static void *aes_cbc_dec_thread_worker(void *arg_) {
    aes_cbc_dec_threadargs *arg = (aes_cbc_dec_threadargs*)arg_;
    size_t blocks = arg->len / 16;
    for (size_t b = arg->thread_id; b < blocks; b += arg->n_threads) {
        uint8_t decout[16];
        arg->decblock(arg->ctx, arg->in + b*16, decout);
        const uint8_t *prev = (b == 0) ? arg->iv : (arg->in + (b-1)*16);
        for (size_t j = 0; j < 16; ++j)
            arg->out[b*16 + j] = decout[j] ^ prev[j];
    }
    return NULL;
}

// For CFB/OFB/CTR: all blocks independent, can be parallelized
typedef struct {
    void *ctx;
    const uint8_t *in;
    uint8_t *out;
    size_t len;
    size_t thread_id;
    size_t n_threads;
    const uint8_t *iv;
    void (*blockfunc)(void *, const uint8_t *, uint8_t *, size_t, size_t, size_t, const uint8_t *);
    } aes_stream_threadargs;

static void *aes_stream_thread_worker(void *arg_) {
    aes_stream_threadargs *arg = (aes_stream_threadargs*)arg_;
    arg->blockfunc(arg->ctx, arg->in, arg->out, arg->len, arg->thread_id, arg->n_threads, arg->iv);
    return NULL;
}
#endif

#define AES128KS 0x80
#define AES192KS 0xC0
#define AES256KS 0x100
#define AES128_ROUNDS 10
#define AES192_ROUNDS 12
#define AES256_ROUNDS 14
#define AES_BLOCK_SIZE 16

typedef uint8_t byte;

#define PRNG_N 624
#define PRNG_M 397
#define PRNG_MATRIX_A 0x9908b0dfUL
#define PRNG_UPPER_MASK 0x80000000UL
#define PRNG_LOWER_MASK 0x7fffffffUL

typedef struct
{
    uint32_t mt[PRNG_N];
    int mti;
} PRNG;

static inline void prng_init(PRNG *__restrict__ prng, uint32_t seed) __noexcept
{
    prng->mt[0] = seed;
    for (prng->mti = 1; prng->mti < PRNG_N; prng->mti++)
    {
        prng->mt[prng->mti] = (1812433253UL * (prng->mt[prng->mti - 1] ^ (prng->mt[prng->mti - 1] >> 30)) + prng->mti);
    }
}

__attr_nodiscard static inline uint32_t prng_rand(PRNG *__restrict__ prng, uint32_t min, uint32_t max) __noexcept
{
    uint32_t y;
    static const uint32_t mag01[2] = {0x0UL, PRNG_MATRIX_A};
    int kk;

    if (unlikely(prng->mti >= PRNG_N))
    {
        for (kk = 0; kk < PRNG_N - PRNG_M; kk++)
        {
            y = (prng->mt[kk] & PRNG_UPPER_MASK) | (prng->mt[kk + 1] & PRNG_LOWER_MASK);
            prng->mt[kk] = prng->mt[kk + PRNG_M] ^ (y >> 1) ^ mag01[y & 0x1UL];
        }
        for (; kk < PRNG_N - 1; kk++)
        {
            y = (prng->mt[kk] & PRNG_UPPER_MASK) | (prng->mt[kk + 1] & PRNG_LOWER_MASK);
            prng->mt[kk] = prng->mt[kk + (PRNG_M - PRNG_N)] ^ (y >> 1) ^ mag01[y & 0x1UL];
        }
        y = (prng->mt[PRNG_N - 1] & PRNG_UPPER_MASK) | (prng->mt[0] & PRNG_LOWER_MASK);
        prng->mt[PRNG_N - 1] = prng->mt[PRNG_M - 1] ^ (y >> 1) ^ mag01[y & 0x1UL];
        prng->mti = 0;
    }
    y = prng->mt[prng->mti++];
    y ^= (y >> 11);
    y ^= (y << 7) & 0x9d2c5680UL;
    y ^= (y << 15) & 0xefc60000UL;
    y ^= (y >> 18);
    return min + (y % (max - min + 1));
}

__attr_nodiscard static inline byte gf_mul(byte a, byte b) __noexcept
{
    byte p = 0;
    for (int i = 0; i < 8; ++i)
    {
        if (likely(b & 1))
            p ^= a;
        byte hiBitSet = a & 0x80;
        a <<= 1;
        if (hiBitSet)
            a ^= 0x1B;
        b >>= 1;
    }
    return p;
}

__attr_nodiscard static inline byte gf_inv(byte x) __noexcept
{
    byte y = x;
    for (int i = 0; i < 4; ++i)
    {
        y = gf_mul(y, y);
        y = gf_mul(y, x);
    }
    return y;
}

__attr_nodiscard static inline byte affine_transform(byte x) __noexcept
{
    byte result = 0x63;
    for (int i = 0; i < 8; ++i)
    {
        if ((x >> i) & 1)
            result ^= (0xF1 >> (7 - i)) & 0xFF;
    }
    return result;
}

__attr_nodiscard static inline byte sbox_entry(byte x) __noexcept
{
    return affine_transform(gf_inv(x));
}

static inline void create_sbox(byte sbox[256]) __noexcept
{
    for (int i = 0; i < 256; ++i)
        sbox[i] = sbox_entry((byte)i);
}

static inline void create_invsbox(const byte sbox[256], byte invsbox[256]) __noexcept
{
    for (int i = 0; i < 256; ++i)
        invsbox[sbox[i]] = (byte)i;
}

static inline void create_rcon(byte rcon[256]) __noexcept
{
    byte c = 1;
    for (int i = 0; i < 256; ++i)
    {
        rcon[i] = c;
        c = gf_mul(c, 0x02);
    }
}

typedef struct
{
    int Nk, Nr, Nb;
    byte round_keys[240];
    byte sbox[256];
    byte inv_sbox[256];
    byte rcon[256];
} aes_ctx;

static inline void aes_init(aes_ctx *ctx, int key_size) __noexcept
{
    ctx->Nb = 4;
    if (key_size == AES128KS)
    {
        ctx->Nk = 4;
        ctx->Nr = 10;
    }
    else if (key_size == AES192KS)
    {
        ctx->Nk = 6;
        ctx->Nr = 12;
    }
    else if (key_size == AES256KS)
    {
        ctx->Nk = 8;
        ctx->Nr = 14;
    }
    else
    {
        ctx->Nk = 4;
        ctx->Nr = 10;
    }
    create_sbox(ctx->sbox);
    create_invsbox(ctx->sbox, ctx->inv_sbox);
    create_rcon(ctx->rcon);
}

static inline void aes_key_expansion(aes_ctx *ctx, const byte *key) __noexcept
{
    int i = 0, Nk = ctx->Nk, Nb = ctx->Nb, Nr = ctx->Nr;
    byte temp[4];
    byte *w = ctx->round_keys;
    for (; i < Nk; ++i)
    {
        w[4 * i + 0] = key[4 * i + 0];
        w[4 * i + 1] = key[4 * i + 1];
        w[4 * i + 2] = key[4 * i + 2];
        w[4 * i + 3] = key[4 * i + 3];
    }
    for (; i < Nb * (Nr + 1); ++i)
    {
        temp[0] = w[4 * (i - 1) + 0];
        temp[1] = w[4 * (i - 1) + 1];
        temp[2] = w[4 * (i - 1) + 2];
        temp[3] = w[4 * (i - 1) + 3];
        if (i % Nk == 0)
        {
            byte t = temp[0];
            temp[0] = ctx->sbox[temp[1]] ^ ctx->rcon[i / Nk];
            temp[1] = ctx->sbox[temp[2]];
            temp[2] = ctx->sbox[temp[3]];
            temp[3] = ctx->sbox[t];
        }
        else if (Nk > 6 && (i % Nk == 4))
        {
            temp[0] = ctx->sbox[temp[0]];
            temp[1] = ctx->sbox[temp[1]];
            temp[2] = ctx->sbox[temp[2]];
            temp[3] = ctx->sbox[temp[3]];
        }
        w[4 * i + 0] = w[4 * (i - Nk) + 0] ^ temp[0];
        w[4 * i + 1] = w[4 * (i - Nk) + 1] ^ temp[1];
        w[4 * i + 2] = w[4 * (i - Nk) + 2] ^ temp[2];
        w[4 * i + 3] = w[4 * (i - Nk) + 3] ^ temp[3];
    }
}

static inline void aes_add_round_key(byte state[4][4], const byte *rk) __noexcept
{
    for (int c = 0; c < 4; ++c)
        for (int r = 0; r < 4; ++r)
            state[r][c] ^= rk[4 * c + r];
}

static inline void aes_sub_bytes(byte state[4][4], const byte sbox[256]) __noexcept
{
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            state[r][c] = sbox[state[r][c]];
}

static inline void aes_inv_sub_bytes(byte state[4][4], const byte invsbox[256]) __noexcept
{
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            state[r][c] = invsbox[state[r][c]];
}

static inline void aes_shift_rows(byte state[4][4]) __noexcept
{
    byte t;
    t = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = t;
    t = state[2][0];
    byte t2 = state[2][1];
    state[2][0] = state[2][2];
    state[2][1] = state[2][3];
    state[2][2] = t;
    state[2][3] = t2;
    t = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = t;
}

static inline void aes_inv_shift_rows(byte state[4][4]) __noexcept
{
    byte t;
    t = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = t;
    t = state[2][0];
    byte t2 = state[2][1];
    state[2][0] = state[2][2];
    state[2][1] = state[2][3];
    state[2][2] = t;
    state[2][3] = t2;
    t = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = t;
}

static inline void aes_mix_columns(byte state[4][4]) __noexcept
{
    for (int c = 0; c < 4; ++c)
    {
        byte a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];
        state[0][c] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3;
        state[1][c] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3;
        state[2][c] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3);
        state[3][c] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2);
    }
}

static inline void aes_inv_mix_columns(byte state[4][4]) __noexcept
{
    for (int c = 0; c < 4; ++c)
    {
        byte a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];
        state[0][c] = gf_mul(a0, 0x0e) ^ gf_mul(a1, 0x0b) ^ gf_mul(a2, 0x0d) ^ gf_mul(a3, 0x09);
        state[1][c] = gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0e) ^ gf_mul(a2, 0x0b) ^ gf_mul(a3, 0x0d);
        state[2][c] = gf_mul(a0, 0x0d) ^ gf_mul(a1, 0x09) ^ gf_mul(a2, 0x0e) ^ gf_mul(a3, 0x0b);
        state[3][c] = gf_mul(a0, 0x0b) ^ gf_mul(a1, 0x0d) ^ gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0e);
    }
}

__attr_hot static inline void aes_encrypt_block(aes_ctx *ctx, const byte in[16], byte out[16]) __noexcept
{
    byte state[4][4];
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            state[r][c] = in[r + 4 * c];
    aes_add_round_key(state, ctx->round_keys);
    for (int round = 1; round < ctx->Nr; ++round)
    {
        aes_sub_bytes(state, ctx->sbox);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, ctx->round_keys + 16 * round);
    }
    aes_sub_bytes(state, ctx->sbox);
    aes_shift_rows(state);
    aes_add_round_key(state, ctx->round_keys + 16 * ctx->Nr);
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            out[r + 4 * c] = state[r][c];
}

__attr_hot static inline void aes_decrypt_block(aes_ctx *ctx, const byte in[16], byte out[16]) __noexcept
{
    byte state[4][4];
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            state[r][c] = in[r + 4 * c];
    aes_add_round_key(state, ctx->round_keys + 16 * ctx->Nr);
    for (int round = ctx->Nr - 1; round >= 1; --round)
    {
        aes_inv_shift_rows(state);
        aes_inv_sub_bytes(state, ctx->inv_sbox);
        aes_add_round_key(state, ctx->round_keys + 16 * round);
        aes_inv_mix_columns(state);
    }
    aes_inv_shift_rows(state);
    aes_inv_sub_bytes(state, ctx->inv_sbox);
    aes_add_round_key(state, ctx->round_keys);
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            out[r + 4 * c] = state[r][c];
}

__attr_nodiscard static inline size_t pkcs7_pad(byte *buf, size_t len, size_t block_size) __noexcept
{
    size_t pad = block_size - (len % block_size);
    for (size_t i = 0; i < pad; ++i)
        buf[len + i] = (byte)pad;
    return len + pad;
}
__attr_nodiscard static inline size_t pkcs7_unpad(byte *buf, size_t len) __noexcept
{
    if (!len)
        return 0;
    byte pad = buf[len - 1];
    if (unlikely(pad > AES_BLOCK_SIZE))
        return len;
    return len - pad;
}

static inline void aes_gen_key(byte *key, size_t key_size) __noexcept
{
    PRNG prng;
    prng_init(&prng, (uint32_t)time(NULL));
    for (size_t i = 0; i < key_size; ++i)
        key[i] = (byte)prng_rand(&prng, 0, 255);
}
static inline void aes_gen_iv(byte *iv, size_t size) __noexcept
{
    PRNG prng;
    prng_init(&prng, (uint32_t)time(NULL));
    for (size_t i = 0; i < size; ++i)
        iv[i] = (byte)prng_rand(&prng, 0, 255);
}

/* ===================== MODE IMPLEMENTATIONS ===================== */

/* ------- ECB ------- */
__attr_hot static inline void aes_ecb_encrypt(aes_ctx *ctx, const byte *in, byte *out, size_t len) __noexcept
{
#ifdef AES_ENABLE_PARALLEL_MODES
    pthread_t th[AES_PARALLEL_THREADS];
    aes_ecb_threadargs args[AES_PARALLEL_THREADS];
    for (size_t t = 0; t < AES_PARALLEL_THREADS; ++t) {
        args[t].ctx = ctx;
        args[t].in = in;
        args[t].out = out;
        args[t].len = len;
        args[t].thread_id = t;
        args[t].n_threads = AES_PARALLEL_THREADS;
        args[t].blockfunc = (void (*)(void *, const uint8_t *, uint8_t *))aes_encrypt_block;
        pthread_create(&th[t], NULL, aes_ecb_thread_worker, &args[t]);
    }
    for (size_t t = 0; t < AES_PARALLEL_THREADS; ++t) {
        pthread_join(th[t], NULL);
    }
#else
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE)
        aes_encrypt_block(ctx, in + i, out + i);
#endif
}

__attr_hot static inline void aes_ecb_decrypt(aes_ctx *ctx, const byte *in, byte *out, size_t len) __noexcept
{
#ifdef AES_ENABLE_PARALLEL_MODES
    pthread_t th[AES_PARALLEL_THREADS];
    aes_ecb_threadargs args[AES_PARALLEL_THREADS];
    for (size_t t = 0; t < AES_PARALLEL_THREADS; ++t) {
        args[t].ctx = ctx;
        args[t].in = in;
        args[t].out = out;
        args[t].len = len;
        args[t].thread_id = t;
        args[t].n_threads = AES_PARALLEL_THREADS;
        args[t].blockfunc = (void (*)(void *, const uint8_t *, uint8_t *))aes_decrypt_block;
        pthread_create(&th[t], NULL, aes_ecb_thread_worker, &args[t]);
    }
    for (size_t t = 0; t < AES_PARALLEL_THREADS; ++t) {
        pthread_join(th[t], NULL);
    }
#else
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE)
        aes_decrypt_block(ctx, in + i, out + i);
#endif
}

/* ------- CBC ------- */
__attr_hot static inline void aes_cbc_encrypt(aes_ctx *ctx, const byte *in, byte *out, size_t len, byte iv[16]) __noexcept
{
    byte prev[16];
    memcpy(prev, iv, 16);
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE)
    {
        byte block[16];
        for (int j = 0; j < 16; ++j)
            block[j] = in[i + j] ^ prev[j];
        aes_encrypt_block(ctx, block, out + i);
        memcpy(prev, out + i, 16);
    }
}

// CBC decryption can be parallelized
__attr_hot static inline void aes_cbc_decrypt(aes_ctx *ctx, const byte *in, byte *out, size_t len, byte iv[16]) __noexcept
{
#ifdef AES_ENABLE_PARALLEL_MODES
    pthread_t th[AES_PARALLEL_THREADS];
    aes_cbc_dec_threadargs args[AES_PARALLEL_THREADS];
    for (size_t t = 0; t < AES_PARALLEL_THREADS; ++t) {
        args[t].ctx = ctx;
        args[t].in = in;
        args[t].out = out;
        args[t].len = len;
        args[t].thread_id = t;
        args[t].n_threads = AES_PARALLEL_THREADS;
        args[t].iv = iv;
        args[t].decblock = (void (*)(void *, const uint8_t *, uint8_t *))aes_decrypt_block;
        pthread_create(&th[t], NULL, aes_cbc_dec_thread_worker, &args[t]);
    }
    for (size_t t = 0; t < AES_PARALLEL_THREADS; ++t) {
        pthread_join(th[t], NULL);
    }
#else
    byte prev[16];
    memcpy(prev, iv, 16);
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE)
    {
        byte block[16];
        aes_decrypt_block(ctx, in + i, block);
        for (int j = 0; j < 16; ++j)
            out[i + j] = block[j] ^ prev[j];
        memcpy(prev, in + i, 16);
    }
#endif
}

/* ------- CFB ------- */
static void aes_cfb_encrypt_parallel(
    void *vctx, const uint8_t *in, uint8_t *out,
    size_t len, size_t tid, size_t nthreads, const uint8_t *iv
){
    aes_ctx *ctx = (aes_ctx *)vctx;
    size_t blocks = len / 16;
    uint8_t prev[16];
    for (size_t b = tid; b < blocks; b += nthreads) {
        if (b == 0)
            memcpy(prev, iv, 16);
        else
            memcpy(prev, out + (b - 1) * 16, 16);
        uint8_t keystream[16];
        aes_encrypt_block(ctx, prev, keystream);
        for (size_t j = 0; j < 16; ++j)
            out[b*16 + j] = in[b*16 + j] ^ keystream[j];
    }
}

static void aes_cfb_decrypt_parallel(void *vctx, const uint8_t *in, uint8_t *out, size_t len, size_t tid, size_t nthreads, const uint8_t *iv)
{
    aes_ctx *ctx = (aes_ctx *)vctx;
    size_t blocks = len / 16;
    uint8_t prev[16];
    for (size_t b = tid; b < blocks; b += nthreads) {
        if (b == 0)
            memcpy(prev, iv, 16);
        else
            memcpy(prev, in + (b - 1) * 16, 16);
        uint8_t keystream[16];
        aes_encrypt_block(ctx, prev, keystream);
        for (size_t j = 0; j < 16; ++j)
            out[b*16 + j] = in[b*16 + j] ^ keystream[j];
    }
}

__attr_hot static inline void aes_cfb_encrypt(aes_ctx *ctx, const byte *in, byte *out, size_t len, byte iv[16]) __noexcept
{
#ifdef AES_ENABLE_PARALLEL_MODES
    pthread_t th[AES_PARALLEL_THREADS];
    aes_stream_threadargs args[AES_PARALLEL_THREADS];
    for (size_t t = 0; t < AES_PARALLEL_THREADS; ++t) {
        args[t].ctx = ctx;
        args[t].in = in;
        args[t].out = out;
        args[t].len = len;
        args[t].thread_id = t;
        args[t].n_threads = AES_PARALLEL_THREADS;
        args[t].iv = iv;
        args[t].blockfunc = aes_cfb_encrypt_parallel;
        pthread_create(&th[t], NULL, aes_stream_thread_worker, &args[t]);
    }
    for (size_t t = 0; t < AES_PARALLEL_THREADS; ++t) {
        pthread_join(th[t], NULL);
    }
#else
    byte prev[16];
    memcpy(prev, iv, 16);
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE)
    {
        byte keystream[16];
        aes_encrypt_block(ctx, prev, keystream);
        for (size_t j = 0; j < AES_BLOCK_SIZE && i + j < len; ++j)
            out[i + j] = in[i + j] ^ keystream[j];
        memcpy(prev, out + i, 16);
    }
#endif
}

__attr_hot static inline void aes_cfb_decrypt(aes_ctx *ctx, const byte *in, byte *out, size_t len, byte iv[16]) __noexcept
{
#ifdef AES_ENABLE_PARALLEL_MODES
    pthread_t th[AES_PARALLEL_THREADS];
    aes_stream_threadargs args[AES_PARALLEL_THREADS];
    for (size_t t = 0; t < AES_PARALLEL_THREADS; ++t) {
        args[t].ctx = ctx;
        args[t].in = in;
        args[t].out = out;
        args[t].len = len;
        args[t].thread_id = t;
        args[t].n_threads = AES_PARALLEL_THREADS;
        args[t].iv = iv;
        args[t].blockfunc = aes_cfb_decrypt_parallel;
        pthread_create(&th[t], NULL, aes_stream_thread_worker, &args[t]);
    }
    for (size_t t = 0; t < AES_PARALLEL_THREADS; ++t) {
        pthread_join(th[t], NULL);
    }
#else
    byte prev[16];
    memcpy(prev, iv, 16);
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE)
    {
        byte keystream[16];
        aes_encrypt_block(ctx, prev, keystream);
        for (size_t j = 0; j < AES_BLOCK_SIZE && i + j < len; ++j)
            out[i + j] = in[i + j] ^ keystream[j];
        memcpy(prev, in + i, 16);
    }
#endif
}

/* ------- OFB ------- */
static void aes_ofb_parallel(void *vctx, const uint8_t *in, uint8_t *out, size_t len, size_t tid, size_t nthreads, const uint8_t *iv)
{
    aes_ctx *ctx = (aes_ctx *)vctx;
    size_t blocks = len / 16;
    uint8_t feedback[16];
    for (size_t b = tid; b < blocks; b += nthreads) {
        if (b == 0)
            memcpy(feedback, iv, 16);
        else
            memcpy(feedback, out + (b - 1) * 16, 16);
        uint8_t keystream[16];
        aes_encrypt_block(ctx, feedback, keystream);
        for (size_t j = 0; j < 16; ++j)
            out[b*16 + j] = in[b*16 + j] ^ keystream[j];
        memcpy(feedback, keystream, 16);
    }
}

__attr_hot static inline void aes_ofb_encrypt(aes_ctx *ctx, const byte *in, byte *out, size_t len, byte iv[16]) __noexcept
{
    byte feedback[16];
    memcpy(feedback, iv, 16);
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE)
    {
        byte keystream[16];
        aes_encrypt_block(ctx, feedback, keystream);
        for (size_t j = 0; j < AES_BLOCK_SIZE && i + j < len; ++j)
            out[i + j] = in[i + j] ^ keystream[j];
        memcpy(feedback, keystream, 16);
    }
}
#define aes_ofb_decrypt aes_ofb_encrypt

/* ------- CTR ------- */
static void aes_ctr_parallel(void *vctx, const uint8_t *in, uint8_t *out, size_t len, size_t tid, size_t nthreads, const uint8_t *nonce)
{
    aes_ctx *ctx = (aes_ctx *)vctx;
    size_t blocks = len / 16;
    for (size_t b = tid; b < blocks; b += nthreads) {
        uint8_t counter[16];
        memcpy(counter, nonce, 16);
        for (int i = 15; i >= 0; --i) {
            uint16_t x = counter[i] + (b & 0xFF);
            counter[i] = x & 0xFF;
            if (!(x & 0x100)) break;
        }
        uint8_t keystream[16];
        aes_encrypt_block(ctx, counter, keystream);
        for (size_t j = 0; j < 16; ++j)
            out[b*16 + j] = in[b*16 + j] ^ keystream[j];
    }
}

static inline void increment_counter(byte counter[16]) __noexcept
{
    for (int i = 15; i >= 0; --i)
    {
        if (++counter[i])
            break;
    }
}

__attr_hot static inline void aes_ctr_encrypt(aes_ctx *ctx, const byte *in, byte *out, size_t len, byte nonce[16]) __noexcept
{
#ifdef AES_ENABLE_PARALLEL_MODES
    pthread_t th[AES_PARALLEL_THREADS];
    aes_stream_threadargs args[AES_PARALLEL_THREADS];
    for (size_t t = 0; t < AES_PARALLEL_THREADS; ++t) {
        args[t].ctx = ctx;
        args[t].in = in;
        args[t].out = out;
        args[t].len = len;
        args[t].thread_id = t;
        args[t].n_threads = AES_PARALLEL_THREADS;
        args[t].iv = nonce;
        args[t].blockfunc = aes_ctr_parallel;
        pthread_create(&th[t], NULL, aes_stream_thread_worker, &args[t]);
    }
    for (size_t t = 0; t < AES_PARALLEL_THREADS; ++t) {
        pthread_join(th[t], NULL);
    }
#else
    byte counter[16];
    memcpy(counter, nonce, 16);
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE)
    {
        byte keystream[16];
        aes_encrypt_block(ctx, counter, keystream);
        for (size_t j = 0; j < AES_BLOCK_SIZE && i + j < len; ++j)
            out[i + j] = in[i + j] ^ keystream[j];
        increment_counter(counter);
    }
#endif
}
#define aes_ctr_decrypt aes_ctr_encrypt

#endif
