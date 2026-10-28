#include "pbkdf2_sha256.h"
#include "sha256_internal.h"

#include <string.h>

#if defined(__aarch64__) && defined(__linux__)
#include <sys/auxv.h>
#ifndef HWCAP_SHA2
#define HWCAP_SHA2 (1 << 6)
#endif
#endif

#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif

static const uint32_t IV[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

// ---- Backend selection --------------------------------------------------------------------

static int cpu_has(nc_backend b) {
    switch (b) {
    case NC_BACKEND_PORTABLE:
        return 1;
#if defined(__aarch64__) && defined(__linux__)
    case NC_BACKEND_ARMV8_SHA2:
        return (getauxval(AT_HWCAP) & HWCAP_SHA2) != 0;
#endif
#if defined(__x86_64__) || defined(__i386__)
    case NC_BACKEND_X86_SHANI: {
        unsigned a, bx, c, d;
        if (!__get_cpuid_count(7, 0, &a, &bx, &c, &d)) return 0;
        int sha = (bx >> 29) & 1;
        if (!__get_cpuid(1, &a, &bx, &c, &d)) return 0;
        int sse41 = (c >> 19) & 1, ssse3 = (c >> 9) & 1;
        return sha && sse41 && ssse3;
    }
#endif
    default:
        return 0;
    }
}

static int g_backend = -1;

nc_backend nc_active_backend(void) {
    if (g_backend < 0) {
        if (cpu_has(NC_BACKEND_ARMV8_SHA2)) g_backend = NC_BACKEND_ARMV8_SHA2;
        else if (cpu_has(NC_BACKEND_X86_SHANI)) g_backend = NC_BACKEND_X86_SHANI;
        else g_backend = NC_BACKEND_PORTABLE;
    }
    return (nc_backend)g_backend;
}

int nc_force_backend(nc_backend b) {
    if (!cpu_has(b)) return 0;
    g_backend = (int)b;
    return 1;
}

const char *nc_backend_name(nc_backend b) {
    switch (b) {
    case NC_BACKEND_ARMV8_SHA2: return "ARMv8 SHA-256 instructions";
    case NC_BACKEND_X86_SHANI: return "x86 SHA extensions";
    default: return "Portable (no SHA-256 instructions)";
    }
}

static nc_compress_fn compress_fn(void) {
    switch (nc_active_backend()) {
#if defined(__aarch64__)
    case NC_BACKEND_ARMV8_SHA2: return nc_compress_armv8;
#endif
#if defined(__x86_64__) || defined(__i386__)
    case NC_BACKEND_X86_SHANI: return nc_compress_shani;
#endif
    default: return nc_compress_portable;
    }
}

static void iterate(const uint32_t ist[8], const uint32_t ost[8], uint32_t u[8], uint32_t t[8], uint32_t n) {
#if defined(__aarch64__)
    if (nc_active_backend() == NC_BACKEND_ARMV8_SHA2) {
        nc_iterate_armv8(ist, ost, u, t, n);
        return;
    }
#endif
    nc_iterate_generic(compress_fn(), ist, ost, u, t, n);
}

// ---- Minimal streaming SHA-256 (for the one-off hashes around the loop) -------------------

typedef struct {
    uint32_t h[8];
    uint8_t buf[64];
    size_t used;
    uint64_t total;  // bytes, including any prefix already folded into h
} sha_ctx;

static void load_words(uint32_t w[16], const uint8_t *p) {
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
}

static void sha_init(sha_ctx *c, const uint32_t h[8], uint64_t prefix_bytes) {
    memcpy(c->h, h, sizeof c->h);
    c->used = 0;
    c->total = prefix_bytes;
}

static void sha_update(sha_ctx *c, const uint8_t *p, size_t n) {
    nc_compress_fn f = compress_fn();
    uint32_t w[16];
    c->total += n;
    while (n) {
        size_t take = 64 - c->used;
        if (take > n) take = n;
        memcpy(c->buf + c->used, p, take);
        c->used += take; p += take; n -= take;
        if (c->used == 64) {
            load_words(w, c->buf);
            f(c->h, w);
            c->used = 0;
        }
    }
    memset(w, 0, sizeof w);
}

static void sha_final_words(sha_ctx *c, uint32_t out[8]) {
    uint64_t bits = c->total * 8;
    uint8_t pad = 0x80, zero = 0, len[8];
    for (int i = 0; i < 8; i++) len[i] = (uint8_t)(bits >> (56 - 8 * i));
    uint64_t keep = c->total;
    sha_update(c, &pad, 1);
    while (c->used != 56) sha_update(c, &zero, 1);
    sha_update(c, len, 8);
    c->total = keep;
    memcpy(out, c->h, 32);
    memset(c, 0, sizeof *c);
}

// ---- PBKDF2 -------------------------------------------------------------------------------

uint32_t nc_pbkdf2_sha256(const uint8_t *pw, size_t pw_len, const uint8_t *salt, size_t salt_len,
                          uint32_t max_rounds, uint32_t chunk, uint8_t out[32],
                          nc_progress_fn cb, void *ctx) {
    nc_compress_fn f = compress_fn();
    uint8_t key[64] = {0}, blockb[64];
    uint32_t w[16], ist[8], ost[8], u[8], t[8];
    sha_ctx c;

    if (max_rounds == 0) { memset(out, 0, 32); return 0; }
    if (chunk == 0) chunk = 1u << 18;

    // HMAC key: the passphrase, or its hash if longer than one block.
    if (pw_len > 64) {
        uint32_t kh[8];
        sha_init(&c, IV, 0);
        sha_update(&c, pw, pw_len);
        sha_final_words(&c, kh);
        for (int i = 0; i < 8; i++)
            for (int j = 0; j < 4; j++) key[4 * i + j] = (uint8_t)(kh[i] >> (24 - 8 * j));
        memset(kh, 0, sizeof kh);
    } else if (pw_len) {
        memcpy(key, pw, pw_len);
    }

    for (int i = 0; i < 64; i++) blockb[i] = key[i] ^ 0x36;
    load_words(w, blockb);
    memcpy(ist, IV, 32);
    f(ist, w);
    for (int i = 0; i < 64; i++) blockb[i] = key[i] ^ 0x5c;
    load_words(w, blockb);
    memcpy(ost, IV, 32);
    f(ost, w);

    // U1 = HMAC(key, salt || INT(1))
    static const uint8_t one[4] = {0, 0, 0, 1};
    uint32_t inner[8];
    sha_init(&c, ist, 64);
    sha_update(&c, salt, salt_len);
    sha_update(&c, one, 4);
    sha_final_words(&c, inner);
    memset(w, 0, sizeof w);
    memcpy(w, inner, 32);
    w[8] = 0x80000000u;
    w[15] = (64 + 32) * 8;
    memcpy(u, ost, 32);
    f(u, w);
    memcpy(t, u, 32);

    uint32_t done = 1;
    int status = 1;
    while (done < max_rounds) {
        // Chunks end on multiples of `chunk`, so progress lands on round numbers.
        uint32_t n = chunk - (done % chunk);
        if (n > max_rounds - done) n = max_rounds - done;
        iterate(ist, ost, u, t, n);
        done += n;
        if (cb) {
            status = cb(ctx, done);
            if (status <= 0) break;
        }
    }

    if (status < 0) {
        memset(out, 0, 32);
        done = 0;
    } else {
        for (int i = 0; i < 8; i++)
            for (int j = 0; j < 4; j++) out[4 * i + j] = (uint8_t)(t[i] >> (24 - 8 * j));
    }

    memset(key, 0, sizeof key); memset(blockb, 0, sizeof blockb); memset(w, 0, sizeof w);
    memset(ist, 0, sizeof ist); memset(ost, 0, sizeof ost); memset(u, 0, sizeof u);
    memset(t, 0, sizeof t); memset(inner, 0, sizeof inner);
    return done;
}
