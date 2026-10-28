// SHA-256 using the ARMv8 Cryptography Extensions (SHA256H/H2/SU0/SU1).
// Present on nearly all 64-bit Android phones and tablets; used only when the CPU
// reports HWCAP_SHA2 at runtime. This file is compiled with -march=armv8-a+crypto.
#if defined(__aarch64__)
#include <arm_neon.h>
#include "sha256_internal.h"

#define RND(m, k)                                        \
    do {                                                 \
        uint32x4_t wk = vaddq_u32((m), vld1q_u32(k));    \
        uint32x4_t a0 = abcd;                            \
        abcd = vsha256hq_u32(abcd, efgh, wk);            \
        efgh = vsha256h2q_u32(efgh, a0, wk);             \
    } while (0)
#define SCHED(m0, m1, m2, m3) (m0) = vsha256su1q_u32(vsha256su0q_u32((m0), (m1)), (m2), (m3))

static inline void block(uint32x4_t *s0, uint32x4_t *s1,
                         uint32x4_t m0, uint32x4_t m1, uint32x4_t m2, uint32x4_t m3) {
    uint32x4_t abcd = *s0, efgh = *s1;
    const uint32_t *k = NC_K256;
    for (int r = 0; r < 3; r++, k += 16) {
        RND(m0, k + 0);  SCHED(m0, m1, m2, m3);
        RND(m1, k + 4);  SCHED(m1, m2, m3, m0);
        RND(m2, k + 8);  SCHED(m2, m3, m0, m1);
        RND(m3, k + 12); SCHED(m3, m0, m1, m2);
    }
    RND(m0, k + 0); RND(m1, k + 4); RND(m2, k + 8); RND(m3, k + 12);
    *s0 = vaddq_u32(*s0, abcd);
    *s1 = vaddq_u32(*s1, efgh);
}

void nc_compress_armv8(uint32_t state[8], const uint32_t w[16]) {
    uint32x4_t s0 = vld1q_u32(state), s1 = vld1q_u32(state + 4);
    block(&s0, &s1, vld1q_u32(w), vld1q_u32(w + 4), vld1q_u32(w + 8), vld1q_u32(w + 12));
    vst1q_u32(state, s0);
    vst1q_u32(state + 4, s1);
}

// The whole PBKDF2 loop with every value kept in vector registers.
void nc_iterate_armv8(const uint32_t ist[8], const uint32_t ost[8],
                      uint32_t u[8], uint32_t t[8], uint32_t n) {
    const uint32_t padw[4] = {0x80000000u, 0, 0, 0};
    const uint32_t lenw[4] = {0, 0, 0, (64 + 32) * 8};
    const uint32x4_t pad = vld1q_u32(padw), len = vld1q_u32(lenw);
    const uint32x4_t i0 = vld1q_u32(ist), i1 = vld1q_u32(ist + 4);
    const uint32x4_t o0 = vld1q_u32(ost), o1 = vld1q_u32(ost + 4);
    uint32x4_t u0 = vld1q_u32(u), u1 = vld1q_u32(u + 4);
    uint32x4_t t0 = vld1q_u32(t), t1 = vld1q_u32(t + 4);
    while (n--) {
        uint32x4_t h0 = i0, h1 = i1;
        block(&h0, &h1, u0, u1, pad, len);
        u0 = o0; u1 = o1;
        block(&u0, &u1, h0, h1, pad, len);
        t0 = veorq_u32(t0, u0);
        t1 = veorq_u32(t1, u1);
    }
    vst1q_u32(u, u0); vst1q_u32(u + 4, u1);
    vst1q_u32(t, t0); vst1q_u32(t + 4, t1);
}
#endif
