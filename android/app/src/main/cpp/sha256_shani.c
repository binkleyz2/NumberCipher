// SHA-256 using Intel/AMD SHA extensions (Chromebooks, x86 tablets, emulators).
// Used only when CPUID reports SHA support. Compiled with -msse4.1 -mssse3 -msha.
#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#include "sha256_internal.h"

void nc_compress_shani(uint32_t state[8], const uint32_t w[16]) {
    // Convert state to the ABEF / CDGH layout the instructions use.
    __m128i tmp = _mm_loadu_si128((const __m128i *)&state[0]);
    __m128i st1 = _mm_loadu_si128((const __m128i *)&state[4]);
    tmp = _mm_shuffle_epi32(tmp, 0xB1);          // CDAB
    st1 = _mm_shuffle_epi32(st1, 0x1B);          // EFGH
    __m128i st0 = _mm_alignr_epi8(tmp, st1, 8);  // ABEF
    st1 = _mm_blend_epi16(st1, tmp, 0xF0);       // CDGH
    const __m128i save0 = st0, save1 = st1;

    // Message words are already host-order values, so no byte swap is needed.
    __m128i m[4];
    for (int i = 0; i < 4; i++) m[i] = _mm_loadu_si128((const __m128i *)&w[4 * i]);

    for (int g = 0; g < 16; g++) {
        if (g >= 4) {
            __m128i a = m[g & 3], b = m[(g + 1) & 3], c = m[(g + 2) & 3], d = m[(g + 3) & 3];
            __m128i x = _mm_sha256msg1_epu32(a, b);
            x = _mm_add_epi32(x, _mm_alignr_epi8(d, c, 4));
            m[g & 3] = _mm_sha256msg2_epu32(x, d);
        }
        __m128i msg = _mm_add_epi32(m[g & 3], _mm_loadu_si128((const __m128i *)&NC_K256[4 * g]));
        st1 = _mm_sha256rnds2_epu32(st1, st0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        st0 = _mm_sha256rnds2_epu32(st0, st1, msg);
    }

    st0 = _mm_add_epi32(st0, save0);
    st1 = _mm_add_epi32(st1, save1);

    tmp = _mm_shuffle_epi32(st0, 0x1B);          // FEBA
    st1 = _mm_shuffle_epi32(st1, 0xB1);          // DCHG
    st0 = _mm_blend_epi16(tmp, st1, 0xF0);       // DCBA
    st1 = _mm_alignr_epi8(st1, tmp, 8);          // HGFE
    _mm_storeu_si128((__m128i *)&state[0], st0);
    _mm_storeu_si128((__m128i *)&state[4], st1);
}
#endif
