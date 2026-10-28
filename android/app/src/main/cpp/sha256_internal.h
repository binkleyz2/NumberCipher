#ifndef NC_SHA256_INTERNAL_H
#define NC_SHA256_INTERNAL_H

#include <stdint.h>

// One SHA-256 compression: state[8] += f(state, w[16]). Message words are host-order
// 32-bit values (already big-endian decoded), so PBKDF2's inner loop never touches bytes.
typedef void (*nc_compress_fn)(uint32_t state[8], const uint32_t w[16]);

// Runs `n` PBKDF2 iterations: u = HMAC(u); t ^= u. ist/ost are the precomputed HMAC
// inner/outer states (after the key block).
typedef void (*nc_iterate_fn)(const uint32_t ist[8], const uint32_t ost[8],
                              uint32_t u[8], uint32_t t[8], uint32_t n);

extern const uint32_t NC_K256[64];

void nc_compress_portable(uint32_t state[8], const uint32_t w[16]);
void nc_iterate_generic(nc_compress_fn compress, const uint32_t ist[8], const uint32_t ost[8],
                        uint32_t u[8], uint32_t t[8], uint32_t n);

#if defined(__aarch64__)
void nc_compress_armv8(uint32_t state[8], const uint32_t w[16]);
void nc_iterate_armv8(const uint32_t ist[8], const uint32_t ost[8],
                      uint32_t u[8], uint32_t t[8], uint32_t n);
#endif

#if defined(__x86_64__) || defined(__i386__)
void nc_compress_shani(uint32_t state[8], const uint32_t w[16]);
#endif

#endif
