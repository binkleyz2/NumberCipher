// PBKDF2-HMAC-SHA256 with a 32-byte output (one block), tuned for long iteration counts.
//
// The work runs in chunks. After each chunk the callback is told how many iterations are
// done and returns:
//    1  keep going
//    0  stop now and keep the result (it is a valid PBKDF2 key for `done` iterations)
//   -1  cancel
// Stopping early is what lets Android aim for a fixed ~10 seconds on any device: a
// single-block PBKDF2 key for N iterations is just the running XOR after N steps.
#ifndef NC_PBKDF2_SHA256_H
#define NC_PBKDF2_SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*nc_progress_fn)(void *ctx, uint32_t done);

typedef enum {
    NC_BACKEND_PORTABLE = 0,
    NC_BACKEND_ARMV8_SHA2 = 1,
    NC_BACKEND_X86_SHANI = 2,
} nc_backend;

/// The fastest SHA-256 implementation this CPU supports (detected once, at runtime).
nc_backend nc_active_backend(void);
const char *nc_backend_name(nc_backend b);

/// Forces a backend (tests only). Returns 0 if the CPU doesn't support it.
int nc_force_backend(nc_backend b);

/// Runs up to `max_rounds` iterations. Returns the number of iterations the key in `out`
/// corresponds to, or 0 if cancelled (out is zeroed).
uint32_t nc_pbkdf2_sha256(const uint8_t *pw, size_t pw_len,
                          const uint8_t *salt, size_t salt_len,
                          uint32_t max_rounds, uint32_t chunk,
                          uint8_t out[32],
                          nc_progress_fn cb, void *ctx);

#ifdef __cplusplus
}
#endif

#endif
