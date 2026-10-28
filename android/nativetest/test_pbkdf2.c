// Host test for the native PBKDF2: prints keys for a set of cases so they can be compared
// with Python's hashlib, plus a speed figure. Not part of the app.
//   test_pbkdf2 [portable|armv8|shani]
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "../app/src/main/cpp/pbkdf2_sha256.h"

static uint32_t stop_at;
static int stopper(void *ctx, uint32_t done) { (void)ctx; return done >= stop_at ? 0 : 1; }
static int canceller(void *ctx, uint32_t done) { (void)ctx; (void)done; return -1; }

static void hex(const uint8_t *b) { for (int i = 0; i < 32; i++) printf("%02x", b[i]); }

int main(int argc, char **argv) {
    if (argc > 1) {
        nc_backend b = !strcmp(argv[1], "armv8") ? NC_BACKEND_ARMV8_SHA2
                     : !strcmp(argv[1], "shani") ? NC_BACKEND_X86_SHANI : NC_BACKEND_PORTABLE;
        if (!nc_force_backend(b)) { printf("BACKEND_UNAVAILABLE\n"); return 2; }
    }
    printf("backend %s\n", nc_backend_name(nc_active_backend()));

    const char *pws[] = {"", "a", "correct horse battery", "é-passé",
        "0123456789012345678901234567890123456789012345678901234567890123",           /* 64 */
        "01234567890123456789012345678901234567890123456789012345678901234",          /* 65 */
        "a much longer passphrase that is well over one sixty-four byte block in length, for sure"};
    const uint8_t salt[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    const uint32_t rounds[] = {1, 2, 3, 1000, 262145, 600000};
    uint8_t out[32];

    for (size_t i = 0; i < sizeof pws / sizeof *pws; i++)
        for (size_t r = 0; r < sizeof rounds / sizeof *rounds; r++) {
            uint32_t got = nc_pbkdf2_sha256((const uint8_t *)pws[i], strlen(pws[i]), salt, 16,
                                            rounds[r], 1000, out, NULL, NULL);
            printf("case %zu %u %u ", i, rounds[r], got); hex(out); printf("\n");
        }

    // Early stop: asking for 10M but stopping after the chunk that reaches 300,000.
    stop_at = 300000;
    uint32_t got = nc_pbkdf2_sha256((const uint8_t *)"stop", 4, salt, 16, 10000000, 100000, out, stopper, NULL);
    printf("stop %u ", got); hex(out); printf("\n");

    got = nc_pbkdf2_sha256((const uint8_t *)"stop", 4, salt, 16, 10000000, 100000, out, canceller, NULL);
    int zero = 1; for (int i = 0; i < 32; i++) zero &= out[i] == 0;
    printf("cancel %u zeroed=%d\n", got, zero);

    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    nc_pbkdf2_sha256((const uint8_t *)"speed", 5, salt, 16, 2000000, 1 << 18, out, NULL, NULL);
    clock_gettime(CLOCK_MONOTONIC, &b);
    double s = (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) / 1e9;
    printf("speed %.0f rounds/s\n", 2000000 / s);
    return 0;
}
