#include <stdint.h>

/*
 * Intentionally unsafe baseline.
 *
 * The branch:
 *
 *     if (secret_exp & 1)
 *
 * depends on the secret exponent.
 */

uint64_t mod_exp(
    uint64_t base,
    uint64_t secret_exp,
    uint64_t mod
) {
    uint64_t result = 1;

    while (secret_exp > 0) {

        if (secret_exp & 1) {
            result = (result * base) % mod;
        }

        base = (base * base) % mod;

        secret_exp >>= 1;
    }

    return result;
}
