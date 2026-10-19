#include <stdint.h>

/*
 * Hand-written constant-time reference for mod_exp.
 *
 * The multiply is performed on every iteration and the result is kept
 * or discarded with a mask instead of `if (secret_exp & 1)`. The loop
 * runs a fixed 64 iterations so it does not depend on the exponent's
 * magnitude. Same results as the baseline for all inputs.
 */
uint64_t mod_exp(
    uint64_t base,
    uint64_t secret_exp,
    uint64_t mod
) {
    uint64_t result = 1;

    for (int i = 0; i < 64; i++) {
        uint64_t mask = 0 - (secret_exp & 1);      /* all ones if bit set */
        uint64_t multiplied = (result * base) % mod;

        result = (multiplied & mask) | (result & ~mask);

        base = (base * base) % mod;
        secret_exp >>= 1;
    }

    return result;
}
