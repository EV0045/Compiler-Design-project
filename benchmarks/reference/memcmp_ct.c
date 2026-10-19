#include <stddef.h>

/*
 * Hand-written constant-time reference for secret_memcmp.
 *
 * Always scans all n bytes (no early exit) and accumulates the
 * differences with OR/XOR, so timing depends only on n (public).
 * Returns 1 if the buffers differ, 0 if equal - same as the baseline.
 */
int secret_memcmp(
    const unsigned char *a,
    const unsigned char *b,
    int n
) {
    unsigned int diff = 0;

    for (int i = 0; i < n; i++) {
        diff |= (unsigned int)(a[i] ^ b[i]);
    }

    /* Branchless "diff != 0": top bit of (diff | -diff) is set iff diff != 0. */
    return (int)((diff | (0u - diff)) >> 31);
}
