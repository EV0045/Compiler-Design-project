#include <stddef.h>

/*
 * Intentionally unsafe baseline.
 *
 * The loop exits early when a mismatch is found.
 * If a and b contain secret data, the control flow
 * can depend on secret information.
 */

int secret_memcmp(
    const unsigned char *a,
    const unsigned char *b,
    int n
) {
    for (int i = 0; i < n; i++) {

        if (a[i] != b[i]) {
            return 1;
        }
    }

    return 0;
}
//this is leaky as eg - a has apple b has axe and it exits in 1 millisecond then hacker knows first letter is A so this is problem 
