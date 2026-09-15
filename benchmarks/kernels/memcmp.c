#include <stddef.h>

int secret_memcmp(const unsigned char *a, const unsigned char *b, int n)
{
    for (int i = 0; i < n; i++)
    {
        if (a[i] != b[i])
        {
            return 1;
        }
    }

    return 0;
}
