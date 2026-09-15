int test_memcmp(const char *secret, const char *public_data, int n)
{
    for (int i = 0; i < n; i++)
    {
        if (secret[i] != public_data[i])
            return 0;
    }

    return 1;
}
