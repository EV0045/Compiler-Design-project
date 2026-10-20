#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#if defined(__has_include)
#if __has_include(<valgrind/memcheck.h>)
#include <valgrind/memcheck.h>
#endif
#endif

#ifndef VALGRIND_MAKE_MEM_UNDEFINED
#define VALGRIND_MAKE_MEM_UNDEFINED(addr, len) ((void)0)
#endif

/* Kernel function declarations */
uint8_t aes_sbox(uint8_t input);
int secret_memcmp(const unsigned char *a, const unsigned char *b, int n);
uint64_t mod_exp(uint64_t base, uint64_t secret_exp, uint64_t mod);

int main(int argc, char **argv) {
    const char *kernel = (argc > 1) ? argv[1] : "aes_sbox";

    if (strcmp(kernel, "aes_sbox") == 0) {
        uint8_t secret_input = 0x5A;
        VALGRIND_MAKE_MEM_UNDEFINED(&secret_input, sizeof(secret_input));
        volatile uint8_t res = aes_sbox(secret_input);
        (void)res;
    } else if (strcmp(kernel, "memcmp") == 0) {
        unsigned char secret_a[16] = "secret_password";
        unsigned char secret_b[16] = "secret_passw0rd";
        VALGRIND_MAKE_MEM_UNDEFINED(secret_a, sizeof(secret_a));
        VALGRIND_MAKE_MEM_UNDEFINED(secret_b, sizeof(secret_b));
        volatile int res = secret_memcmp(secret_a, secret_b, 15);
        (void)res;
    } else if (strcmp(kernel, "mod_exp") == 0) {
        uint64_t base = 3;
        uint64_t secret_exp = 0x12345678ULL;
        uint64_t mod = 0xFFFFFFFBULL;
        VALGRIND_MAKE_MEM_UNDEFINED(&secret_exp, sizeof(secret_exp));
        volatile uint64_t res = mod_exp(base, secret_exp, mod);
        (void)res;
    } else {
        fprintf(stderr, "Unknown kernel: %s\n", kernel);
        return 1;
    }

    return 0;
}
