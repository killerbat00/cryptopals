#ifndef CRYPTOPALS_XOR_H
#define CRYPTOPALS_XOR_H
#include "hex.h"

unsigned char* xor_bytes(const unsigned char *, size_t, const unsigned char *, size_t, size_t *);
char* fixed_xor_hex(const char *, const char *);
unsigned char* single_byte_xor_hex(const char *, unsigned char, size_t *);
double score_string(const unsigned char *, size_t);
int probability_was_xored(const char *hexString, double *minScoreVal);
int find_likely_keysize(unsigned char *, size_t, int, int);
unsigned char* transpose_and_solve(const unsigned char *, size_t, int);

#endif //CRYPTOPALS_XOR_H
