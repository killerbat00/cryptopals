#ifndef CRYPTOPALS_HEX_H
#define CRYPTOPALS_HEX_H
#include <stdlib.h>

unsigned char* hex2bytes(const char *, size_t *);
char* bytes2hex(const unsigned char *, size_t);

#endif //CRYPTOPALS_HEX_H
