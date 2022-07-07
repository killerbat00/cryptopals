#ifndef CRYPTOPALS_B64_H
#define CRYPTOPALS_B64_H
#include <stdlib.h>

char* bytes2base64(const unsigned char *, size_t);
unsigned char* base642bytes(const char *, size_t *);

#endif //CRYPTOPALS_B64_H