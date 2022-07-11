#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hex.h"

unsigned char* hex2bytes(const char *hexstring, size_t *numBytes) {
    size_t len = strlen(hexstring);
    if (len % 2 != 0) {
        *numBytes = 0;
        return NULL;
    }

    *numBytes = (len / 2);
    unsigned char *output = calloc(*numBytes + 1,sizeof(unsigned char));
    if (output == NULL) {
        *numBytes = 0;
        return NULL;
    }

    for (int i = 0; i < *numBytes; i++) {
        sscanf(hexstring, "%2hhx", &output[i]);
        hexstring += 2;
    }
    return output;
}

char* bytes2hex(const unsigned char *bytes, size_t numBytes) {
    char* output = calloc((numBytes * 2) + 1, sizeof(char));
    if (output == NULL) {
        return NULL;
    }
    char *ptr = output;
    for (int i = 0; i < numBytes; i++) {
        ptr += sprintf(ptr, "%02x", bytes[i]);
    }
    output[numBytes * 2] = '\0';

    return output;
}

