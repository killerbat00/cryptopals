#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hex.h"

/**
 * @brief Converts a hexstring to the equivalent bytestring.
 *
 * @param hexstring the hexstring to convert.
 * @param numBytes contains the number of bytes in the resulting string.
 * @return unsigned char* of resulting bytes. MUST BE free'D!
 */
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

/**
 * @brief Converts a bytestring to the equivalent hexstring.
 *
 * @param bytes the bytes to convert.
 * @param numBytes the number of bytes to convert.
 * @return char* of the resulting hexstring. MUST BE free'D!
 */
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

