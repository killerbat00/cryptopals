#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "b64.h"

#define B64WHITESPACE 64
#define B64EQUALS     65
#define B64INVALID    66

static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const unsigned char decode[] = {
        66,66,66,66,66,66,66,66,66,64,64,66,66,64,66,66,66,66,66,66,66,66,66,66,66,
        66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,62,66,66,66,63,52,53,
        54,55,56,57,58,59,60,61,66,66,66,65,66,66,66, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,66,66,66,66,66,66,26,27,28,
        29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,66,66,
        66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
        66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
        66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
        66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
        66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
        66,66,66,66,66,66
};

/**
 * Size of the b64 encoded data.
 * @param inlen length of input
 * @return Size of the b64 encoded data
 */
size_t b64_size(size_t inlen) {
    size_t ret;

    ret = inlen;
    if (inlen % 3 != 0)
        ret += 3 - (inlen % 3);
    ret /= 3;
    ret *= 4;
    return ret;
}

/**
 * Number of bytes that will be decoded from a b64 string.
 * @param b64 encoded string
 * @return Number of bytes that will be decoded from a b64 string.
 */
size_t byte_size(const char *b64string) {
    size_t len;
    size_t ret;
    size_t i;
    if (b64string == NULL)
        return -1;

    len = strlen(b64string);
    ret = len / 4 * 3;
    for (i=len; i -->0; ) {
        if (b64string[i] == '=') {
            ret--;
        } else {
            break;
        }
    }
    return ret;
}

/**
 * Encodes an array of bytes to a base64-encoded string.
 * @param bytes the bytes to base64 encode
 * @param numBytes the number of bytes to encode
 * @return base64-encoded string of bytes
 */
char* bytes2base64(const unsigned char* bytes, size_t numBytes) {
    char *output;
    size_t olen;
    size_t i;
    size_t j;
    size_t v;

    if (bytes == NULL || numBytes == 0)
        return NULL;

    olen = b64_size(numBytes);
    output = calloc(olen + 1, sizeof(char));
    if (output == NULL)
        return NULL;
    output[olen] = '\0';

    for (i = 0, j = 0; i < numBytes; i+=3, j+= 4) {
        v = bytes[i];
        v = i+1 < numBytes ? v << 8 | bytes[i+1] : v << 8;
        v = i+2 < numBytes ? v << 8 | bytes[i+2] : v << 8;

        output[j] = table[(v >> 18) & 0x3F];
        output[j+1] = table[(v >> 12) & 0x3F];
        if (i + 1 < numBytes) {
            output[j+2] = table[(v >> 6) & 0x3F];
        } else {
            output[j+2] = '=';
        }

        if (i + 2 < numBytes) {
            output[j+3] = table[v & 0x3F];
        } else {
            output[j+3] = '=';
        }
    }

    return output;
}

/**
 * Decodes a base64-encoded string into an array of bytes.
 * @param base64string base64-encoded string
 * @param numBytes number of bytes in output
 * @return base64 decoded bytes
 */
unsigned char* base642bytes(const char* base64string, size_t* numBytes) {
    if (base64string == NULL)
        return NULL;

    size_t len = strlen(base64string);
    *numBytes = byte_size(base64string);
    unsigned char *output = calloc(*numBytes + 1, sizeof(unsigned char));
    if (output == NULL) {
        *numBytes = 0;
        return NULL;
    }

    unsigned char *start = output;
    const char *end = base64string + len;
    char iter = 0;
    uint32_t buf = 0;
    size_t realLen = 0;

    while (base64string < end) {
        int c = decode[(int) *base64string++];

        switch (c) {
            case B64WHITESPACE:
                continue;
            case B64INVALID:
                return NULL;
            case B64EQUALS:
                base64string = end;
                continue;
            default:
                buf = buf << 6 | c;
                iter++;
                if (iter == 4) {
                    if ((realLen += 3) > *numBytes) return NULL;
                    *(output++) = (buf >> 16) & 255;
                    *(output++) = (buf >> 8) & 255;
                    *(output++) = buf & 255;
                    buf = 0;
                    iter = 0;
                }
        }
    }

    if (iter == 3) {
        if ((realLen += 2) > *numBytes) return NULL;
        *(output++) = (buf >> 10) & 255;
        *(output++) = (buf >> 2) & 255;
    } else if (iter == 2) {
        if (++realLen > *numBytes) return NULL;
        *(output++) = (buf >> 4) & 255;
    }

    *numBytes = realLen;
    void *tmp = realloc(start, *numBytes + 1);
    if (tmp != NULL) {
        start = tmp;
    }
    return start;
}

