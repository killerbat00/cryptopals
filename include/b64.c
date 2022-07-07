#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "b64.h"

#define B64WHITESPACE 64
#define B64EQUALS     65
#define B64INVALID    66

static const unsigned char table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const unsigned char decode[] = {
        66,66,66,66,66,66,66,66,66,66,64,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
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
 * Encodes an array of bytes to a base64-encoded string.
 * @param bytes the bytes to base64 encode
 * @param numBytes the number of bytes to encode
 * @return base64-encoded string of bytes
 */
char* bytes2base64(const unsigned char* bytes, size_t numBytes) {
    unsigned char *out, *pos;
    const unsigned char *end, *in;

    size_t olen = (4*((numBytes + 2) / 3));
    if (olen < numBytes) {
        return NULL;
    }

    char* output = calloc(olen + 1, sizeof(char));
    if (output == NULL) {
        return NULL;
    }
    output[olen] = '\0';

    out = (unsigned char *)&output[0];
    end = bytes + numBytes;
    in = bytes;
    pos = out;
    while (end - in >= 3) {
        *pos++ = table[in[0] >> 2]; // in[0] / 2 / 2
        *pos++ = table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
        *pos++ = table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
        *pos++ = table[in[2] & 0x3f];
        in += 3;
    }

    if (end - in) {
        *pos++ = table[in[0] >> 2];
        if (end - in == 1) {
            *pos++ = table[(in[0] & 0x03) << 4];
            *pos++ = '=';
        } else {
            *pos++ = table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
            *pos++ = table[(in[1] & 0x0f) << 2];
        }
        *pos++ = '=';
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
    size_t len = strlen(base64string);
    /* will be at least this big, but we may skip whitespace */
    *numBytes = ((len / 4) * 3);

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
        unsigned char c = decode[(unsigned int) *base64string++];

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

