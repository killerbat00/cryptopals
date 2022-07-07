#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "xor.h"
#include "hex.h"

#define max(a,b) \
    ({ __typeof__ (a) _a = (a); \
        __typeof__ (b) _b = (b); \
       _a > _b ? _a : _b; })

#define min(a,b) \
    ({ __typeof__ (a) _a = (a); \
        __typeof__ (b) _b = (b); \
       _a < _b ? _a : _b; })
/**
 * XORs two bytestrings together, returning the result (which must be free'd).
 * If one bytestring is smaller than the other, repeating-key XOR is used.
 * This will deteriorate into single-byte XOR if one bytestring is 1 element long.
 * @param b1 bytestring to XOR
 * @param b1len number of bytes in b1
 * @param b2 bytestring to XOR
 * @param b2len number of bytes in b2
 * @param outLen length of the XOR'd bytes
 * @return unsigned char pointer to the XOR'd bytes
 */
unsigned char* xor_bytes(const unsigned char *b1, size_t b1len, const unsigned char *b2, size_t b2len, size_t *outLen) {
    if (b1len == 0 || b2len == 0) {
        return NULL;
    }
    const unsigned char *maxBytes = b1len > b2len ? b1 : b2;
    const unsigned char *minBytes = b1len > b2len ? b2 : b1;
    *outLen = max(b1len, b2len);
    int minLen = (int) min(b1len, b2len);
    unsigned char *xored;

    if ((xored = calloc(*outLen + 1, sizeof(unsigned char))) == NULL) {
        return NULL;
    }

    for (int i = 0, j; i < *outLen; i++) {
        j = i % minLen;
        xored[i] = maxBytes[i] ^ minBytes[j];
    }

    return xored;
}

/**
 * XORs two equivalent-length hexstrings together returning
 * the resulting hex-encoded string (which must be free'd).
 * @param h1 hexstring to XOR
 * @param h2 hexstring to XOR
 * @return hex-encoded string of h1 XOR h2
 */
char* fixed_xor_hex(const char *h1, const char *h2) {
    size_t h1len = strlen(h1);
    size_t h2len = strlen(h2);
    if (h1len != h2len) {
        return NULL;
    }

    size_t olen = 0, o2len = 0;
    unsigned char *h1bytes;
    unsigned char *h2bytes;
    if ((h1bytes = hex2bytes(h1, &olen)) == NULL) {
        return NULL;
    }
    if ((h2bytes = hex2bytes(h2, &o2len)) == NULL) {
        free(h1bytes);
        return NULL;
    }

    if (olen != o2len) {
        free(h1bytes);
        free(h2bytes);
        return NULL;
    }

    size_t xoredLen = 0;
    unsigned char *xored = xor_bytes(h1bytes, olen, h2bytes, olen, &xoredLen);
    if (xored == NULL) {
        free(h1bytes);
        free(h2bytes);
        return NULL;
    }

    char *output = bytes2hex(xored, olen);
    free(h1bytes);
    free(h2bytes);
    free(xored);

    return output;
}

/**
 * XORs a single character against every byte of a hexstring.
 * @param h1 hexstring
 * @param h2 char to XOR
 * @param outLen length of the XOR'd bytes
 * @return bytestring of h1 XOR h2
 */
unsigned char* single_byte_xor_hex(const char *h1, const unsigned char h2, size_t *outLen) {
    size_t h1len = strlen(h1);

    if (h1len == 0) {
        return NULL;
    }

    size_t olen = 0;
    unsigned char *h1bytes = hex2bytes(h1, &olen);
    if (h1bytes == NULL || olen == 0) {
        return NULL;
    }

    unsigned char *xored = xor_bytes(h1bytes, olen, &h2, 1, outLen);
    if (xored == NULL || olen != *outLen) {
        *outLen = 0;
        free(h1bytes);
        return NULL;
    }

    free(h1bytes);
    return xored;
}

static const double english_frequencies[] = {
        .082, .015, .028, .043, .13, .022, .02, .061,
        .07, .0015, .0077, .04, .024, .067, .075,
        .019, .00095, .06, .063, .091, .028, .0098,
        .024, .0015, .02, .00074, .1716
}; // a, b, c, d ... <space>

/**
 * Calculates the Chi^2 score for a bytestring compared to
 * character frequencies in english ASCII text.
 * @param bytestring the bytestring to score
 * @param numBytes the number of bytes to score
 * @return the string's chi^2 score.
 */
double score_string(const unsigned char *bytestring, size_t numBytes) {
    if (numBytes == 0) {
        return -1;
    }

    int freq[27] = {0}, ignored = 0, i;
    for (i = 0; i < numBytes; i++) {
        unsigned char c = bytestring[i];
        if (isalpha(c)) {
            freq[tolower(c) - 97]++;
        } else if (isspace(c)) {
            freq[26]++;
        } else {
            ignored++;
        }
    }

    if (ignored >= numBytes / 4) { // skip if we ignored a quarter or more of the bytes
        return -1;
    }

    double score = 0;
    int len = (int)numBytes - ignored;
    for (i = 0; i < 27; i++) {
        int obs = freq[i];
        double expected = len * english_frequencies[i];
        double difference = obs - expected;
        score += (difference * difference / expected);
    }
    return score;
}

/**
 * For each of the 256 single-byte characters, determines the
 * probability the hexstring was XOR'd against that byte by XOR'ing the
 * hexstring against the byte, then calculating the chi^2 score
 * compared to english letter sentence frequency.
 * @param hexString hexstring to check
 * @param minScoreVal output of the minimum chi^2 score found
 * @return the (integer representation) byte that was likely used as the XOR key
 */
int probability_was_xored(const char *hexString, double *minScoreVal) {
    size_t len = strlen(hexString);
    double scores[256] = {0};
    int minScore = 256;

    for (int i = 0; i < 256; i++) {
        unsigned char *xored;
        size_t outLen = 0;
        if ((xored = single_byte_xor_hex(hexString, (unsigned char) i, &outLen)) == NULL) {
            continue;
        }
        if (outLen == 0 || outLen != len / 2) {
            free(xored);
            continue;
        }

        double score = score_string(xored, outLen);
        if (score == -1 || score == 0) {
            free(xored);
            continue;
        }
        scores[i] = score;
        minScore = minScore > 255 ? i : score < scores[minScore] ? i : minScore;
        free(xored);
    }
    if (minScore == 256) {
        return -1;
    }
    *minScoreVal = scores[minScore];
    return minScore;
}
