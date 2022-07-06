/* -*- mode: C -*- */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

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

    if (ignored > numBytes / 4) { // spaces have a 20% probability
        return -1;
    }

    double score = 0;
    int len = (int)numBytes - ignored;
    for (i = 0; i < 27; i++) {
        int obs = freq[i];
        double expected = len * english_frequencies[i];
        double difference = obs - expected;
        score += difference * difference / expected;
    }
    return score;
}

int challenge_one() {
    char *hexstring = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    char *b64output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    size_t outputLen = 0;
    unsigned char *output = hex2bytes(hexstring, &outputLen);
    if (output == NULL) {
        return 1;
    }

    char* newhexstring = bytes2hex(output, outputLen);
    if (newhexstring == NULL) {
        free(output);
        return 1;
    }

    if (strcmp(hexstring, newhexstring) != 0) {
        printf("Hexstring conversion failed.\n");
        printf("Original\t%s\n", hexstring);
        printf("new     \t%s\n", newhexstring);
    }

    char* base64string = bytes2base64(output, outputLen);
    if (base64string == NULL) {
        free(output);
        free(newhexstring);
        return 1;
    }

    if (strcmp(b64output, base64string) != 0) {
        printf("Hexstring conversion does not match expected value.\n");
        printf("Original\t%s\n", b64output);
        printf("New     \t%s\n", base64string);
    }

    size_t outputLen2 = 0;
    unsigned char *b64bytes = base642bytes(base64string, &outputLen2);
    if (b64bytes == NULL) {
        printf("Problem converting base64 string to bytes.\n");
        free(output);
        free(newhexstring);
        free(base64string);
        return 1;
    }

    if (memcmp(output, b64bytes, outputLen2) != 0 || outputLen != outputLen2) {
        printf("Bytes post base64 encoding & decoding don't match.");
        printf("Original\t%s\n", output);
        printf("New     \t%s\n", b64bytes);
    }

    free(output);
    free(newhexstring);
    free(base64string);
    free(b64bytes);

    return 0;
}

int challenge_two() {
    char *a = "1c0111001f010100061a024b53535009181c";
    char *b = "686974207468652062756c6c277320657965";
    char *expectedOutput = "746865206b696420646f6e277420706c6179";

    char *output = fixed_xor_hex(a, b);
    if (output == NULL) {
        return 1;
    }
    if (strcmp(expectedOutput, output) != 0) {
        printf("Fixed XOR did not match expected value.\n");
        printf("Expected:\t%s\n", expectedOutput);
        printf("Output:  \t%s\n", output);
        return 1;
    }
    free(output);
    return 0;
}

int challenge_three() {
    char *hexString = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    size_t len = strlen(hexString);
    double scores[256] = {0};
    scores[255] = UINT32_MAX;
    int minScore = 255;

    for (int i = 0; i < 256; i++) {
        unsigned char *xored;
        size_t outLen = 0;
        if ((xored = single_byte_xor_hex(hexString, (unsigned char) i, &outLen)) == NULL) {
            continue;
        }
        if (outLen == 0 || outLen != len / 2) {
            continue;
        }

        double score = score_string(xored, outLen);
        if (score == -1) {
            free(xored);
            continue;
        }
        scores[i] = score;
        minScore = score < scores[minScore] ? i : minScore;
        free(xored);
    }

    if ((char) minScore != 'X') {
        return 1;
    }

    unsigned char *likelyMsg;
    size_t outLen = 0;
    if ((likelyMsg = single_byte_xor_hex(hexString, (unsigned char) minScore, &outLen)) == NULL) {
        return 1;
    }

    if (strcmp((char *)likelyMsg, "Cooking MC's like a pound of bacon") != 0) {
        return 1;
    }
    free(likelyMsg);
    return 0;
}

int main(void) {
    if (challenge_one() != 0) {
        printf("Challenge one failed.\n");
        return 1;
    }

    if (challenge_two() != 0) {
        printf("Challenge two failed.\n");
        return 1;
    }

    if (challenge_three() != 0) {
        printf("Challenge three failed.\n");
        return 1;
    }
    return 0;
}
