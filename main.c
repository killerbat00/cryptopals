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

unsigned char* base642bytes(const char* base64string, size_t* numBytes) {
    size_t len = strlen(base64string);
    /* will be at least this big but we may skip whitespace */
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

char* fixed_xor_hex(const char *h1, const char *h2) {
    size_t h1len = strlen(h1);
    size_t h2len = strlen(h2);
    if (h1len != h2len) {
        return NULL;
    }

    size_t olen = 0;
    unsigned char *h1bytes = hex2bytes(h1, &olen);
    if (h1bytes == NULL) {
        return NULL;
    }

    size_t o2len = 0;
    unsigned char *h2bytes = hex2bytes(h2, &o2len);
    if (h2bytes == NULL) {
        free(h1bytes);
        return NULL;
    }

    if (olen != o2len) {
        free(h1bytes);
        free(h2bytes);
        return NULL;
    }

    unsigned char *xored = calloc(olen + 1, sizeof(unsigned char));
    if (xored == NULL) {
        free(h1bytes);
        free(h2bytes);
        return NULL;
    }

    for (int i = 0; i < olen; i++) {
        xored[i] = h1bytes[i] ^ h2bytes[i];
    }

    char *output = bytes2hex(xored, olen);
    free(h1bytes);
    free(h2bytes);
    free(xored);

    return output;
}

char* single_byte_xor_hex(const char *h1, const unsigned char h2) {
    size_t h1len = strlen(h1);

    if (h1len == 0 || h2 == '\0') {
        return NULL;
    }

    size_t olen = 0;
    unsigned char *h1bytes = hex2bytes(h1, &olen);
    if (h1bytes == NULL || olen == 0) {
        return NULL;
    }

    unsigned char *xored = calloc(olen + 1, sizeof(unsigned char));
    if (xored == NULL) {
        free(h1bytes);
        return NULL;
    }

    for (int i = 0; i < olen; i++) {
        xored[i] = h1bytes[i] ^ h2;
    }

    char *output = bytes2hex(xored, olen);
    free(h1bytes);
    free(xored);

    return output;
}

static const unsigned char kLewendFrequency[] = "etaoinshrdlcumwfgypbvkjxqz";
static const double english_frequencies[] = {
        .082, .015, .028, .043, .13, .022, .02, .061,
        .07, .0015, .0077, .04, .024, .067, .075,
        .019, .00095, .06, .063, .091, .028, .0098,
        .024, .0015, .02, .00074, .1716
}; // a, b, c, d ... <space>

unsigned char* char_frequency(const unsigned char *bytestring, size_t numBytes, size_t *outBytes) {
    if (numBytes == 0) {
        return NULL;
    }

    unsigned char freq[256] = {0};
    unsigned char chars[256] = {0};

    for (int i = 0; i < 256; i++) {
        chars[i] = (unsigned char) i;
    }

    for (int i = 0; i < numBytes; i++) {
        freq[tolower(bytestring[i])]++;
    }

    *outBytes += freq[0] > 0;
    for (int i = 1; i < 256; i++) {
        if (freq[i] > 0) {
            *outBytes += 1;
        }
        int j = i;
        while (j > 0 && freq[j-1] < freq[j]) {
            unsigned char tmp = freq[j];
            unsigned char tmp2 = chars[j];
            freq[j] = freq[j-1];
            chars[j] = chars[j-1];
            freq[j-1] = tmp;
            chars[j-1] = tmp2;
            j -= 1;
        }
    }

    unsigned char *output = calloc(*outBytes + 1, sizeof(unsigned char));
    if (output == NULL) {
        return NULL;
    }

    int j = 0;
    for (int i = 0; i < *outBytes; i++) {
        if (!isspace(chars[i]) && !ispunct(chars[i])) {
            output[j] = chars[i];
            j += 1;
        }
    }
    *outBytes = (size_t) j;
    return output;
}

char single_byte_xor_cipher(const char *hexstring) {
    size_t len = strlen(hexstring);
    if (len == 0) {
        return '\0';
    }

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

    size_t numBytes = 0;
    unsigned char testString[] = {'T','h','i','s',' ', 'i', 's', ' ','m', 'y', ' ', 't', 'e', 's', 't', ' ', 's', 't', 'r', 'i', 'n', 'g', '.'};
    unsigned char *freqString = char_frequency(testString, 23, &numBytes);
    printf("%s\n", freqString);

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
