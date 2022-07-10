/* -*- mode: C -*- */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include "include/hex.h"
#include "include/b64.h"
#include "include/xor.h"
#include "include/aes.h"

/**
 * https://cryptopals.com/sets/1/challenges/1
 */
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

/**
 * https://cryptopals.com/sets/1/challenges/2
 */
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

/**
 * https://cryptopals.com/sets/1/challenges/3
 */
int challenge_three() {
    char *hexString = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    double minScoreVal;
    int minScore = probability_was_xored(hexString, &minScoreVal);
    if (minScore == -1) {
        return 1;
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

/**
 * https://cryptopals.com/sets/1/challenges/4
 */
int challenge_four() {
    FILE *fp;
    char line[62];
    int lc = 0;
    char **lines;
    double overallMinScore = 999999999999999;
    int minScoreIdx = 327;
    unsigned char minkey;

    if ((fp = fopen("/home/ddnull/Documents/dev/cryptopals/challenge_three", "rb")) == NULL) {
        return 1;
    }

    if ((lines = calloc(327, sizeof(char *))) == NULL) {
        return 1;
    }
    for (int i = 0; i < 327; i++) {
        if ((lines[i] = calloc(60 + 1, sizeof(char))) == NULL) {
            for (int j = 0; j < i; j++) {
                free(lines[j]);
            }
            return 1;
        }
    }

    while (fgets(line, sizeof(char) * 62, fp) != NULL) {
        size_t lineLen = strlen(line);
        memcpy(lines[lc], line, lineLen-1);
        lines[lc][lineLen - 1] = '\0';
        lc++;
    }
    fclose(fp);

    for (int i = 0; i < 327; i++) {
        double minScoreVal;
        int s = probability_was_xored(lines[i], &minScoreVal);
        if (s == -1) {
            continue;
        }
        if (minScoreVal < overallMinScore) {
            overallMinScore = minScoreVal;
            minScoreIdx = i;
            minkey = (unsigned char) s;
        }
    }

    int ret = 0;
    if (minScoreIdx == 327) {
        ret = 1;
        goto cleanup;
    }

    if (minkey != '5') {
        ret = 1;
        goto cleanup;
    }

    size_t outBytes;
    unsigned char *decoded = single_byte_xor_hex(lines[minScoreIdx], minkey, &outBytes);
    if (decoded == NULL) {
        ret = 1;
        goto cleanup;
    }
    if (strcmp((char *)decoded, "Now that the party is jumping\n") != 0) {
        ret = 1;
        free(decoded);
        goto cleanup;
    }
    free(decoded);

cleanup:
    for (int i = 0; i < 327; i++) {
        free(lines[i]);
    }
    free(lines);
    return ret;
}

/*
 * https://cryptopals.com/sets/1/challenges/5
 */
int challenge_five() {
    char *input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    size_t l = strlen(input);
    char *key = "ICE";

    size_t outNum;
    unsigned char *result = xor_bytes((unsigned char *)input, l, (unsigned char *)key, 3, &outNum);
    if (result == NULL) {
        return 1;
    }
    char *encoded = bytes2hex(result, outNum);
    if (encoded == NULL) {
        free(result);
        return 1;
    }

    if (strcmp(encoded, "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f") != 0) {
        free(result);
        free(encoded);
        return 1;
    }

    free(result);
    free(encoded);
    return 0;
}

/**
 * mmaps a file and returns the pointer
 * @param filename the filename to mmap
 * @return the pointer to the mmap'd file, must be free'd. NULL on error
 */
unsigned char *mmap_file(char *filename, size_t *size) {
    int fd;
    struct stat s;

    if ((fd = open(filename, O_RDONLY)) == -1)
        return NULL;

    if (fstat(fd, &s) == -1)
        return NULL;

    *size = s.st_size;
    unsigned char *outBytes = mmap(0, *size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (outBytes == MAP_FAILED)
        return NULL;

    return outBytes;
}

/*
 * https://cryptopals.com/sets/1/challenges/6
 */
int challenge_six() {
    size_t size;
    char *filename = "/home/ddnull/Documents/dev/cryptopals/challenge_six";

    unsigned char *b64bytes = mmap_file(filename, &size);
    size_t numBytes;
    unsigned char *bytes = base642bytes((char *) b64bytes, &numBytes);
    if (bytes == NULL) {
        return 1;
    }

    int keysize = find_likely_keysize(bytes, numBytes, 2, 40);
    char *key = transpose_and_solve(bytes, numBytes, keysize);
    if (key != NULL) {
        if (strcmp(key, "Terminator X: Bring the noise") != 0) {
            return 1;
        }
        free(key);
    }

    free(bytes);
    munmap(b64bytes, size);

    return 0;
}

int challenge_seven() {
    size_t size;
    char *filename = "/home/ddnull/Documents/dev/cryptopals/challenge_seven_bytes";

    //unsigned char *b64bytes = mmap_file(filename, &size);
    unsigned char *bytes = mmap_file(filename, &size);
    //size_t numBytes;
    //unsigned char *bytes = base642bytes((char *) b64bytes, &numBytes);
    if (bytes == NULL)
        return 1;

    int outLen;
    unsigned char *decoded = decrypt_aes_128_ecb(bytes, size, "YELLOW SUBMARINE", &outLen);
    //fwrite(decoded, 1, outLen, stdout);

    free(decoded);
    //free(bytes);
    //munmap(b64bytes, size);
    munmap(bytes, size);
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

    if (challenge_four() != 0) {
        printf("Challenge four failed.\n");
        return 1;
    }

    if (challenge_five() != 0) {
        printf("Challenge five failed.\n");
        return 1;
    }

    if (challenge_six() != 0) {
        printf("Challenge six failed.\n");
        return 1;
    }

    if (challenge_seven() != 0) {
        printf("Challenge seven failed.\n");
        return 1;
    }

    return 0;
}
