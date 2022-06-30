/* -*- mode: C -*- */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

unsigned char* hex2bytes(const char *hexstring, int *numBytes) {
    int len = strlen(hexstring);
    if (len % 2 != 0) {
        return NULL;
    }

    *numBytes = len / 2;
    unsigned char* output = malloc(*numBytes);
    if (output == NULL) {
        return NULL;
    }

    for (int i = 0; i < len / 2; i++) {
        sscanf(hexstring, "%2hhx", &output[i]);
        hexstring += 2;
    }
    return output;
}

char* bytes2hex(const unsigned char *bytes, int numBytes) {
    char* output = malloc((numBytes * 2) + 1);
    if (output == NULL) {
        return NULL;
    }
    output[(numBytes * 2)] = '\0';
    char *ptr = &output[0];

    for (int i = 0; i < numBytes; i++) {
        ptr += sprintf(ptr, "%02X", bytes[i]);
    }
    return output;
}

int main(void) {
    const char *hexstring = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    printf("%s\n", hexstring);

    int outputLen;
    unsigned char *output = hex2bytes(hexstring, &outputLen);
    if (output == NULL) {
        printf("Problem converting hexstring to bytes.\n");
        return 1;
    }
    printf("%s\n", output);

    char* newhexstring = bytes2hex(output, outputLen);
    printf("%s\n", newhexstring);

    free(output);
    free(newhexstring);

    return 0;
}