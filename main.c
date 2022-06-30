/* -*- mode: C -*- */
#include <stdio.h>
#include <stdlib.h>
#include "include/hex.h"

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
