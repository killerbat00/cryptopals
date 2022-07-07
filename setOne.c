/* -*- mode: C -*- */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/hex.h"
#include "include/b64.h"
#include "include/xor.h"

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

    if ((fp = fopen("/home/ddnull/Documents/dev/cryptopals/encoded_strings", "rb")) == NULL) {
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

/*
 * https://cryptopals.com/sets/1/challenges/6
 */
static const char *b64data = "HUIfTQsPAh9PE048GmllH0kcDk4TAQsHThsBFkU2AB4BSWQgVB0dQzNTTmVSBgBHVBwNRU0HBAxTEjwMHghJGgkRTxRMIRpHKwAFHUdZEQQJAGQmB1MANxYGDBoXQR0BUlQwXwAgEwoFR08SSAhFTmU+Fgk4RQYFCBpGB08fWXh+amI2DB0PQQ1IBlUaGwAdQnQEHgFJGgkRAlJ6f0kASDoAGhNJGk9FSA8dDVMEOgFSGQELQRMGAEwxX1NiFQYHCQdUCxdBFBZJeTM1CxsBBQ9GB08dTnhOSCdSBAcMRVhICEEATyBUCHQLHRlJAgAOFlwAUjBpZR9JAgJUAAELB04CEFMBJhAVTQIHAh9PG054MGk2UgoBCVQGBwlTTgIQUwg7EAYFSQ8PEE87ADpfRyscSWQzT1QCEFMaTwUWEXQMBk0PAg4DQ1JMPU4ALwtJDQhOFw0VVB1PDhxFXigLTRkBEgcKVVN4Tk9iBgELR1MdDAAAFwoFHww6Ql5NLgFBIg4cSTRWQWI1Bk9HKn47CE8BGwFTQjcEBx4MThUcDgYHKxpUKhdJGQZZVCFFVwcDBVMHMUV4LAcKQR0JUlk3TwAmHQdJEwATARNFTg5JFwQ5C15NHQYEGk94dzBDADsdHE4UVBUaDE5JTwgHRTkAUmc6AUETCgYAN1xGYlUKDxJTEUgsAA0ABwcXOwlSGQELQQcbE0c9GioWGgwcAgcHSAtPTgsAABY9C1VNCAINGxgXRHgwaWUfSQcJABkRRU8ZAUkDDTUWF01jOgkRTxVJKlZJJwFJHQYADUgRSAsWSR8KIgBSAAxOABoLUlQwW1RiGxpOCEtUYiROCk8gUwY1C1IJCAACEU8QRSxORTBSHQYGTlQJC1lOBAAXRTpCUh0FDxhUZXhzLFtHJ1JbTkoNVDEAQU4bARZFOwsXTRAPRlQYE042WwAuGxoaAk5UHAoAZCYdVBZ0ChQLSQMYVAcXQTwaUy1SBQsTAAAAAAAMCggHRSQJExRJGgkGAAdHMBoqER1JJ0dDFQZFRhsBAlMMIEUHHUkPDxBPH0EzXwArBkkdCFUaDEVHAQANU29lSEBAWk44G09fDXhxTi0RAk4ITlQbCk0LTx4cCjBFeCsGHEETAB1EeFZVIRlFTi4AGAEORU4CEFMXPBwfCBpOAAAdHUMxVVUxUmM9ElARGgZBAg4PAQQzDB4EGhoIFwoKUDFbTCsWBg0OTwEbRSonSARTBDpFFwsPCwIATxNOPBpUKhMdTh5PAUgGQQBPCxYRdG87TQoPD1QbE0s9GkFiFAUXR0cdGgkADwENUwg1DhdNAQsTVBgXVHYaKkg7TgNHTB0DAAA9DgQACjpFX0BJPQAZHB1OeE5PYjYMAg5MFQBFKjoHDAEAcxZSAwZOBREBC0k2HQxiKwYbR0MVBkVUHBZJBwp0DRMDDk5rNhoGACFVVWUeBU4MRREYRVQcFgAdQnQRHU0OCxVUAgsAK05ZLhdJZChWERpFQQALSRwTMRdeTRkcABcbG0M9Gk0jGQwdR1ARGgNFDRtJeSchEVIDBhpBHQlSWTdPBzAXSQ9HTBsJA0UcQUl5bw0KB0oFAkETCgYANlVXKhcbC0sAGgdFUAIOChZJdAsdTR0HDBFDUk43GkcrAAUdRyonBwpOTkJEUyo8RR8USSkOEENSSDdXRSAdDRdLAA0HEAAeHQYRBDYJC00MDxVUZSFQOV1IJwYdB0dXHRwNAA9PGgMKOwtTTSoBDBFPHU54W04mUhoPHgAdHEQAZGU/OjV6RSQMBwcNGA5SaTtfADsXGUJHWREYSQAnSARTBjsIGwNOTgkVHRYANFNLJ1IIThVIHQYKAGQmBwcKLAwRDB0HDxNPAU94Q083UhoaBkcTDRcAAgYCFkU1RQUEBwFBfjwdAChPTikBSR0TTwRIEVIXBgcURTULFk0OBxMYTwFUN0oAIQAQBwkHVGIzQQAGBR8EdCwRCEkHElQcF0w0U05lUggAAwANBxAAHgoGAwkxRRMfDE4DARYbTn8aKmUxCBsURVQfDVlOGwEWRTIXFwwCHUEVHRcAMlVDKRsHSUdMHQMAAC0dCAkcdCIeGAxOazkABEk2HQAjHA1OAFIbBxNJAEhJBxctDBwKSRoOVBwbTj8aQS4dBwlHKjUECQAaBxscEDMNUhkBC0ETBxdULFUAJQAGARFJGk9FVAYGGlMNMRcXTRoBDxNPeG43TQA7HRxJFUVUCQhBFAoNUwctRQYFDE43PT9SUDdJUydcSWRtcwANFVAHAU5TFjtFGgwbCkEYBhlFeFsABRcbAwZOVCYEWgdPYyARNRcGAQwKQRYWUlQwXwAgExoLFAAcARFUBwFOUwImCgcDDU5rIAcXUj0dU2IcBk4TUh0YFUkASEkcC3QIGwMMQkE9SB8AMk9TNlIOCxNUHQZCAAoAHh1FXjYCDBsFABkOBkk7FgALVQROD0EaDwxOSU8dGgI8EVIBAAUEVA5SRjlUQTYbCk5teRsdRVQcDhkDADBFHwhJAQ8XClJBNl4AC1IdBghVEwARABoHCAdFXjwdGEkDCBMHBgAwW1YnUgAaRyonB0VTGgoZUwE7EhxNCAAFVAMXTjwaTSdSEAESUlQNBFJOZU5LXHQMHE0EF0EABh9FeRp5LQdFTkAZREgMU04CEFMcMQQAQ0lkay0ABwcqXwA1FwgFAk4dBkIACA4aB0l0PD1MSQ8PEE87ADtbTmIGDAILAB0cRSo3ABwBRTYKFhROHUETCgZUMVQHYhoGGksABwdJAB0ASTpFNwQcTRoDBBgDUkksGioRHUkKCE5THEVCC08EEgF0BBwJSQoOGkgGADpfADETDU5tBzcJEFMLTx0bAHQJCx8ADRJUDRdMN1RHYgYGTi5jMURFeQEaSRAEOkURDAUCQRkKUmQ5XgBIKwYbQFIRSBVJGgwBGgtzRRNNDwcVWE8BT3hJVCcCSQwGQx9IBE4KTwwdASEXF01jIgQATwZIPRpXKwYKBkdEGwsRTxxDSToGMUlSCQZOFRwKUkQ5VEMnUh0BR0MBGgAAZDwGUwY7CBdNHB5BFwMdUz0aQSwWSQoITlMcRUILTxoCEDUXF01jNw4BTwVBNlRBYhAIGhNMEUgIRU5CRFMkOhwGBAQLTVQOHFkvUkUwF0lkbXkbHUVUBgAcFA0gRQYFCBpBPU8FQSsaVycTAkJHYhsRSQAXABxUFzFFFggICkEDHR1OPxoqER1JDQhNEUgKTkJPDAUAJhwQAg0XQRUBFgArU04lUh0GDlNUGwpOCU9jeTY1HFJARE4xGA4LACxSQTZSDxsJSw1ICFUdBgpTNjUcXk0OAUEDBxtUPRpCLQtFTgBPVB8NSRoKSREKLUUVAklkERgOCwAsUkE2Ug8bCUsNSAhVHQYKUyI7RQUFABoEVA0dWXQaRy1SHgYOVBFIB08XQ0kUCnRvPgwQTgUbGBwAOVREYhAGAQBJEUgETgpPGR8ELUUGBQgaQRIaHEshGk03AQANR1QdBAkAFwAcUwE9AFxNY2QxGA4LACxSQTZSDxsJSw1ICFUdBgpTJjsIF00GAE1ULB1NPRpPLF5JAgJUVAUAAAYKCAFFXjUeDBBOFRwOBgA+T04pC0kDElMdC0VXBgYdFkU2CgtNEAEUVBwTWXhTVG5SGg8eAB0cRSo+AwgKRSANExlJCBQaBAsANU9TKxFJL0dMHRwRTAtPBRwQMAAATQcBFlRlIkw5QwA2GggaR0YBBg5ZTgIcAAw3SVIaAQcVEU8QTyEaYy0fDE4ITlhIJk8DCkkcC3hFMQIEC0EbAVIqCFZBO1IdBgZUVA4QTgUWSR4QJwwRTWM=";
int challenge_six() {
    size_t numBytes;
    unsigned char *bytes = base642bytes(b64data, &numBytes);
    if (bytes == NULL) {
        return 1;
    }

    int keysize = find_likely_keysize(bytes, numBytes, 2, 40);
    printf("keysize: %i\n", keysize);
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

    return 0;
}
