#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>

unsigned char *decrypt_aes_128_ecb(const unsigned char *ciphertext, int numBytes, const unsigned char *key, int *outlen) {
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *outdigest = calloc(numBytes, sizeof(char));

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return NULL;

    EVP_CipherInit(ctx, EVP_aes_128_ecb(), key, NULL, 0);
    EVP_DecryptUpdate(ctx, outdigest, outlen, ciphertext, numBytes);

    unsigned char *out = calloc(*outlen, sizeof(unsigned char));
    memcpy(out, outdigest, *outlen);
    OPENSSL_free(outdigest);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}