#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>

unsigned char *decrypt_aes_128_ecb(const unsigned char *ciphertext, int numBytes, const unsigned char *key) {
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *outdigest[numBytes*2];
    EVP_CIPHER_CTX_init(ctx);

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return NULL;

    int outlen;
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_DecryptUpdate(ctx, (unsigned char *) outdigest, &outlen, ciphertext, numBytes);
    EVP_DecryptFinal(ctx, (unsigned char *) outdigest + outlen, &outlen);

    unsigned char *out = calloc(numBytes, sizeof(unsigned char));
    memcpy(out, outdigest, numBytes);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}