#ifndef CRYPTOPALS_AES_H
#define CRYPTOPALS_AES_H

/**
 * Decrypts the given ciphertext via AES ECB using the given key.
 * @param ciphertext the ciphertext to decrypt
 * @param numBytes the number of bytes in the ciphertext
 * @param key the encryption key
 * @return decrypted bytes
 */
unsigned char *decrypt_aes_128_ecb(const unsigned char *ciphertext, int numBytes, const unsigned char *key);

#endif //CRYPTOPALS_AES_H
