#ifndef CRYPTOPALS_HEX_H
#define CRYPTOPALS_HEX_H
#include <stdlib.h>

/**
 * @brief Converts a hexstring to the equivalent bytestring.
 *
 * @param hexstring the hexstring to convert.
 * @param numBytes contains the number of bytes in the resulting string.
 * @return unsigned char* of resulting bytes. MUST BE free'D!
 */
unsigned char* hex2bytes(const char *hexstring, size_t *numBytes);

/**
 * @brief Converts a bytestring to the equivalent hexstring.
 *
 * @param bytes the bytes to convert.
 * @param numBytes the number of bytes to convert.
 * @return char* of the resulting hexstring. MUST BE free'D!
 */
char* bytes2hex(const unsigned char *bytes, size_t numBytes);

#endif //CRYPTOPALS_HEX_H
