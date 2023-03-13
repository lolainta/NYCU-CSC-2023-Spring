#ifndef _SHA_H
#define _SHA_H

#include <stdint.h>
#include <stdlib.h>

#ifdef USE_OPENSSL
#include <openssl/sha.h>
#else

/* SHA-1 context */
typedef struct {
    uint32_t state[5];  /* Context state */
    uint32_t count[2];  /* Context counter */
    uint8_t buffer[64]; /* SHA-1 buffer  */
} SHA1_CTX;

#define SHA1_DIGEST_SIZE 20  /* SHA-1 Digest size in bytes */

/* For OpenSSL comppat */
typedef SHA1_CTX SHA_CTX;
#define SHA_DIGEST_LENGTH SHA1_DIGEST_SIZE

void SHA1_Init(SHA1_CTX *context);

void SHA1_Update(SHA1_CTX *context, const void *p, size_t len);

void SHA1_Final(uint8_t digest[SHA1_DIGEST_SIZE], SHA1_CTX *context);

#endif
#endif
