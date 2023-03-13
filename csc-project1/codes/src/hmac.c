#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "hmac.h"
#include "sha.h"

#ifndef SHA_BLOCKSIZE
#define SHA_BLOCKSIZE 64
#endif

void hmac_sha1(uint8_t const *k,
               size_t klen,
               uint8_t const *data,
               size_t dlen,
               uint8_t *digest,
               size_t *digelen)
{
    SHA_CTX ictx, octx;
    uint8_t isha[SHA_DIGEST_LENGTH], osha[SHA_DIGEST_LENGTH];
    uint8_t key[SHA_DIGEST_LENGTH];
    uint8_t buf[SHA_BLOCKSIZE];
    size_t i;

    if (klen > SHA_BLOCKSIZE) {
        SHA_CTX tctx;

        SHA1_Init(&tctx);
        SHA1_Update(&tctx, k, klen);
        SHA1_Final(key, &tctx);

        k = key;
        klen = SHA_DIGEST_LENGTH;
    }


    /* Get inner digest */
    SHA1_Init(&ictx);

    /* Pad the key for inner digest */
    for (i = 0; i < klen; ++i) {
        buf[i] = k[i] ^ 0x36;
    }
    for (i = klen; i < SHA_BLOCKSIZE; ++i) {
        buf[i] = 0x36;
    }

    SHA1_Update(&ictx, buf, SHA_BLOCKSIZE);
    SHA1_Update(&ictx, data, dlen);

    SHA1_Final(isha, &ictx);


    /* Get outer digest */
    SHA1_Init(&octx);

    /* Pad the key for outter digest */
    for (i = 0; i < klen; ++i) {
        buf[i] = k[i] ^ 0x5c;
    }
    for (i = klen; i < SHA_BLOCKSIZE; ++i) {
        buf[i] = 0x5c;
    }

    SHA1_Update(&octx, buf, SHA_BLOCKSIZE);
    SHA1_Update(&octx, isha, SHA_DIGEST_LENGTH);

    SHA1_Final(osha, &octx);

    /* Truncate the results if length execeeds */
    *digelen = *digelen > SHA_DIGEST_LENGTH ? SHA_DIGEST_LENGTH : *digelen;
    memcpy(digest, osha, *digelen);
}


ssize_t hmac_sha1_96(uint8_t const *k,
                     size_t klen,
                     uint8_t const *data,
                     size_t dlen,
                     uint8_t *digest)
{
    size_t digelen = HMAC96AUTHLEN;
    hmac_sha1(k, klen, data, dlen, digest, &digelen);

    if (digelen != HMAC96AUTHLEN)
        return -1;

    return HMAC96AUTHLEN;
}
