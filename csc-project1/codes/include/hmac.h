#ifndef _HMAC_H
#define _HMAC_H

#include <stdint.h>
#include <stdlib.h>

#define HMAC96AUTHLEN 12

/**
 * hmac_sha1()
 * Calculate the digest of the HMAC with SHA1 and set the length of result
 * equals to minimum of value of @t and SHA_DIGEST_LENGTH.
 *
 * @k: pointer to the secret key
 * @klen: length of the key in bytes
 * @data: pointer to the data used to generate digest
 * @dlen: data length in bytes
 * @digest: pointer to the computed digest
 * @digelen: pointer to the length of computed digest should be
 */
void hmac_sha1(uint8_t const *k,
               size_t klen,
               uint8_t const *data,
               size_t dlen,
               uint8_t *digest,
               size_t *digelen);


ssize_t hmac_sha1_96(uint8_t const *k,
                     size_t klen,
                     uint8_t const *data,
                     size_t dlen,
                     uint8_t *digest);
#endif
