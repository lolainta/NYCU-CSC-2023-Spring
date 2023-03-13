#ifndef _ESP_H
#define _ESP_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <linux/pfkeyv2.h>

#include "net.h"

/* Authentication data length of HMAC-SHA1-96 is 96 bits */
#define MAXESPPADLEN 3
#define MAXESPPLEN \
    IP_MAXPACKET - sizeof(EspHeader) - sizeof(EspTrailer) - HMAC96AUTHLEN

#ifndef _TYPEDEF_STRUCT_TXP
#define _TYPEDEF_STRUCT_TXP
typedef struct txp Txp;
#endif

#ifndef _TYPEDEF_STRUCT_ESP
#define _TYPEDEF_STRUCT_ESP
typedef struct esp Esp;
#endif

typedef struct esp_header {
    uint32_t spi;
    uint32_t seq;
} EspHeader;

typedef struct esp_trailer {
    uint8_t pad_len;
    uint8_t nxt;
} EspTrailer;

struct esp {
    EspHeader hdr;

    uint8_t *pl;    // ESP payload
    size_t plen;    // ESP payload length

    uint8_t *pad;   // ESP padding

    EspTrailer tlr;

    uint8_t *auth;
    size_t authlen;

    uint8_t *esp_key;

    uint8_t *(*set_padpl)(Esp *self);
    uint8_t *(*set_auth)(Esp *self,
                         ssize_t (*hmac)(uint8_t const *, size_t,
                                         uint8_t const *, size_t,
                                         uint8_t *));
    void (*get_key)(Esp *self);
    uint8_t *(*dissect)(Esp *self, uint8_t *esp_pkt, size_t esp_len);
    Esp *(*fmt_rep)(Esp *self, Proto p);
};

void get_ik(int type, uint8_t *key);

void get_esp_key(Esp *self);

uint8_t *set_esp_pad(Esp *self);

uint8_t *set_esp_auth(Esp *self,
                      ssize_t (*hmac)(uint8_t const *, size_t,
                                      uint8_t const *, size_t,
                                      uint8_t *));

uint8_t *dissect_esp(Esp *self, uint8_t *esp_pkt, size_t esp_len);

Esp *fmt_esp_rep(Esp *self, Proto p);

void init_esp(Esp *self);
#endif
