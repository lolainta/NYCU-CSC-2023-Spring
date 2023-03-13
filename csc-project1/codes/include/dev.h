#ifndef _DEV_H
#define _DEV_H

#include <stdint.h>
#include <net/if.h>
#include <linux/if_packet.h>

#ifndef _TYPEDEF_STRUCT_DEV
#define _TYPEDEF_STRUCT_DEV
typedef struct dev Dev;
#endif

#ifndef _TYPEDEF_STRUCT_NET
#define _TYPEDEF_STRUCT_NET
typedef struct net Net;
#endif

#ifndef _TYPEDEF_STRUCT_ESP
#define _TYPEDEF_STRUCT_ESP
typedef struct esp Esp;
#endif

#ifndef _TYPEDEF_STRUCT_TXP
#define _TYPEDEF_STRUCT_TXP
typedef struct txp Txp;
#endif

struct dev {
    int mtu;

    struct sockaddr_ll addr;
    int fd;

    uint8_t *frame;
    uint16_t framelen;

    uint8_t *linkhdr;

    void (*fmt_frame)(Dev *self, Net net, Esp esp, Txp txp);
    ssize_t (*tx_frame)(Dev *self);
    ssize_t (*rx_frame)(Dev *self);
};

void init_dev(Dev *self, char *dev_name);

void fmt_frame(Dev *self, Net net, Esp esp, Txp txp);

ssize_t tx_frame(Dev *self);

ssize_t rx_frame(Dev *self);

#endif
