#ifndef _Net_H
#define _Net_H

#include <netdb.h>
#include <netinet/ip.h>

#ifndef _TYPEDEF_STRUCT_NET
#define _TYPEDEF_STRUCT_NET
typedef struct net Net;
#endif

typedef enum proto {
    UNKN_PROTO = 0,

    IPv4 = IPPROTO_IP,

    ESP = IPPROTO_ESP,

    TCP = IPPROTO_TCP,
} Proto;

struct net {
    char *src_ip;
    char *dst_ip;

    char *x_src_ip; /* Expected src IP addr */
    char *x_dst_ip; /* Expected dst IP addr */

    struct iphdr ip4hdr;

    size_t hdrlen;
    uint16_t plen;
    Proto pro;

    uint8_t *(*dissect)(Net *self, uint8_t *pkt, size_t pkt_len);
    Net *(*fmt_rep)(Net *self);
};

uint16_t cal_ipv4_cksm(struct iphdr iphdr);

uint8_t *dissect_ip(Net *self, uint8_t *pkt, size_t pkt_len);

Net *fmt_net_rep(Net *self);

void init_net(Net *self);

#endif
