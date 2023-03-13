#ifndef _TRANSPORT_H
#define _TRANSPORT_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "net.h"

#define BUFSIZE 65535

#ifndef _TYPEDEF_STRUCT_TXP
#define _TYPEDEF_STRUCT_TXP
typedef struct txp Txp;
#endif

struct txp {
    uint16_t x_src_port; /* Expected src port to CSCF */
    uint16_t x_dst_port; /* Expected dst port to CSCF */

    uint32_t x_tx_seq; /* Expected tx sequence number */
    uint32_t x_tx_ack; /* Expected tx acknowledge number */

    struct tcphdr thdr;
    uint8_t hdrlen;

    uint8_t *pl;
    uint16_t plen;

    uint8_t *(*dissect)(Net *net, Txp *self, uint8_t *txp_data, size_t txp_len);
    Txp *(*fmt_rep)(Txp *self, struct iphdr iphdr, uint8_t *data, size_t dlen);
};

uint16_t cal_tcp_cksm (struct iphdr iphdr, struct tcphdr tcphdr, uint8_t *pl, int plen);

uint8_t *dissect_tcp(Net *net, Txp *self, uint8_t *segm, size_t segm_len);

Txp *fmt_tcp_rep(Txp *self, struct iphdr iphdr, uint8_t *data, size_t dlen);

void init_txp(Txp *self);

#endif
