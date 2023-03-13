#ifndef _REPLAY_H
#define _REPLAY_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#define WAIT_PKT 0
#define WAIT_SECRET 1
#define SEND_ACK 2

#define LINKHDRLEN 14

#define ENA_TCP_ACK true
#define DISABLE_TCP_ACK false

#define MAXBUFCOUNT 8

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

struct frame_arr {

    uint8_t frame[MAXBUFCOUNT][65535];
    uint16_t framelen[MAXBUFCOUNT];
    long msec[MAXBUFCOUNT];

    ssize_t count;
};

extern struct frame_arr frame_buf;

void tx_esp_rep(Dev dev,
                Net net,
                Esp esp,
                Txp txp,
                uint8_t *data, ssize_t dlen, long msec);

ssize_t send_msg(Dev *dev,
                Net *net,
                Esp *esp,
                Txp *txp,
                char* str);

bool dissect_rx_data(Dev *dev,
                Net *net,
                Esp *esp,
                Txp *txp,
                int *state,
                char* victim_ip,
                char* server_ip,
                bool* test_for_dissect);

uint8_t *wait(Dev *dev,
                Net *net,
                Esp *esp,
                Txp *txp,
                int *state,
                char* victim_ip,
                char* server_ip,
                bool* test_for_dissect);

void record_txp(Net *net, Esp *esp, Txp *txp);

void get_info(Dev *dev,
                Net *net,
                Esp *esp,
                Txp *txp,
                int *try,
                char* victim_ip,
                char* server_ip,
                bool* test_for_dissect);


#endif
