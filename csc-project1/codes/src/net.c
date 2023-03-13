#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <unistd.h>

#include "net.h"
#include "transport.h"
#include "esp.h"

uint16_t cal_ipv4_cksm(struct iphdr iphdr)
{
    // [DONE]: Finish IP checksum calculation
//    printf("[%s]:%d(%s)\n",__FILE__,__LINE__,__func__);
    uint16_t buf[10];
    memcpy(buf,&iphdr,20);
    int ret=0;
    for(int i=0;i<10;++i){
//	printf("%04x %04x => ",buf[i],ret);
	ret+=buf[i];
//	printf("%04x\n",ret);
    }
    ret+=(ret>>16);
    ret&=0xffff;
    return ~ret;
}

uint8_t *dissect_ip(Net *self, uint8_t *pkt, size_t pkt_len)
{
    // [DONE]: Collect information from pkt.
    // Return payload of network layer

    self->pro=pkt[9];
    self->src_ip=(uint32_t*)(pkt+12);
    self->ip4hdr.saddr=*((uint32_t*)self->src_ip);
//    self->x_src_ip=pkt+12;
    self->dst_ip=(uint32_t*)(pkt+16);
    self->ip4hdr.daddr=*((uint32_t*)self->dst_ip);
//    self->x_dst_ip=pkt+16;
    self->plen=pkt_len-self->hdrlen;
    return pkt+self->hdrlen;
}

Net *fmt_net_rep(Net *self)
{
    // [DONE]: Fill up self->ip4hdr (prepare to send)

    self->ip4hdr.ihl=5;
    self->ip4hdr.version=4;
    self->ip4hdr.tos=0;
    self->ip4hdr.tot_len=__bswap_16(sizeof(self->ip4hdr)+self->plen);
/*
    printf("[%s]:%d(%s)\t",__FILE__,__LINE__,__func__);
    printf("ipv4hdr tot_len=%d+%d\n",sizeof(self->ip4hdr),self->plen);
*/
    self->ip4hdr.id=__bswap_16(0xabcd);
    self->ip4hdr.frag_off=0;
    self->ip4hdr.ttl=0xff;
    self->ip4hdr.protocol=ESP;
    self->ip4hdr.saddr=*((uint32_t*)self->x_src_ip);
    self->ip4hdr.daddr=*((uint32_t*)self->x_dst_ip);
/*
    printf("[%s]:%d(%s)\t",__FILE__,__LINE__,__func__);
    printf("src_ip=%x dst_ip=%x\n",*((uint32_t*)(self->x_src_ip)),*((uint32_t*)(self->x_dst_ip)));
*/
    self->ip4hdr.check=0x0000;
    self->ip4hdr.check=cal_ipv4_cksm(self->ip4hdr);
    return self;
}

void init_net(Net *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    self->src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->hdrlen = sizeof(struct iphdr);

    self->dissect = dissect_ip;
    self->fmt_rep = fmt_net_rep;
}
