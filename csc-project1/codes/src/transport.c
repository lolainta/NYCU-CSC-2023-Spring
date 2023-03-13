#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "net.h"
#include "transport.h"

uint16_t cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphdr, uint8_t *pl, int plen)
{
    // [DONE]: Finish TCP checksum calculation
    int ret[2]={0,0};
    uint8_t buf[8];
    memcpy(buf,&iphdr.saddr,4);
    memcpy(buf+4,&iphdr.daddr,4);
    for(int i=0;i<4;i++){
	ret[0]+=buf[2*i];
	ret[1]+=buf[2*i+1];
//	printf("%02x %02x\n",ret[0],ret[1]);
    }
//    printf("tcphdrlen=%d\n",tcphdr.th_off<<2);
    ret[1]+=(0x0006+20+plen);
    int nplen=(plen+1)/2*2;
//    printf("plen=%x nplen=%x ret=%02x %02x\n",plen,nplen,ret[0],ret[1]);
//    printf("%02x %02x\n",ret[0],ret[1]);
    uint8_t*data=(uint8_t*)calloc(nplen,1);
    memcpy(data,pl,plen);
    for(int i=0;i<nplen/2;i++){
//        printf("%02x %02x += ",ret[0],ret[1]);
//        printf("%02x %02x =>",data[2*i],data[2*i+1]);
	ret[0]+=data[2*i];
	ret[1]+=data[2*i+1];
//        printf("%02x %02x\n",ret[0],ret[1]);
    }
//    printf("plen finished\n");
    uint8_t tcpbuf[20];
    memcpy(tcpbuf,&tcphdr,20);
    for(int i=0;i<10;++i){
//        printf("%02x %02x += ",ret[0],ret[1]);
//        printf("%02x %02x =>",tcpbuf[2*i],tcpbuf[2*i+1]);
	ret[0]+=tcpbuf[2*i];
	ret[1]+=tcpbuf[2*i+1];
//        printf("%02x %02x\n",ret[0],ret[1]);
    }
//    ret+=(ret>>16);
//    ret&=0xffff;
    int ans=(ret[0]<<8)+(ret[1]);
    ans+=ans>>16;
    ans&=0xffff;
//    printf("%02x %02x ans: %04x\n",ret[0],ret[1],ans);
    return __bswap_16(~ans);
}

uint8_t *dissect_tcp(Net *net, Txp *self, uint8_t *segm, size_t segm_len)
{
    // [DONE]: Collect information from segm
    // (Check IP addr & port to determine the next seq and ack value)

//    self->thdr.th_sport=__bswap_16(*(uint16_t*)segm);
    self->thdr.th_sport=*(uint16_t*)segm;
//    self->thdr.th_dport=__bswap_16(*((uint16_t*)(segm+2)));
    self->thdr.th_dport=*((uint16_t*)(segm+2));
//    self->thdr.th_seq=__bswap_32(*((uint32_t*)(segm+4)));
    self->thdr.th_seq=*((uint32_t*)(segm+4));
//    self->thdr.th_ack=__bswap_32(*((uint32_t*)(segm+8)));
    self->thdr.th_ack=*((uint32_t*)(segm+8));
    self->thdr.th_flags=*(segm+13);
    self->thdr.th_sum=0x0000;;
    self->hdrlen=(*(segm+12))>>2;

/*
    printf("%p %p\n",(*(uint32_t*)net->src_ip,*(uint32_t*)net->x_src_ip));
    if(strcpy(*(uint32_t*)net->src_ip,*(uint32_t*)net->x_src_ip)){
        printf("true\n");
//        printf("true: sport=%x dport=%x\n",*(uint16_t*)segm,*(uint16_t*)(segm+2));
    }else{
        printf("false\n");
    }
*/
 
/*
    self->x_src_port=__bswap_16(*(uint16_t*)segm);
    self->x_dst_port=__bswap_16(*((uint16_t*)(segm+2)));
*/
    self->plen=segm_len-(self->hdrlen);;
    self->pl=segm+(self->hdrlen);

/*
    self->x_tx_seq=__bswap_32(self->thdr.th_ack);
    self->x_tx_ack=__bswap_32(self->thdr.th_seq);
    printf("[%s]:%d(%s)\t\n",__FILE__,__LINE__,__func__);
    for(int i=0;i<20;i++){
	printf("%02x ",segm[i]);
    } 
    printf("\n");

    printf("[%s]:%d(%s)\t\n",__FILE__,__LINE__,__func__);
    printf("sgm: %x %x\n",*(uint32_t*)(segm+4),*(uint32_t*)(segm+8));
    printf("port: %x %x\n",self->thdr.th_seq,self->thdr.th_ack);
    printf("xport: %x %x\n",self->x_tx_seq,self->x_tx_ack);
*/
    return self->pl;
    return segm+(self->hdrlen<<2);

}

Txp *fmt_tcp_rep(Txp *self, struct iphdr iphdr, uint8_t *data, size_t dlen)
{
    // [DONE]: Fill up self->tcphdr (prepare to send)
/*
    self->thdr.source=*((uint16_t*)self->x_src_port);
    self->thdr.source=*((uint16_t*)self->x_src_port);
*/
    self->thdr.source=__bswap_16(self->x_src_port);
    self->thdr.dest=__bswap_16(self->x_dst_port);
/*
    printf("[%s]:%d(%s)\t",__FILE__,__LINE__,__func__);
    printf("port: %d %d\n",self->x_src_port,self->x_dst_port);
*/
    self->thdr.th_seq=__bswap_32(self->x_tx_seq);
    self->thdr.th_ack=__bswap_32(self->x_tx_ack);
    self->thdr.th_off=0x05;
    self->thdr.th_x2=0;
    self->thdr.th_flags=TH_ACK;
    self->thdr.th_win=__bswap_16(48763);
    self->pl=data;
    self->plen=dlen;
    self->thdr.th_sum=cal_tcp_cksm(iphdr,self->thdr,self->pl,self->plen);
/*
    printf("[%s]:%d(%s)\t",__FILE__,__LINE__,__func__);
    printf("src=%x dst=%x\n",iphdr.saddr,iphdr.daddr);
    printf("[%s]:%d(%s)\t",__FILE__,__LINE__,__func__);
    printf("seq=%08x ack=%08x\n",self->thdr.th_seq,self->thdr.th_ack);
*/
    return self;
}

inline void init_txp(Txp *self)
{
    self->pl = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
    self->hdrlen = sizeof(struct tcphdr);

    self->dissect = dissect_tcp;
    self->fmt_rep = fmt_tcp_rep;
}

