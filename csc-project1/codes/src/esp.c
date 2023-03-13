#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/pfkeyv2.h>

#include "esp.h"
#include "transport.h"
#include "hmac.h"

EspHeader esp_hdr_rec;

void print_sadb_msg(struct sadb_msg*msgp,ssize_t sz){
    printf("ver=%d type=%d err=%d satype=%d len=%d res=%d seq=%d pid=%d\n",msgp->sadb_msg_version,msgp->sadb_msg_type,msgp->sadb_msg_errno,msgp->sadb_msg_satype,msgp->sadb_msg_len,msgp->sadb_msg_reserved,msgp->sadb_msg_seq,msgp->sadb_msg_pid);
    if(msgp->sadb_msg_len*8!=sz)
	printf("ERROR size\n");

}
void get_ik(int type, uint8_t *rkey)
{
    // [DONE]: Dump authentication key from security association database (SADB)
    // (Ref. RFC2367 Section 2.3.4 & 2.4 & 3.1.10)

    int s;
    char buf[4096];
    struct sadb_msg msg;
    if((s=socket(PF_KEY,SOCK_RAW,PF_KEY_V2))<0){
        perror("socket");
        exit(1);
    }
    bzero(&msg,sizeof(msg));
    msg.sadb_msg_version=PF_KEY_V2;
    msg.sadb_msg_type=SADB_DUMP;
    msg.sadb_msg_satype=type;
    msg.sadb_msg_len=sizeof(msg)/8;
    msg.sadb_msg_pid=getpid();
//    print_sadb_msg(&msg,sizeof(msg));
    if(write(s,&msg,sizeof(msg))<0){
        perror("write");
        exit(1);
    }
    /* Read and print SADB_DUMP replies until done */
    int goteof;
    goteof=0;
    while(goteof==0){
        int msglen;
        struct sadb_msg*msgp;
    
        if((msglen=read(s,&buf,sizeof(buf)))<0){
            perror("read");
            exit(1);
        }
        msgp=(struct sadb_msg*)&buf;
/*
	printf("got sadb msg\n======\n");
        print_sadb_msg(msgp,msglen);
        if(msgp->sadb_msg_type==SADB_DUMP)
	    printf("type=SADB_DUMP\n");
*/
        if(msgp->sadb_msg_seq==0){
            goteof=1;
            continue;
        }
	struct sadb_ext*ext;
        ext=(struct sadb_ext*)(msgp+1);
        msglen-=sizeof(struct sadb_msg);
	while(msglen>0){
	    switch(ext->sadb_ext_type){
	    case SADB_EXT_SA:{
                struct sadb_sa*sa=(struct sadb_sa*)ext;
		break;
	    }case SADB_EXT_KEY_AUTH:{
                struct sadb_key*key=(struct sadb_key*)ext;
//                printf("key->sadb_key_exttype=%d\n",key->sadb_key_exttype);
//                printf("key->sadb_key_bits=%d\n",key->sadb_key_bits);
		unsigned char*p;
		int bits=key->sadb_key_bits;
		int i=0;
		for(p=(unsigned char*)(key+1),i=0,bits=key->sadb_key_bits;
			bits>0;p++,bits-=8,i++){
		    memcpy(rkey+i,p,1);
		}
		rkey=key+1;
		break;
            }default:{
//                printf("default sadb exttype=%d\n",ext->sadb_ext_type);
	    }
	    }
            msglen-=ext->sadb_ext_len<<3;
	    ext = (char *)ext + (ext->sadb_ext_len << 3);
//	    printf("msglen=%d\n-------\n",msglen/8);
        }
    }
    close(s);
}

void get_esp_key(Esp *self)
{
    get_ik(SADB_SATYPE_ESP, self->esp_key);
}

uint8_t *set_esp_pad(Esp *self)
{
    // [DONE]: Fill up self->pad and self->pad_len (Ref. RFC4303 Section 2.4)

    size_t pdlen=(6-self->plen)%4;
//    pdlen=254-self->plen;
    self->tlr.pad_len=pdlen;
    for(int i=1;i<=pdlen;++i)
        self->pad[i-1]=i;
//    self->plen+=pdlen;
/*
    printf("[%s]:%d(%s)\t",__FILE__,__LINE__,__func__);
    printf("plen=%d padlen=%d\n",self->plen,self->tlr.pad_len);
*/
    return self->pad;
}

uint8_t *set_esp_auth(Esp *self,
                      ssize_t (*hmac)(uint8_t const *, size_t,
                                      uint8_t const *, size_t,
                                      uint8_t *))
{
    if (!self || !hmac) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }

    uint8_t buff[BUFSIZE];
    size_t esp_keylen = 16;
    size_t nb = 0;  // Number of bytes to be hashed
    ssize_t ret;
/*
    printf("[%s]:%d(%s)\t",__FILE__,__LINE__,__func__);
    for(int i=0;i<16;++i){
        printf("%02x",self->esp_key[i]);
    }
    printf("\n");
*/
    // [DONE]: Put everything needed to be authenticated into buff and add up nb

    memcpy(buff+nb,&self->hdr,sizeof(self->hdr)),nb+=sizeof(self->hdr);
    memcpy(buff+nb,self->pl,self->plen),nb+=self->plen;
    memcpy(buff+nb,self->pad,self->tlr.pad_len),nb+=self->tlr.pad_len;
    memcpy(buff+nb,&self->tlr,sizeof(self->tlr)),nb+=sizeof(self->tlr);
/*
    printf("[%s]:%d(%s)\t",__FILE__,__LINE__,__func__);
    printf("hdr=%d plen=%d padlen=%d tlr=%d nb=%d\n",sizeof(self->hdr),self->plen,self->tlr.pad_len,sizeof(self->tlr),nb);

    printf("[%s]:%d(%s)\t",__FILE__,__LINE__,__func__);
    printf("keylen=%d HMAC96AUTHLEN=%d\n",esp_keylen,HMAC96AUTHLEN);
*/

    ret = hmac(self->esp_key, esp_keylen, buff, nb, self->auth);

    if (ret == -1) {
        fprintf(stderr, "Error occurs when try to compute authentication data");
        return NULL;
    }

    self->authlen = ret;
    return self->auth;
}

uint8_t *dissect_esp(Esp *self, uint8_t *esp_pkt, size_t esp_len)
{
    // [DONE]: Collect information from esp_pkt.
    // Return payload of ESP

    self->hdr.spi=__bswap_32(*(uint32_t*)esp_pkt);
    self->hdr.seq=__bswap_32(*(uint32_t*)(esp_pkt+4));
    self->pl=esp_pkt+8;
    self->auth=esp_pkt+(esp_len-self->authlen);
    memcpy(&self->tlr,esp_pkt+(esp_len-(self->authlen+sizeof(self->tlr))),sizeof(self->tlr));
    self->plen=esp_len-sizeof(self->hdr)-self->authlen-sizeof(self->tlr)-self->tlr.pad_len;
//    memcpy(self->pl,esp_pkt+(esp_len-(self->authlen+sizeof(self->tlr)+self->tlr.pad_len)),self->plen);
    return self->pl;
}

Esp *fmt_esp_rep(Esp *self, Proto p)
{
    // [DONE]: Fill up ESP header and trailer (prepare to send)
    self->hdr.spi=__bswap_32(self->hdr.spi);
    self->hdr.seq=__bswap_32(self->hdr.seq+1);
    self->tlr.nxt=p;
}

void init_esp(Esp *self)
{
    self->pl = (uint8_t *)malloc(MAXESPPLEN * sizeof(uint8_t));
    self->pad = (uint8_t *)malloc(MAXESPPADLEN * sizeof(uint8_t));
    self->auth = (uint8_t *)malloc(HMAC96AUTHLEN * sizeof(uint8_t));
    self->authlen = HMAC96AUTHLEN;
    self->esp_key = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));

    self->set_padpl = set_esp_pad;
    self->set_auth = set_esp_auth;
    self->get_key = get_esp_key;
    self->dissect = dissect_esp;
    self->fmt_rep = fmt_esp_rep;
}
