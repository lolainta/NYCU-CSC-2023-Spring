#include <bits/stdc++.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/uio.h>
#include <sys/time.h>

using namespace std;
#define MAXLEN 10000

int get_src_port(int sockfd) {
    struct sockaddr_in addr;
    socklen_t len;

    len = sizeof(addr);
    getsockname(sockfd, (struct sockaddr*)&addr, &len);
    printf("Src port: %d\n", ntohs(addr.sin_port));
    getpeername(sockfd, (struct sockaddr*)&addr, &len);
    printf("remote port: %d\n", ntohs(addr.sin_port));
    return ntohs(addr.sin_port);
}

void bind_local(int socket, char *interface_name, int bind_port) {
    if (interface_name) {
        // set name
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface_name);

        if (setsockopt(socket, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
            perror("setsockopt");
            exit(1);
        }
    }
    int enable = 1;
    if (setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0){
        perror("setsockopt reuse address error");
        exit(1);
    }

    if (bind_port > 0) {
        int ret;
        struct sockaddr_in cli_addr;
        cli_addr.sin_family = AF_INET;
        cli_addr.sin_port = htons(bind_port);
        cli_addr.sin_addr.s_addr = 0;

        if ((ret = bind(socket, (struct sockaddr* )&cli_addr, sizeof(struct sockaddr_in))) < 0) {
            perror("bind");
            exit(1);
        }
        printf("bind to port %d\n", bind_port);
    }
}

int connect_TCP(char *addr, int server_port, char* bind_interface, int bind_port) {
    struct hostent *he;
    struct sockaddr_in serv_addr;
    int sockfd;
    if((he = gethostbyname(addr)) == NULL){
        return -1;
    }
    memset((char*)&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr = *(struct in_addr *)he -> h_addr;
    serv_addr.sin_port = htons(server_port);
    // Open a TCP socket (an Internet stream socket).
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        perror("client: can't connect to server");
        exit(1);
    }

    bind_local(sockfd, bind_interface, bind_port);

    if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
        perror("client:connect error");
        exit(1);
    }
    return sockfd;
}
int main(int argc, char **argv) {
    int bind_port = 0;
    char *bind_interface = NULL;
    int server_port = 0;
    if (argc != 3 && argc != 5) {
        cerr << "Usage: " << argv[0] << "<server ip> <server port> [-bp <bind_port>] [-bi <bind_interface>]" << endl;
        exit(1);
    } else {
        server_port = atoi(argv[2]);
        for (int i = 3; i + 1 < argc; i += 2) {
            if (strcmp(argv[i], "-bp") == 0) {
                bind_port = atoi(argv[4]);
            } else if (strcmp(argv[i], "-bi") == 0) {
                bind_interface = argv[i + 1];
            } else {
                cerr << "Usage: " << argv[0] << "<server ip> <server port> [-bp <bind_port>] [-bi <bind_interface>]" << endl;
                exit(1);
            }
        }
    }
    int sockfd = connect_TCP(argv[1], server_port, bind_interface, bind_port);
    if (sockfd < 0) {
        cerr << "Sockfd connect error" << endl;
        exit(1);
    }
    get_src_port(sockfd);

    //send_request
    string send_str = "I am client, and I am keeping sending message to server hahahaha\n";
    char recv_str[MAXLEN];
    fd_set readfds;

    struct timeval timeout;
    timeout.tv_usec=1;
    timeout.tv_sec=0;

    for(int cnt=1;; cnt++) {
        bzero(recv_str, MAXLEN);
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        if(select(sockfd + 1, &readfds, NULL, NULL, &timeout) < 0){
            exit(1);
        }

        //read prompt from server
        if(FD_ISSET(sockfd, &readfds)){
            while(1) {
                bzero(recv_str, MAXLEN);
                int rc = read(sockfd, recv_str, MAXLEN);
                if(rc < 0){ //error
                    cerr << "send_request: read error" << endl;
                    exit(1);
                } else if(rc == 0){ //finished
                    break;
                } else if(rc  < MAXLEN){
                    cout << recv_str << endl;
                    break;
                } else if(rc == MAXLEN){
                    cout << recv_str << endl;
                }
            }
        }

        // write msg
        string msg = to_string(cnt) + ":" + send_str;
        if(write(sockfd, msg.c_str(), msg.length())<0){
            cerr << "send_request: write error" << endl;
            exit(1);
        }
        sleep(1);
    }
    close(sockfd);
}
