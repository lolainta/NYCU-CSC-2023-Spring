#include <bits/stdc++.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define SA struct sockaddr
#define MAXLEN 10000
#define FLAGNUM 10
#define LISTENQ 100
using namespace std;

bool process_request(int sockfd) {
    FILE* file = fopen("answer.txt", "r");
    if(!file){
        cerr << "[Error] File read failed: " << sockfd << endl;
        return 0;
    }

    vector<string> flag;
    vector<string> secret;

    // read answer from file
    int num = 0;
    char line[MAXLEN];
    while(fgets(line, MAXLEN, file)){
        char *part = strtok(line, ":");
        flag.push_back(part);
        part = strtok(NULL, "\n");
        secret.push_back(part);
        bzero(&line, MAXLEN);
        num ++;
    }
    fclose(file);

    char recv_str[MAXLEN];
    while(1) {
        bzero(&recv_str, sizeof(recv_str));
        int len = read(sockfd, recv_str, MAXLEN);
        if (len < 0){
            cerr << "[Error] Read message error: " << sockfd << endl;
            return 0;
        } else if (len == 0) {
            cout << "[Info] Connection closed by client: " << sockfd << endl;
            return 0;
        } else {
            cout << "[Info] " << recv_str;
            char *ans = strtok(recv_str, "\r");
            for(int i=0; i<num; i++){
                // if(strncmp(ans, flag[i].c_str(), flag[i].length()) == 0){
                string sstr(recv_str);
                if(sstr.find(flag[i]) != std::string::npos) {
                    cout << "[Info] " << sockfd << " get correct answer " << ans << endl;
                    //cout << "[Info] Ans is " << secret[i] << endl;
                    if(write(sockfd, secret[i].c_str(), secret[i].length()) < 0) {
                        cerr << "[Error] Send secret error: " << sockfd << endl;
                        return 0;
                    }
                    break;
                }
           }
        }
    }
    return 0;
}

int main(int argc, char* argv[]) {
    int sockfd, connfd;
    struct sockaddr_in serv_addr;

    if (argc != 2) {
        cerr << "Usage: ./tcp_server <server port>" << endl;
        exit(1);
    }

    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        cerr << "[Error] Can't open stream socket" << endl;
        exit(1);
    }

    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family        = AF_INET;
    serv_addr.sin_port          = htons(atoi(argv[1]));
    serv_addr.sin_addr.s_addr   = htonl(INADDR_ANY);

    if(bind(sockfd, (SA *)&serv_addr, sizeof(serv_addr)) < 0) {
        cerr << "[Error] Can't bind local address" << endl;
        exit(1);
    }
    listen(sockfd, LISTENQ);

    // Accpet from client
    signal(SIGCHLD, SIG_IGN);
    while(1) {
        int childpid;
        if((connfd = accept(sockfd, NULL, NULL)) < 0) {
            cerr << "[Error] Accept error" << endl;
            continue;
        }
        if((childpid = fork()) < 0) {
            cerr << "[Error] Fork error" << endl;
            close(connfd);
            continue;
        } else if(childpid == 0) {       //child process
            close(sockfd);
            process_request(connfd);
            close(connfd);
            exit(0);
        }
    }
}
