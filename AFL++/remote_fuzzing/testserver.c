#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include "stdbool.h"
#include "../include/afl-remotefuzzing.h"


uint8_t tracebits[1 * 1024 * 1024L];
int main() {

    ServerInfo server = {0};
    server.ip = "127.0.0.1";
    server.port = 4444;
    int sock = connect_server(&server);


    FILE* f = fopen("/home/kali/Desktop/testcase1963.err", "rb");
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    printf("fsize: %d\n", fsize);
    fseek(f, 0, SEEK_SET);
    u8* input = (u8*) malloc(fsize);
    if (input == NULL) {perror("malloc");};
    int fBytes = fread(input, fsize, 4096, f);
    printf("fbytes: %d\n", fBytes);

    FuzzingTestcase testcase = {0};
    testcase.id = 0;
    testcase.sync = true;
    testcase.length = htonl(fsize);
    write(sock, &testcase, sizeof(testcase));
    puts(input);
    int written = write(sock, input, fsize);
    if (written != fsize)
    {
        perror("write");
    }

    FuzzingFeedback feedback = {0};
    read(sock, &feedback, sizeof(feedback));
    int ret = ntohl(feedback.fault);
    int mapsize = ntohl(feedback.mapsize);
    printf("feedback: %d %d\n", ret, mapsize);
    int bytes = read(sock, tracebits, mapsize);
    printf("tracebits: %d", bytes);
        // sleep(2);


    return 0;
}