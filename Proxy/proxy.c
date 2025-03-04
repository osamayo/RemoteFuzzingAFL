#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include <string.h>
#include "afl-remotefuzzing.h"
#include "stdbool.h"
#include "rs232.h"

// Buffer
uint8_t FuzzingInstancesCount;
int testcasesBufferLen;
u8* testcaseBuffer;
u32 testcaseLength;
u8* bitmapBuffer;
u32 bitmap_size;

bool debug;

int boardSock=0;

u8 MAX_LENGTH=1000;
int cport_nr=16;       /* /dev/ttyUSB0  */
int bdrate=115200;     /* 9600 baud */
char padding[1000] = {0}; // TODO: use halfSize

bool Serial=true;
void SerialInit()
{
    if (!Serial)
    {
        ServerInfo info = {0};
        info.ip = "127.0.0.1";
        info.port = 4444;
        
        boardSock = connect_server(&info);
        if (boardSock==-1)
        {
        puts("Failed to connect to board!");
        exit(EXIT_FAILURE);
        }
    } else 
    {
        char mode[]={'8','N','1',0};

        if(RS232_OpenComport(cport_nr, bdrate, mode, 0))
        {
        printf("Can not open comport\n");
        exit(EXIT_FAILURE);
        }
        puts("Connected!");
      
    }
       

  
}

size_t SerialWrite(u8* buffer, u32 len)
{
    if (!Serial)
        return send_buffer(boardSock, buffer, len);
    else
    {
        int bytes_sent = 0;
        while (len > 0)
        {
            bytes_sent = RS232_SendBuf(cport_nr, buffer, len);
            if (bytes_sent == -1)
            {
                printf("Error: %d %d\n", len, bytes_sent);
                return -1;
            }

            buffer += bytes_sent;
            len -= bytes_sent;
        }
        return bytes_sent;

    }
    //    return RS232_SendBuf(cport_nr, buffer, len);

}

size_t SerialRead(u8* OutBuffer, u32 len)
{
    if (!Serial)
        return recieve_buffer(boardSock, OutBuffer, len);
    else 
    {
        int ret=0;
        int recievedLen=0;

        time_t t0 = time(0);
        while (recievedLen < len && (ret = RS232_PollComport(cport_nr, OutBuffer + recievedLen, len - recievedLen))>=0 ) // TODO: Improve >0
        {
            if (ret == 0)
            {
                time_t t1 = time(0);
                double diff = difftime(t1, t0);
                if ((int)diff > 5) // Wait 5 seconds
                {
                    printf("Recieved: %d | len: %d | ret: %d\n", recievedLen, len, ret);
                    return recievedLen;
                }

            } else 
            {
                recievedLen += ret;

            }
        }    

        return recievedLen;
    }
        // return RS232_PollComport(cport_nr, OutBuffer, len);

}


void USAGE()
{
    perror("Usage: proxy -l <listen-ip> -p <listen-port> -M <Max-testcase-length> -N <Number of Fuzzing Instances> \n");
    exit(1);
}

int main(int argc, char** argv) {
    char* ip;
    uint32_t port;
    int c;
    while ((c = getopt(argc, argv, "sl:p:N:M:")) != -1)
    {
        switch (c)
        {
            case 'l':
                if (!optarg) {perror("No argument specified"); exit(EXIT_FAILURE);}
                ip = optarg;
                break;
            case 'p':
                if (!optarg) {perror("No argument specified"); exit(EXIT_FAILURE);}
                port = atoi(optarg);
                break;
            case 'N':
                if (!optarg) {perror("No argument specified"); exit(EXIT_FAILURE);}
                FuzzingInstancesCount = atoi(optarg);
                break;
            case 'M':
                if (!optarg) {perror("No argument specified"); exit(EXIT_FAILURE);}
                MAX_LENGTH = atoi(optarg);
                break;

            case 's':
                Serial=true;
            default:
                USAGE();
        }
    }
    printf("ip: %s\n", ip);
    printf("port: %d\n", port);
    printf("Fuzzing Instances: %d\n", FuzzingInstancesCount);
    testcasesBufferLen = FuzzingInstancesCount;

    if (port < 1 || ip == NULL || FuzzingInstancesCount == 0) {
        USAGE();
    }

    if (getenv("AFL_DEGUG")) debug = true;



    // init buffer
    testcaseBuffer = (u8*) malloc(MAX_FILE);
    bitmapBuffer = (u8*) malloc(DEFAULT_SHMEM_SIZE);

    if (testcaseBuffer == NULL || bitmapBuffer == NULL)
    {
        perror("Error while malloc()");
        exit(EXIT_FAILURE);
    }
    memset(bitmapBuffer, 0, DEFAULT_SHMEM_SIZE);
    
    printf("FuzzingTestcase: %d\n", sizeof(FuzzingTestcase));

    // connecting to board
    puts("Connecting to board");
    SerialInit();
    puts("Successfully connected to board");

    puts("Sending number of instances");
    SerialWrite(&FuzzingInstancesCount, 1);


    size_t FeedbackStructLen = sizeof(FuzzingFeedback);
    FuzzingFeedback signalFeedback = {0};
    printf("FeedbackStructLen: %d\n", FeedbackStructLen);


    puts("Waiting for device signal packet");
    int ret=0;
    ret = SerialRead((u8*)&signalFeedback, FeedbackStructLen);

    printf("SerialRead: %d\n", ret);
    assert(ret == FeedbackStructLen);
    puts("Successfully recieved signal feedback");



    ServerInfo info = {0};
    info.ip = ip;
    info.port = port;
    int* clients = start_multiple_instances_server(&info, FuzzingInstancesCount); // wait all fuzzing instances to connect


    // exit(0);
    // send a signal to all fuzzing instances
    for (int i=0; i<FuzzingInstancesCount; i++)
    {
        int sent = send(*(clients+i), &signalFeedback, FeedbackStructLen, 0);
        assert(sent == FeedbackStructLen);
    }
    // main
    size_t testcaseStructLen = sizeof(FuzzingTestcase);
    fd_set clientsFd;
    int packetLen;
    bool ready=false;
    size_t halfSize = 100;
    memset(padding, 0, sizeof(padding));
    uint32_t totalSent=0;
    struct timespec tstart={0,0}, tend={0,0};
    while (true)
    {
        // n = RS232_PollComport(cport_nr, buf, 4095);

        // if(n > 0)
        // {
        // buf[n] = 0;   /* always put a "null" at the end of a string! */

        // printf("received %i bytes\n", n);
        // puts(buf);
        // }

        FD_ZERO(&clientsFd);

        for (int i=0; i<FuzzingInstancesCount; i++)
        {
            int fd = *(clients+i);
            FD_SET(fd, &clientsFd);
        }

        int max_fd = *(clients+FuzzingInstancesCount-1); // TODO improve

    
        int rc = select(max_fd+1, &clientsFd, NULL, NULL, NULL);

        for (int i=0; i<FuzzingInstancesCount; i++)
        {
            int fd = *(clients+i);
            if (FD_ISSET(fd, &clientsFd)) {
                clock_gettime(CLOCK_MONOTONIC, &tstart);

                // printf("client: %d is ready!\n", i);
                FuzzingTestcase testcase = {0};
                // printf("Waiting client: %d\n", i);
                packetLen = recv(*(clients+i), &testcase, testcaseStructLen, 0);
                if (packetLen != testcaseStructLen)
                {
                    printf("Client %d disconnected\n", i);
                    exit(EXIT_FAILURE);
                }
                
                testcase.instance_id = (u8)i;
                puts("Sending testcase header");
                packetLen=SerialWrite((u8*)&testcase, testcaseStructLen);
                if (packetLen != testcaseStructLen)
                {
                    printf("Device is disconnected1\n");
                    exit(EXIT_FAILURE);
                }
                totalSent+=testcaseStructLen;
                puts("header sent");

                if (testcase.sync && testcase.update_virgin_bits)
                {
                    // sending padding bytes
                    SerialWrite(padding, halfSize - testcaseStructLen);
                    totalSent+= (halfSize-testcaseStructLen);
                    // send virgin_bits maps
                    puts("Receiving virgin_bit map from device");
                    FuzzingFeedback update_res = {0};
                    size_t s = sizeof(FuzzingFeedback);
                    packetLen=SerialRead((u8*)&update_res, s);
                    if (packetLen != s)
                    {
                        printf("Device is disconnected2\n");
                        exit(EXIT_FAILURE);
                    }

                    u32 mapsize= htonl(update_res.mapsize);

                    packetLen=SerialRead(bitmapBuffer, mapsize);
                    if (packetLen != mapsize)
                    {
                        char msg[100] = {0};
                        sleep(5);
                        SerialRead(msg, 100);
                        printf("msg: %s", msg);
                        printf("Device is disconnected3\n");
                        exit(EXIT_FAILURE);

                        
                    }

                    int sent = send_buffer(*(clients+i), (u8*)&update_res, s);
                    assert(sent == s);
                    sent = send_buffer(*(clients+i), bitmapBuffer, mapsize);
                    assert(sent == mapsize);
                    // printf("Send virgin_bits update %d: %d\n", i, fsrv.map_size);
                    printf("Total Sent: %d\n", totalSent);
                    totalSent=0;
                    continue;    

                }
                else if (testcase.update_virgin_bits)
                {
                    // handle update virgin map
                    uint32_t len = ntohl(testcase.length);
                    printf("Send virgin_bits update %d: %d\n", i, len);
                    packetLen = recieve_buffer(*(clients+i), bitmapBuffer, len);
                    assert(packetLen == len);
                    uint32_t padding = 0;
                    uint32_t lentmp = len;
                    len += testcaseStructLen;
                    if (len <= halfSize)
                    {
                        padding = halfSize - len;
                    } else 
                    {
                        padding = halfSize - (len % halfSize);
                    }
                    packetLen=SerialWrite(bitmapBuffer, lentmp+padding);
                    totalSent+=lentmp+padding;
                    if (packetLen != lentmp+padding)
                    {
                        printf("Device is disconnected4\n");
                        exit(EXIT_FAILURE);
                    }
                    printf("Total Sent: %d\n", totalSent);
                    totalSent=0;

                    continue;
                }else
                {

                    uint32_t len = ntohl(testcase.length);
                    printf("testcase length: %d\n", len);
                    assert(len <=MAX_LENGTH); // MAX LENGTH

                    packetLen = recieve_buffer(*(clients+i), testcaseBuffer, len);
                    
                    if (packetLen != len)
                    {
                        printf("Client %d disconnected\n", i);
                        exit(EXIT_FAILURE);
                    }
                    // puts(testcaseBuffer);
                    
                    
                    uint32_t padding = 0;
                    uint32_t lentmp = len;
                    len+=testcaseStructLen;
                    if (len <= halfSize)
                    {
                        padding = halfSize - len;
                    } else 
                    {
                        padding = halfSize - (len % halfSize);
                    }
                    // memset(testcaseBuffer+lentmp, 0, padding); //TODO: Restore
                    printf("Sending testcase body %d with padding %d\n", len, padding);
                    packetLen = SerialWrite(testcaseBuffer, lentmp+padding);
                    totalSent+=lentmp+padding;
                    if (packetLen != lentmp+padding)
                    {
                        printf("Device is disconnected5\n");
                        exit(EXIT_FAILURE);
                    }
                    printf("Total Sent: %d\n", totalSent);
                    totalSent=0;
                    puts("testcase sent");

                    bool analyze_feedback = testcase.analyze_feedback;

                    FuzzingFeedback feedback = {0};
                    size_t s = sizeof(FuzzingFeedback);
                    
                    puts("Recieving feedback");
                    packetLen=SerialRead((u8*)&feedback, s);
                    clock_gettime(CLOCK_MONOTONIC, &tend);

                    // uint32_t boardt0 = ntohl(feedback.total_execs_lower);
                    // uint32_t boardt1 = ntohl(feedback.total_execs_upper);
                    // feedback.total_execs_lower = 0;
                    // feedback.total_execs_upper = 0;
                    // printf("Feedback t0: %d | t1: %d\n", boardt0, boardt1);

                    double diff = ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - 
           ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec);
                    printf("took about %f\n", diff *1000.);
           

                    if (packetLen != s)
                    {
                        puts("[*] Possible crash!");
                        FILE* f = fopen("./crash.bin", "wb");
                        fwrite(testcaseBuffer, 1, len, f);
                        fclose(f); 
                        printf("Device is disconnected6\n");
                        exit(EXIT_FAILURE);
                    }
                    puts("Feedback header recieved");

                    u32 mapsize= htonl(feedback.mapsize);

                    // puts("sending feedback header");
                    int sent = send_buffer(*(clients+i), (u8*)&feedback, s);
                    assert(sent == s);
                    // puts("header sent");
                    
                    
                    if (!analyze_feedback)
                    {
                        printf("recieving bitmap: %d\n", mapsize);
                        packetLen=SerialRead(bitmapBuffer, mapsize);
                        
                        // if (packetLen != mapsize) // ignore bitmap length check
                        // {
                        //     printf("Device is disconnected7\n");
                        //     exit(EXIT_FAILURE);
                        // }
                        puts("sending bitmap");
                        sent = send_buffer(*(clients+i), bitmapBuffer, mapsize);
                        assert(sent == mapsize);
                    } 

                }
            }
        }

    }

    return 0;
}

