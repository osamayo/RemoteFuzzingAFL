#include "afl-remotefuzzing.h"
#include <pthread.h>
#include <assert.h>

int serversock, remoteClientFd, remoteClientStructLen;
struct sockaddr_in fuzzingServerAddr, remoteClient;

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
int run_result;
bool readySync;

int connect_server(ServerInfo* info)
{
    char* ip = info->ip;
    uint32_t port = info->port;
    int serverFd;
    struct sockaddr_in serv_addr;
    if ((serverFd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
        perror("Socket creation error\n");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = inet_addr(ip);
    if (connect(serverFd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) !=0 )
    {
        perror("Couldn't connect to the server!\n");
        return -1;
    }

    puts("Successfully connected to the server!\n");
    return serverFd;

}

int start_server(ServerInfo* info)
{
    char* ip = info->ip;
    uint32_t port = info->port;
    
    printf("Starting server: %s %d!\n", ip, port);
    int opt=1;
    serversock = socket(AF_INET, SOCK_STREAM, 0);
    if (serversock == -1)
    {
        perror("socket creation failed!\n");
        exit(1);
    }

    fuzzingServerAddr.sin_family = AF_INET;
    fuzzingServerAddr.sin_port = htons(port);
    fuzzingServerAddr.sin_addr.s_addr = inet_addr(ip);

    if (setsockopt(serversock, SOL_SOCKET,
                   SO_REUSEADDR | SO_REUSEPORT, &opt,
                   sizeof(opt))) {
        perror("setsockopt\n");
        exit(EXIT_FAILURE);
    }

    if ((bind(serversock, (struct sockaddr*)&fuzzingServerAddr, sizeof(fuzzingServerAddr)))!=0)
    {
        perror("socket bind failed!\n");
        exit(EXIT_FAILURE);
    }

    if ((listen(serversock, 1))!=0) {
        perror("listen failed!\n");
        exit(EXIT_FAILURE);
    }

    puts("Listening!");
    if ((remoteClientFd  = accept(serversock, (struct sockaddr*)&remoteClient, &remoteClientStructLen)) < 0 ) {
        perror("Accept client failed!\n");
        exit(EXIT_FAILURE);
    }
    puts("Successfully connected!");
    return remoteClientFd;

}

int* start_multiple_instances_server(ServerInfo* info, u8 InstancesCount)
{
    // malloc n array
    int* clients = (int*) malloc(sizeof(int)*InstancesCount);
    if (clients == NULL)
    {
        perror("Failed to malloc!");
        exit(EXIT_FAILURE);
    }

    for (int i=0; i<InstancesCount; i++)
    {
        *(clients+i) = 0;
    }



    char* ip = info->ip;
    uint32_t port = info->port;
    
    printf("Starting server: %s %d!\n", ip, port);
    int opt=1;
    serversock = socket(AF_INET, SOCK_STREAM, 0);
    if (serversock == -1)
    {
        perror("socket creation failed!\n");
        exit(1);
    }

    fuzzingServerAddr.sin_family = AF_INET;
    fuzzingServerAddr.sin_port = htons(port);
    fuzzingServerAddr.sin_addr.s_addr = inet_addr(ip);

    if (setsockopt(serversock, SOL_SOCKET,
                   SO_REUSEADDR | SO_REUSEPORT, &opt,
                   sizeof(opt))) {
        perror("setsockopt\n");
        exit(EXIT_FAILURE);
    }

    if ((bind(serversock, (struct sockaddr*)&fuzzingServerAddr, sizeof(fuzzingServerAddr)))!=0)
    {
        perror("socket bind failed!\n");
        exit(EXIT_FAILURE);
    }

    if ((listen(serversock, 1))!=0) {
        perror("listen failed!\n");
        exit(EXIT_FAILURE);
    }

    puts("Listening!");
    
    for (int i=0; i<InstancesCount; i++)
    {
        int c;
        if ((c  = accept(serversock, (struct sockaddr*)&remoteClient, &remoteClientStructLen)) < 0 ) {
            perror("Accept client failed!\n");
            exit(EXIT_FAILURE);
        }
        printf("Client %d connected successfully!\n", i);
        *(clients+i) = c;
    }

    puts("Successfully connected!");
    return clients;
}

void reconnect_with_client(int* clientsFd, int offset)
{
    puts("Listening!");
    int c;
    if ((c  = accept(serversock, (struct sockaddr*)&remoteClient, &remoteClientStructLen)) < 0 ) {
        perror("Accept client failed!\n");
        exit(EXIT_FAILURE);
    }
    printf("Client %d connected successfully!\n", offset);
    *(clientsFd+offset) = c;
    return;
}

FeedbackCondVar init_cond_var() {
    FeedbackCondVar ret = {0};
    ret.cond = &cond;
    ret.mutex = &lock;
    ret.run_result = &run_result;
    ret.ready = & readySync;
    // printf("init_cond_var: %p %p %p\n", ret.cond, ret.mutex, ret.run_result);
    return ret;
}

size_t recieve_buffer(int sock, u8* buffer, u32 len)
{
    int ret;
    int recievedLen=0;

    while (recievedLen < len && (ret = recv(sock, buffer + recievedLen, len - recievedLen, 0)) > 0)
        recievedLen += ret;

    return recievedLen;
}

int send_buffer(int sock, u8* buffer, u32 len)
{
    int bytes_sent = 0;
    while (len > 0)
    {
        bytes_sent = send(sock, buffer, len, 0);
        if (bytes_sent == -1)
        {
            printf("Error: %d %d %d\n", sock, len, bytes_sent);
            return -1;
        }

        buffer += bytes_sent;
        len -= bytes_sent;
    }
    return bytes_sent;
}

#ifdef __AFL_FUZZER_SERVER__
void recieve_feedback(afl_state_t* afl){
    // int counter = 0;
    // int packetLen;
    // FuzzingFeedback feedback = {0};
    // afl_forkserver_t fsrv = afl->fsrv;

    // puts("Start listening for feedbacks\n");
    // while ((packetLen = recv(remoteClientFd, &feedback, sizeof(FuzzingFeedback), 0)) > 0)
    // {
    //     if (feedback.sync)
    //     {
    //         // puts("------------------------- Feedback SYNC -------------------------\n");
    //         int mapsize = ntohl(feedback.mapsize);
    //         // printf("Recieved feedback sync: %d %d\n", feedback.fault, mapsize);

    //         uint32_t total_upper = ntohl(feedback.total_execs_upper);
    //         uint32_t total_lower = ntohl(feedback.total_execs_lower);
    //         afl->fsrv.total_execs = (total_upper << 32) + (total_lower);

    //         pthread_mutex_lock(&lock);
    //         // TODO
    //         int readLen = recieve_buffer(remoteClientFd, afl->fsrv.trace_bits, mapsize);
    //         if (readLen != mapsize)
    //         {
    //             printf("mapsize: %d, readlen: %d\n", mapsize, readLen);
    //             exit(EXIT_FAILURE);
    //         }          
            
    //         afl->fsrv.map_size = mapsize;

    //         run_result = feedback.fault;
    //         pthread_cond_signal(&cond);
    //         pthread_mutex_unlock(&lock);
    //     } else 
    //     {
    //         uint32_t id = ntohl(feedback.id);
    //         uint32_t mapsize = ntohl(feedback.mapsize);
    //         if (id == (uint32_t) -1)
    //         {  counter++;
    //             // printf("Ready signal recieved!: %d\n", counter);
    //             // client is ready
    //             pthread_mutex_lock(&afl->fsrv.mutex);
                
    //             afl->fsrv.ready = true;
    //             // puts("Waking common fuzz");
    //             pthread_cond_signal(&afl->fsrv.cond);

    //             pthread_mutex_unlock(&afl->fsrv.mutex);
    //         } else if (mapsize > 0)
    //         {
    //             // printf("Recieved feedback async: %d %d\n",  feedback.fault, mapsize);
    //             // TODO insecure id 
    //             uint32_t total_upper = ntohl(feedback.total_execs_upper);
    //             uint32_t total_lower = ntohl(feedback.total_execs_lower);
    //             afl->fsrv.total_execs = (total_upper << 32) + (total_lower);
    //             // printf("Total execs: %d\n", afl->fsrv.total_execs);
    //             afl->fsrv.map_size = mapsize;
    //             u32 id = ntohl(feedback.id);
    //             if (id >= afl->fsrv.bufferLen)
    //             {
    //                 FATAL("Insecure ID");
    //             }
                
    //             // printf("feedback id: %d\n", id);

    //             // printf("memset: %d\n", *(fsrv.feedbacksLengthArr+id));
    //             int readLen = recieve_buffer(remoteClientFd, *(fsrv.feedbacksBuffer+id), mapsize);
    //             // puts("recieve buffer");
    //             if (readLen != mapsize)
    //             {
    //                 printf("mapsize: %d, readlen: %d\n", mapsize, readLen);
    //                 exit(EXIT_FAILURE);
    //             }
    //             *(fsrv.feedbacksLengthArr + id) = mapsize;

    //             *(fsrv.feedbacksFaultCodes + id) = feedback.fault;
    //             // printf("mapsize: %d\n", *(fsrv.feedbacksLengthArr+id));

    //             // TODO Can't be handled by recieve feedback threads
    //             // puts("save_if_interesting before called()\n");
    //             // afl->queued_imported += save_if_interesting(afl, *(afl->fsrv.testcasesBuffer + id), *(afl->fsrv.testcasesBufferLengthArr + id), feedback.fault);
    //             // puts("save_if_interesting called()\n");
                
    //         }
    //     }
    // }
}
#endif