#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include "stdbool.h"
#include "pthread.h"

#ifndef afl_forkserver_t
#include "forkserver.h"
#endif

#ifdef __AFL_FUZZER_SERVER__
#include "afl-fuzz.h"
#endif

typedef struct {
    char* ip;
    uint32_t port;
} ServerInfo;

typedef struct {
    uint32_t length;
    bool analyze_feedback;
    bool trim_operation;
    bool update_firsttrace;
    bool update_virgin_bits;
    bool update_trace_bits;
    bool sync;
    bool main_fuzzer;
    uint32_t saved_hangs_upper;
    uint32_t saved_hangs_lower;
    uint32_t saved_crashes_upper;
    uint32_t saved_crashes_lower;
    uint8_t crash_mode;
    uint8_t schedule;
    uint8_t ignore_timeout;
    uint8_t instance_id;
    // uint32_t total;
} FuzzingTestcase;

typedef struct {
    uint8_t  fault;
    uint32_t mapsize;
    uint32_t real_mapsize;
    // uint32_t id;
    uint32_t total_execs_upper;
    uint32_t total_execs_lower;
    uint8_t new_bits;
    uint8_t simplified_newbits;
    uint32_t cksum_upper;
    uint32_t cksum_lower;
    uint32_t exec_cksum_upper;
    uint32_t exec_cksum_lower;
    bool sync;

} FuzzingFeedback;

typedef struct {
    pthread_mutex_t* mutex;
    pthread_cond_t*  cond;
    int* run_result;
    bool* ready;
} FeedbackCondVar;

#ifdef __AFL_FUZZER_SERVER__
void recieve_feedback(afl_state_t*);
#endif
void reconnect_with_client(int* clientsFd, int offset);
int connect_server(ServerInfo*);
int start_server(ServerInfo*);
int* start_multiple_instances_server(ServerInfo*, u8);
size_t recieve_buffer(int sock, u8* buffer, u32 len);
int send_buffer(int sock, u8* buffer, u32 len);

FeedbackCondVar init_cond_var();
