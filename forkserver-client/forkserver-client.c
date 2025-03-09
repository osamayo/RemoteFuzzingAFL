#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include "getopt.h"
#include "stdbool.h"

#include <signal.h>

#include "../include/forkserver.h"
#include "../include/sharedmem.h"
#include "../include/common.h"
#include "../include/alloc-inl.h"
#include "../include/afl-remotefuzzing.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <pthread.h>
#include <assert.h>
#include <time.h>

#include "bitmap.h"

#define PATH_MAX	1024

void USAGE();
void setup_signal_handlers();
void at_exit_handler();
void setup_signal_handlers();
void hexdump (const char * desc, const void * addr, const int len, int perLine);
void setup_target_args(char **argv, u8 *prog_in, bool *use_stdin);
void Pthread_mutex_lock(pthread_mutex_t *mutex);

bool debug=false;
bool stop_soon=false;
uint32_t mapsize = DEFAULT_SHMEM_SIZE;



// Buffer
int FuzzingInstancesCount, testcasesBufferLen;
u8** testcases;
u32* testcasesLengthArr;
u8** virgin_bits;
u8** virgin_tmout;
u8** virgin_crash;
// u8** first_trace;

int mapsize_init;

FILE* timestamplog;


void run_target_analyze_feedback(afl_forkserver_t* fsrv, int*clients, int offset, bool trim_operation, uint8_t schedule, uint8_t crash_mode, u8 ignore_timeout, uint64_t saved_crashes, uint64_t saved_hangs, bool main_fuzzer)
{
    // puts("Running testcase & analyze feedback!");
    // puts(*(testcases+i));

    afl_fsrv_write_to_testcase(fsrv, *(testcases+offset), *(testcasesLengthArr+offset));
    fsrv_run_result_t ret = afl_fsrv_run_target(fsrv, fsrv->exec_tmout, (u8*)&stop_soon);
    if (mapsize_init != fsrv->map_size)
    {
        puts("mapsize changed");
        exit(EXIT_FAILURE);
    }

    Feedback feedback2 = {0};
    analyze_feedback(&feedback2, fsrv, trim_operation, schedule, ignore_timeout, crash_mode, saved_crashes, saved_hangs, *(testcasesLengthArr+offset), ret, virgin_bits, virgin_crash, virgin_tmout, offset);

    // printf("Feedback: %llu | %d\n", feedback2.cksum, feedback2.new_bits);

    FuzzingFeedback feedback = {0};
    size_t FeedbackStructLen = sizeof(FuzzingFeedback);

    feedback.fault = ret;

    feedback.mapsize = 0;
    feedback.real_mapsize = htonl(fsrv->real_map_size);
    feedback.cksum_lower = htonl((uint32_t)feedback2.cksum);
    feedback.cksum_upper = htonl(feedback2.cksum >> 32);
    u64 lower = (uint32_t)feedback2.exec_cksum;
    feedback.exec_cksum_lower = htonl(lower);
    u64 upper = feedback2.exec_cksum >> 32;
    feedback.exec_cksum_upper = htonl(upper);
    // printf("lower: %llu | upper: %llu | exec_cksum: %llu\n", lower, upper, feedback2.exec_cksum);
    feedback.new_bits = feedback2.new_bits;
    feedback.simplified_newbits = feedback2.simplified_newbits;
    if (main_fuzzer)
    {
        feedback.total_execs_lower = htonl((uint32_t) fsrv->total_execs);
        feedback.total_execs_upper = htonl(fsrv->total_execs >> 32);
    }
    // printf("Send analyzed feedback: %d\n", offset);
    int sent = send(*(clients+offset), &feedback, FeedbackStructLen, 0); 
    assert(sent == FeedbackStructLen);

    // printf("Feedback sent: [execs] %d [Mapsize] %d [RealMapsize] %d [Ret] %d\n", fsrv->total_execs, 0, fsrv->real_map_size, ret);

}

void run_target(afl_forkserver_t* fsrv, int* clients, int i, bool main_fuzzer)
{
    // puts("Running testcase!");
    // puts(*(testcases+i));

    afl_fsrv_write_to_testcase(fsrv, *(testcases+i), *(testcasesLengthArr+i));
    fsrv_run_result_t ret = afl_fsrv_run_target(fsrv, fsrv->exec_tmout, (u8*)&stop_soon);
    if (mapsize_init != fsrv->map_size)
    {
        puts("mapsize changed");
        exit(EXIT_FAILURE);
    }

    FuzzingFeedback feedback = {0};
    size_t FeedbackStructLen = sizeof(FuzzingFeedback);

    feedback.fault = ret;

    feedback.mapsize = htonl(fsrv->map_size);
    feedback.real_mapsize = htonl(fsrv->real_map_size);
    if (main_fuzzer)
    {
        feedback.total_execs_lower = htonl((uint32_t) fsrv->total_execs);
        feedback.total_execs_upper = htonl(fsrv->total_execs >> 32);
    }
    // printf("Send feedback: %d\n", i);
    int sent = send(*(clients+i), &feedback, FeedbackStructLen, 0); // TODO clientFd
    assert(sent == FeedbackStructLen);
    // printf("feedback header sent: %d\n", i);
    sent = send_buffer(*(clients+i), (u8*)fsrv->trace_bits, fsrv->map_size);// TODO clientFd
    assert(sent==fsrv->map_size);
    time_t tlog;
    tlog = time(NULL);
    fprintf(timestamplog, "%d\n", tlog);

    // printf("Feedback sent: [execs] %d [Mapsize] %d [RealMapsize] %d [Ret] %d\n", fsrv->total_execs, fsrv->map_size, fsrv->real_map_size, ret);

}

char **use_argv;

int main(int argc, char** argv) {
    char* ip;
    uint32_t port;
    int c;
    while ((c = getopt(argc, argv, "c:p:N:")) != -1)
    {
        switch (c)
        {
            case 'c':
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
            default:
                USAGE();
        }
    }

    if (port < 1 || ip == NULL || FuzzingInstancesCount == 0) {
        USAGE();
    }

    printf("ip: %s\n", ip);
    printf("port: %d\n", port);
    printf("Fuzzing Instances: %d\n", FuzzingInstancesCount);
    testcasesBufferLen = FuzzingInstancesCount;


    if (getenv("AFL_DEGUG")) debug = true;



    // init buffer
    testcases = (u8**) malloc(sizeof(u8*) * testcasesBufferLen);
    if (testcases == NULL )
    {
        perror("Error while malloc()");
        exit(EXIT_FAILURE);
    }
    for (int i=0; i<testcasesBufferLen; i++)
    {
        *(testcases+i) = (u8*) malloc(MAX_FILE);
        if (*(testcases+i) == NULL)
        {
            perror("Error while malloc()");
            exit(EXIT_FAILURE);
        }
    }


    testcasesLengthArr = (u32*) malloc (sizeof(u32) * testcasesBufferLen);
    if (testcasesLengthArr == NULL)
    {
        perror("Error while malloc()");
        exit(EXIT_FAILURE);
    }
    for (int i=0; i<testcasesBufferLen; i++)
    {
      *(testcasesLengthArr + i) = 0;
    }


    // Start forkserver
    afl_forkserver_t fsrv = {0};
    sharedmem_t shm = {0};

    afl_fsrv_init(&fsrv);

    init_count_class16();

    fsrv.map_size = get_map_size();
    fsrv.trace_bits = afl_shm_init(&shm, mapsize, 0);
    

    fsrv.out_file = strdup("./.cur_input");
    unlink(fsrv.out_file);                              /* Ignore errors */

    timestamplog = fopen("./calibratecase.tmp", "w");
    if (timestamplog==NULL)
    {
        puts("Error while creating log file!");
        exit(EXIT_FAILURE);
    }
    fsrv.out_fd = open(fsrv.out_file, O_RDWR | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
    fsrv.dev_null_fd = open("/dev/null", O_RDWR);

    if (fsrv.out_fd < 0) {FATAL("Unable to create '%s'", fsrv.out_file); }
    if (fsrv.dev_null_fd < 0) { PFATAL("Unable to open /dev/null"); }


    // detect target arguments
    u32 j = optind + 1;
    while (argv[j]) {

      u8 *aa_loc = strstr(argv[j], "@@");

      if (aa_loc) {

        // use stdin=false; replace @@ with full path out_file

        setup_target_args(argv + optind + 1, fsrv.out_file, &fsrv.use_stdin);
        use_argv = argv+optind;
        break;

      }

      ++j;

    }

    // atexit(at_exit_handler);
    // setup_signal_handlers();
    // set_up_environment(&fsrv);
    fsrv.target_path = find_binary(argv[optind]);
    puts(fsrv.target_path);
    afl_fsrv_start(&fsrv, use_argv, (u8*)&stop_soon, 0);

    // Init virgin maps
    mapsize_init = fsrv.map_size; // TODO remove
    virgin_bits = (u8**) malloc(sizeof(u8*) * FuzzingInstancesCount);
    virgin_tmout = (u8**) malloc(sizeof(u8*) * FuzzingInstancesCount);
    virgin_crash = (u8**) malloc(sizeof(u8*) * FuzzingInstancesCount);
    // first_trace = (u8**) malloc (sizeof(u8*) * FuzzingInstancesCount);

    if (!virgin_bits || !virgin_crash || !virgin_tmout)
    {
        perror("Error while malloc()");
        exit(EXIT_FAILURE);
    }

    for (int i=0; i<FuzzingInstancesCount; i++)
    {
        *(virgin_bits + i) = (u8*) malloc(fsrv.map_size);
        *(virgin_tmout + i) = (u8*) malloc(fsrv.map_size);
        *(virgin_crash + i) = (u8*) malloc(fsrv.map_size);
        // *(first_trace + i) = (u8*) malloc(fsrv.map_size);

        if ((*(virgin_bits+i) == NULL)  || (*(virgin_crash+i) == NULL) || (*(virgin_tmout+i) == NULL))
        {
            perror("Error while malloc()");
            exit(EXIT_FAILURE);
        }

        memset(*(virgin_bits+i), 255, fsrv.map_size);
        memset(*(virgin_crash+i), 255, fsrv.map_size);
        memset(*(virgin_tmout+i), 255, fsrv.map_size);
        // memset(*(first_trace+i), 255, fsrv.map_size);
    }

    // Init server
    ServerInfo info = {0};
    info.ip = ip;
    info.port = port;
    int* clients = start_multiple_instances_server(&info, FuzzingInstancesCount); // wait all fuzzing instances to connect
    //int* clientFd = start_server(&info); // TODO

    size_t FeedbackStructLen = sizeof(FuzzingFeedback);
    FuzzingFeedback signalFeedback = {0};
    signalFeedback.sync = true;

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
    while (true)
    {
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

                // printf("client: %d is ready!\n", i);
                FuzzingTestcase testcase = {0};
                // printf("Waiting client: %d\n", i);
                packetLen = recv(*(clients+i), &testcase, testcaseStructLen, 0);
                
                if (packetLen != testcaseStructLen)
                {
                    printf("Client %d disconnected\n", i);
                    exit(EXIT_FAILURE);
                }

                if (testcase.sync && testcase.update_virgin_bits)
                {
                    // send virgin_bits maps

                    FuzzingFeedback update_res = {0};
                    size_t s = sizeof(FuzzingFeedback);
                    update_res.mapsize = htonl(fsrv.map_size);
                    int sent = send_buffer(*(clients+i), (u8*)&update_res, s);
                    assert(sent == s);
                    sent = send_buffer(*(clients+i), (u8*)*(virgin_bits+i), fsrv.map_size);
                    assert(sent == fsrv.map_size);
                    // printf("Send virgin_bits update %d: %d\n", i, fsrv.map_size);
                    continue;
                }
                else if (testcase.update_virgin_bits)
                {
                    // handle update virgin map
                    uint32_t len = ntohl(testcase.length);
                    // printf("Recieve virgin_bits update %d: %d\n", i, len);
                    packetLen = recieve_buffer(*(clients+i), *(virgin_bits+i), len);
                    assert(packetLen == len);
                    continue;
                }else
                {
                    uint32_t len = ntohl(testcase.length);
                    // printf("testcase length: %d\n", len);
                    // clear previous testcase
                    memset(*(testcases+i), 0, *(testcasesLengthArr+i)); // TODO remove

                    packetLen = recieve_buffer(*(clients+i), *(testcases+i), len);
                    
                    if (packetLen != len)
                    {
                        printf("Client %d disconnected\n", i);
                        exit(EXIT_FAILURE);
                    }
                    // printf("testcase recieved: %d %d\n", i, len);
                    *(testcasesLengthArr + i) = len;

                    bool analyze_feedback = testcase.analyze_feedback;
                    bool trim_operation = testcase.trim_operation;
                    if (analyze_feedback)
                    {
                        uint8_t ignore_timeout = testcase.ignore_timeout;
                        uint8_t schedule = testcase.schedule;
                        uint8_t crash_mode = testcase.crash_mode;
                        uint64_t saved_crashes = ntohl(testcase.saved_crashes_upper) << 32;
                        saved_crashes += ntohl(testcase.saved_crashes_lower);
                        uint64_t saved_hangs = ntohl(testcase.saved_hangs_upper) << 32;
                        saved_hangs += ntohl(testcase.saved_hangs_lower);

                        run_target_analyze_feedback(&fsrv, clients, i, trim_operation, schedule, crash_mode, ignore_timeout, saved_crashes, saved_hangs, testcase.main_fuzzer);

                    }  else 
                    {
                        // run testcase & send feedback
                        run_target(&fsrv, clients, i, testcase.main_fuzzer);

                    }
                }

            }
        }


    }

    return 0;
}

void setup_target_args(char **argv, u8 *prog_in, bool *use_stdin) {
  u32 i = 0;
  u8  cwd[PATH_MAX];
  if (getcwd(cwd, (size_t)sizeof(cwd)) == NULL) { PFATAL("getcwd() failed"); }

  /* we are working with libc-heap-allocated argvs. So do not mix them with
   * other allocation APIs like ck_alloc. That would disturb the free() calls.
   */
  while (argv[i]) {

    u8 *aa_loc = strstr(argv[i], "@@");

    if (aa_loc) {

      if (!prog_in) { FATAL("@@ syntax is not supported by this tool."); }

      *use_stdin = false;

      /* Be sure that we're always using fully-qualified paths. */

      *aa_loc = 0;

      /* Construct a replacement argv value. */
      u8 *n_arg;

      if (prog_in[0] == '/') {

        n_arg = alloc_printf("%s%s%s", argv[i], prog_in, aa_loc + 2);

      } else {

        n_arg = alloc_printf("%s%s/%s%s", argv[i], cwd, prog_in, aa_loc + 2);

      }

    //   ck_free(argv[i]);
      argv[i] = n_arg;
    }

    i++;

  }

  /* argvs are automatically freed at exit. */

}


void USAGE()
{
    perror("Usage: forkserver-client -c <LISTEN-IP> -p <LISTEN-PORT> -N <Number of Fuzzing Instances> -- /path/to/fuzzed_app [ ... ]\n");
    exit(1);
}


/* Handle Ctrl-C and the like. */

void handle_stop_sig(int sig) {
  puts("Interrupt sig\n");
  stop_soon = 1;
  afl_fsrv_killall();
  exit(0);
}

void at_exit_handler() {
  puts("Exit handler\n");
  afl_fsrv_killall();

}

void setup_signal_handlers() {

  struct sigaction sa;

  sa.sa_handler = NULL;
  sa.sa_flags = SA_RESTART;
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);

  /* Various ways of saying "stop". */

  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

}


