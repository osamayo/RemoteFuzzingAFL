# American Fuzzy Lop++ (AFL++)

This repository contains a modified version of AFL++ (version 4.10c).

**Official AFL++ Repository:**  
[https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus)

You can either download and compile the modified version directly from this repository or manually patch an official AFL++ release by following the instructions below.

This modified version of AFL++ supports sending test cases via TCP/IP and receiving feedback in the form of either a bitmap or an analysis result.

---

## Getting Started

After compiling AFL++ from this repository or manually patching an official version, you can run AFL++ with remote fuzzing options as follows:

```sh
AFL_INPUT_LEN_MAX=<MAX_TESTCASE_LENGTH> ./afl-fuzz -i <input-dir> -o <output-dir> -r 1 -- tcp://<proxy-ip>:<port>
```

### Explanation of the `-r` Option:
- `-r 1` enables remote feedback analysis. This enhances fuzzing performance by reducing feedback size, as the target system sends only a few bytes instead of the full bitmap.
- `-r 0` disables remote feedback analysis, meaning the full bitmap will be sent instead.

---

## Manually Patching AFL++
To manually modify AFL++ for remote fuzzing, follow these steps:

1. **Include Additional Files:**
   - Add `afl-remotefuzzing.c` to the `src` directory.
   - Add `afl-remotefuzzing.h` to the `include` directory.

2. **Modify `forkserver.h`:**
   - Add the required fields in the `afl_forkserver` structure.

```c
  @@ -211,18 +202,52 @@ typedef struct afl_forkserver {
+  bool remote_fuzzing; /* remote fuzzing */
+  u32 port;
+  char* ip;
+  bool serverStarted;
+  u8* testcase;
+  u32 testcaseLen;
+  u8* testcase_gap_buffer;
+  u32 testcase_gap_len;
+  
+  // u32 bufferLen;
+  u8** testcases;
+  u8** testcasesBuffer;
+  u8** feedbacksBuffer; 
+
+  u32* testcasesLengthArr;
+  u32* testcasesBufferLengthArr;
+  u32* feedbacksLengthArr;
+  u8* feedbacksFaultCodes;
+
+  u32 testcasesPointer;
+  u32 testcasesBufferPointer;
+  bool HandleFeedbackRemotely;
+  
+  bool ready;
+  pthread_cond_t cond;
+  pthread_mutex_t mutex;
+  int clientFd;
+  u64 testcasesHash;
+  u64 feedbackHash;
+
+  // remote feedback analysis
+  bool enable_remote_feedback_analyze;
+  bool remote_feedback_analyze;
+  bool trim_operation;
+  bool main_fuzzer;
+  u8 schedule;
+  u8 crash_mode;
+  bool ignore_timeout;
+  u64 saved_crashes;
+  u64 saved_hangs;
+  u64 cksum;
+  u64 exec_cksum;
+  u8 new_bits;
+  u8 simplified_newbits;
+  
 } afl_forkserver_t;

```

3. **Declare Additional Functions:**
   - Ensure the necessary function declarations are added in the appropriate header files.

```c
+u8 save_if_interesting_remote_feedback(afl_state_t *, void *, u32, u8);
```

4. **Modify the Following Source Files:**
   - **`afl-fuzz.c`** → Add support for remote fuzzing options.
```c
@@ -25,9 +24,8 @@
+#include "afl-remotefuzzing.h"


@@ -227,6 +164,10 @@ static void usage(u8 *argv0, int more_help) {
       "  -Y            - use VM fuzzing (NYX mode - multiple instances mode)\n"
 #endif
       "\n"
+      "Remote fuzzing:\n"
+      "  -r <mode> - Target path -> tcp://<ip>:<port>\n"
+      "                - Mode 0: disable remote feedback analysis\n"
+      "                - Mode 1: enable remote feedback analysis\n\n"
 


@@ -612,11 +541,10 @@ int main(int argc, char **argv_orig, char **envp) {
 
   afl->shmem_testcase_mode = 1;  // we always try to perform shmem fuzzing
 
-  // still available: HjJkKqrv
-  while (
-      (opt = getopt(argc, argv,
-                    "+a:Ab:B:c:CdDe:E:f:F:g:G:hi:I:l:L:m:M:nNo:Op:P:QRs:S:t:T:"
-                    "uUV:w:WXx:YzZ")) > 0) {
+  // still available: HjJkKqruvwz
+  while ((opt = getopt(argc, argv,
+                       "+a:Ab:B:c:CdDe:E:f:F:g:G:hi:I:l:L:m:M:nNo:Op:P:QRs:S:t:"
+                       "T:UV:WXx:YZr:")) > 0) {
 
@@ -852,7 +743,7 @@ int main(int argc, char **argv_orig, char **envp) {
       case 'M': {                                           /* main sync ID */
 
         u8 *c;
-
+        afl->fsrv.main_fuzzer = true;


@@ -1485,7 +1366,21 @@ int main(int argc, char **argv_orig, char **envp) {
             "(custom_mutators/radamsa/).");
 
         break;
-
+      case 'r':                                                 /* Remote fuzzing*/
+        if (!optarg) {FATAL("Missing parameter for -r option");}
+
+        // afl->fsrv.bufferLen = atoi(optarg);
+        if (atoi(optarg) == 1)
+        {
+          afl->fsrv.enable_remote_feedback_analyze = true;
+        }
+        afl->fsrv.remote_fuzzing = true;
+        afl->fsrv.HandleFeedbackRemotely = true;
+        // if (afl->fsrv.bufferLen <= 0)
+        // {
+        //   FATAL("Wrong argument for r option");
+        // }
+        break;


@@ -2045,19 +1925,35 @@ int main(int argc, char **argv_orig, char **envp) {
 
   }
 
+
+// verify that remote fuzzing is running in main mode
+  if (afl->fsrv.remote_fuzzing )
+  {
+    if (afl->no_forkserver || afl->fsrv.qemu_mode || afl->fsrv.nyx_mode || afl->fsrv.cs_mode || afl->fsrv.frida_mode || afl->non_instrumented_mode || afl->unicorn_mode || afl->cmplog_binary)
+    {
+      FATAL("Remote fuzzing have to run in main mode  (instrumented mode && forkserver)");
+    }
+  }
+
   save_cmdline(afl, argc, argv);
   check_if_tty(afl);
   if (afl->afl_env.afl_force_ui) { afl->not_on_tty = 0; }
 
+// TODO: ignore binding to cpu
   get_core_count(afl);
 
   atexit(at_exit);
 
   setup_dirs_fds(afl);
 
+if (!afl->fsrv.remote_fuzzing)
+{
   #ifdef HAVE_AFFINITY
   bind_to_free_cpu(afl);
-  #endif                                                   /* HAVE_AFFINITY */
+  #endif                                                   
+}
+
+/* HAVE_AFFINITY */

@@ -2449,19 +2203,57 @@ int main(int argc, char **argv_orig, char **envp) {
 
   }
 
+  if (!afl->fsrv.remote_fuzzing) // remote funzzing - don't check binary
+  {
+    check_binary(afl, argv[optind]);
+  } else {
+    // parse ip and port
+    char* target = strdup(argv[optind]);
+
+    char* ret =  strstr(target, "tcp://");
+    if (ret == NULL)
+    {
+      FATAL("Error parsing ip & port");
+    }
+    int firstSlice = (ret+6) - target; 
+
+    ret = strstr((target+firstSlice), ":");
+    if (ret == NULL)
+    {
+      FATAL("Error parsing ip & port");
+    }
+    int secondSlice = (ret) - target;
+
+    int ipLen = secondSlice - firstSlice + 1;
+    char* ip = (char*) malloc(sizeof(char) * ipLen);
+    char* portStr = (char*) malloc(sizeof(char) * 6);
+
+    if ((ip == NULL) || (portStr == NULL))
+    {
+      FATAL("IP || Port malloc error");
+    }
+    memset(ip, 0, ipLen);
+    memset(portStr, 0, 6);
+    strncpy(ip, (target+firstSlice), ipLen -1 );
+    strncpy(portStr, (target+secondSlice+1), 5);
+
+
+    afl->fsrv.ip = ip;
+    afl->fsrv.port = atoi(portStr);
+  }
+


@@ -3416,35 +3030,14 @@ int main(int argc, char **argv_orig, char **envp) {
   }
 
 stop_fuzzing:
-
+  if (afl->fsrv.remote_fuzzing)
+    sync_fuzzers(afl);
   afl->force_ui_update = 1;  // ensure the screen is reprinted
   afl->stop_soon = 1;        // ensure everything is written
   show_stats(afl);           // print the screen one last time
   write_bitmap(afl);
   save_auto(afl);


```
   - **`afl-fuzz-run.c`** → Modify execution logic for remote test case transmission.
```c
@@ -276,6 +244,15 @@ u32 __attribute__((hot)) write_to_testcase(afl_state_t *afl, void **mem,
 static void write_with_gap(afl_state_t *afl, u8 *mem, u32 len, u32 skip_at,
                            u32 skip_len) {
 
+  if (afl->fsrv.remote_fuzzing && !afl->fsrv.testcase_gap_buffer)
+  {
+    afl->fsrv.testcase_gap_buffer = (u8*) malloc(MAX_FILE);
+    if (!afl->fsrv.testcase_gap_buffer)
+    {
+      FATAL("Error while malloc!");
+    }
+  }
+

 
@@ -339,8 +316,25 @@ static void write_with_gap(afl_state_t *afl, u8 *mem, u32 len, u32 skip_at,
     });
 
   }
+  // #TODO free - remote fuzzing
+  if (afl->fsrv.remote_fuzzing)
+  {
+    if (!post_process_skipped)
+    {
+      afl->fsrv.testcase = new_mem;
+      afl->fsrv.testcaseLen = new_size;
+    } else 
+    {
+
+      memcpy(afl->fsrv.testcase_gap_buffer, mem, skip_at);
+
+      memcpy(afl->fsrv.testcase_gap_buffer + skip_at, mem + skip_at + skip_len, tail_len);
+      afl->fsrv.testcase = afl->fsrv.testcase_gap_buffer;
+      afl->fsrv.testcaseLen = skip_at + tail_len;
+      
+    }


@@ -434,6 +428,26 @@ static void write_with_gap(afl_state_t *afl, u8 *mem, u32 len, u32 skip_at,
 
 u8 calibrate_case(afl_state_t *afl, struct queue_entry *q, u8 *use_mem,
                   u32 handicap, u8 from_queue) {
+  // request virgin_bits
+  if (afl->fsrv.remote_fuzzing && afl->fsrv.enable_remote_feedback_analyze)
+  {
+    return 0; // Ignore calibrate case for remote fuzzing & remote feedback analyze
+    FuzzingTestcase update_request ={0};
+    size_t s = sizeof(FuzzingTestcase);
+    update_request.sync = true;
+    update_request.update_virgin_bits = true;
+    int sent = send_buffer(afl->fsrv.clientFd, (u8*)&update_request, s);
+    assert(sent == s);
+    FuzzingFeedback update_res = {0};
+    s = sizeof(FuzzingFeedback);
+    int recieved = recieve_buffer(afl->fsrv.clientFd, (u8*)&update_res, s);
+    assert(recieved == s);
+    int mapsize = ntohl(update_res.mapsize);
+    recieved = recieve_buffer(afl->fsrv.clientFd, (u8*)afl->virgin_bits, mapsize);
+    assert(recieved == mapsize);
+    // printf("recieved virgin_bits: %d\n", mapsize);
+
+  }
 

@@ -459,12 +472,12 @@ u8 calibrate_case(afl_state_t *afl, struct queue_entry *q, u8 *use_mem,
   ++q->cal_failed;
 
   afl->stage_name = "calibration";
-  afl->stage_max = afl->afl_env.afl_cal_fast ? CAL_CYCLES_FAST : CAL_CYCLES;
+  afl->stage_max = (afl->afl_env.afl_cal_fast||afl->fsrv.remote_fuzzing) ? CAL_CYCLES_FAST : CAL_CYCLES;
 
   /* Make sure the forkserver is up before we do anything, and let's not
      count its spin-up time toward binary calibration. */
 
-  if (!afl->fsrv.fsrv_pid) {
+  if (!afl->fsrv.fsrv_pid && !afl->fsrv.remote_fuzzing) {


@@ -697,7 +702,29 @@ abort_calibration:
 
   if (!first_run) { show_stats(afl); }
 
-  update_calibration_time(afl, &calibration_start_us);
+  // send updated virgin_bits
+  if (afl->fsrv.remote_fuzzing && afl->fsrv.enable_remote_feedback_analyze)
+  {
+    FuzzingTestcase update = {0};
+    update.update_virgin_bits = true;
+    update.length = ntohl(afl->fsrv.map_size);
+    size_t structLen = sizeof(FuzzingTestcase);
+    int sent = send_buffer(afl->fsrv.clientFd, (u8*)&update, structLen);
+    assert(sent == structLen);
+
+    // printf("testcase header sent, last testcase executed: %d\n", fsrv->total_execs);
+    assert (sent == structLen);
+    sent = send_buffer(afl->fsrv.clientFd, (u8*)afl->virgin_bits, afl->fsrv.map_size);
+    if (sent != afl->fsrv.map_size)
+    {
+      printf("Sent: %d | len: %d\n", sent, afl->fsrv.map_size);
+      exit(1);
+      
+    }
+
+
+  }
+
   return fault;
 
 }


@@ -867,16 +884,14 @@ void sync_fuzzers(afl_state_t *afl) {
 
-        if (afl->stop_soon) { goto close_sync; }
+        if (afl->stop_soon && !afl->fsrv.remote_fuzzing) { goto close_sync; }
 

@@ -1013,10 +1013,25 @@ u8 trim_case(afl_state_t *afl, struct queue_entry *q, u8 *in_buf) {
       u64 cksum;
 
       write_with_gap(afl, in_buf, q->len, remove_pos, trim_avail);
+      if (afl->fsrv.enable_remote_feedback_analyze)
+      {
+        afl->fsrv.remote_feedback_analyze = true;
+        afl->fsrv.trim_operation = true;
+        afl->fsrv.ignore_timeout = afl->afl_env.afl_ignore_timeouts;
+        afl->fsrv.crash_mode = afl->crash_mode;
+        afl->fsrv.schedule = afl->schedule;
+        afl->fsrv.saved_hangs = afl->saved_hangs;
+        afl->fsrv.saved_crashes = afl->saved_crashes;
 
-      fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);
+      }
 
-      update_trim_time(afl, &trim_start_us);
+      fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);
+    // if (fault != 0)
+    //   {
+    //     printf("Fault trim: %d\n", fault);
+    //   }
+      afl->fsrv.trim_operation = false;
+      afl->fsrv.remote_feedback_analyze = false;
 
       if (afl->stop_soon || fault == FSRV_RUN_ERROR) { goto abort_trimming; }
 
@@ -1024,8 +1039,15 @@ u8 trim_case(afl_state_t *afl, struct queue_entry *q, u8 *in_buf) {
        */
 
       ++afl->trim_execs;
-      classify_counts(&afl->fsrv);
-      cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);
+      if (!afl->fsrv.enable_remote_feedback_analyze)
+      {
+        classify_counts(&afl->fsrv);
+        cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);
+
+      } else 
+      {
+        cksum = afl->fsrv.cksum;
+      }


@@ -1182,18 +1143,30 @@ abort_trimming:
    error conditions, returning 1 if it's time to bail out. This is
    a helper function for fuzz_one(). */
 
-u8 __attribute__((hot)) common_fuzz_stuff(afl_state_t *afl, u8 *out_buf,
-                                          u32 len) {
-
+u8 __attribute__((hot))
+common_fuzz_stuff(afl_state_t *afl, u8 *out_buf, u32 len) {
   u8 fault;
 
   if (unlikely(len = write_to_testcase(afl, (void **)&out_buf, len, 0)) == 0) {
+    puts("common fuzz 0!");
 
     return 0;
 
   }
 
+  if (afl->fsrv.enable_remote_feedback_analyze)
+  {
+    afl->fsrv.remote_feedback_analyze = true;
+    afl->fsrv.ignore_timeout = afl->afl_env.afl_ignore_timeouts;
+    afl->fsrv.crash_mode = afl->crash_mode;
+    afl->fsrv.schedule = afl->schedule;
+    afl->fsrv.saved_hangs = afl->saved_hangs;
+    afl->fsrv.saved_crashes = afl->saved_crashes;
+
+  }
+
   fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);
+  afl->fsrv.remote_feedback_analyze = false;
 
   if (afl->stop_soon) { return 1; }


@@ -1225,7 +1199,13 @@ u8 __attribute__((hot)) common_fuzz_stuff(afl_state_t *afl, u8 *out_buf,
 
   /* This handles FAULT_ERROR for us: */
 
-  afl->queued_discovered += save_if_interesting(afl, out_buf, len, fault);
+  if (afl->fsrv.enable_remote_feedback_analyze)
+  {
+    afl->queued_discovered += save_if_interesting_remote_feedback(afl, out_buf, len, fault);
+  } else 
+  {
+    afl->queued_discovered += save_if_interesting(afl, out_buf, len, fault);
+  }
 
   if (!(afl->stage_cur % afl->stats_update_freq) ||
       afl->stage_cur + 1 == afl->stage_max) {
```
   - **`afl-forkserver.c`** → Implement necessary changes for remote execution.
```c
@@ -52,6 +49,9 @@
 #include <sys/select.h>
 #include <sys/stat.h>
 
+#include "afl-remotefuzzing.h"

 void afl_fsrv_start(afl_forkserver_t *fsrv, char **argv,
                     volatile u8 *stop_soon_p, u8 debug_child_output) {
 
+  // remote fuzzing 
+  if (fsrv->remote_fuzzing && fsrv->serverStarted)
+  {
+    return;
+  }
+
+  if (fsrv->remote_fuzzing)
+  {
+
+    ServerInfo info = {0};
+    info.ip = fsrv->ip;
+    info.port = fsrv->port;
+    
+    fsrv->clientFd = connect_server(&info);
+    if (fsrv->clientFd==-1)
+    {
+      puts("Failed to connect to server!");
+      exit(EXIT_FAILURE);
+    }
+    fsrv->serverStarted = true;
+    puts("Waiting for a signal from client!\n");
+
+    FuzzingFeedback signalFeedback = {0};
+    size_t packetLen = sizeof(FuzzingFeedback);
+    int len = recv(fsrv->clientFd, &signalFeedback, packetLen, 0);
+    assert(len == packetLen);
+    fsrv->real_map_size = ntohl(signalFeedback.real_mapsize);
+    fsrv->map_size = ntohl(signalFeedback.mapsize);
+    puts("success!");
+    return ;
+  }
+
+


+void __attribute__((hot))
+afl_fsrv_write_to_testcase(afl_forkserver_t *fsrv, u8 *buf, size_t len) {
+
+  if (fsrv->remote_fuzzing)
+  {
+    fsrv->testcaseLen = len;
+    if (len == 0)
+    {
+      FATAL("length == 0");
+    }
+    fsrv->testcase = buf;

+    return;
+  }

@@ -1843,18 +1700,148 @@ void __attribute__((hot)) afl_fsrv_write_to_testcase(afl_forkserver_t *fsrv,
 /* Execute target application, monitoring for timeouts. Return status
    information. The called program will update afl->fsrv->trace_bits. */
 
-fsrv_run_result_t __attribute__((hot)) afl_fsrv_run_target(
-    afl_forkserver_t *fsrv, u32 timeout, volatile u8 *stop_soon_p) {
+fsrv_run_result_t __attribute__((hot))
+afl_fsrv_run_target(afl_forkserver_t *fsrv, u32 timeout,
+                    volatile u8 *stop_soon_p) {
+  
+  if (fsrv->remote_fuzzing)
+  {
+    size_t structLen = sizeof(FuzzingTestcase);
+    int ret;
+    FuzzingTestcase testcase = {0};
+    testcase.main_fuzzer = fsrv->main_fuzzer;
+
+    if (fsrv->remote_feedback_analyze)
+    {
+      testcase.length = htonl(fsrv->testcaseLen);
+      testcase.analyze_feedback = true;
+      testcase.ignore_timeout = fsrv->ignore_timeout;
+      testcase.crash_mode = fsrv->crash_mode;
+      testcase.schedule = fsrv->schedule;
+      testcase.saved_crashes_upper = htonl(fsrv->saved_crashes>>32);
+      testcase.saved_crashes_lower = htonl((uint32_t) fsrv->saved_crashes);
+      testcase.saved_hangs_upper = htonl(fsrv->saved_hangs>>32);
+      testcase.saved_hangs_lower = htonl((uint32_t) fsrv->saved_hangs);
+      if (fsrv->trim_operation) testcase.trim_operation = true;
+
+    } else 
+    {
+      testcase.length = htonl(fsrv->testcaseLen);
+
+    }
+    // send testcase
+
+    int sent = send_buffer(fsrv->clientFd, (u8*)&testcase, structLen);
+    // printf("testcase header sent, last testcase executed: %d\n", fsrv->total_execs);
+    // assert (sent == structLen);
+    if (sent!= structLen)
+            goto target_crashed;
+
+    sent = send_buffer(fsrv->clientFd, fsrv->testcase, fsrv->testcaseLen);
+    if (sent != fsrv->testcaseLen)
+    {
+      // printf("Sent: %d | len: %d\n", sent, fsrv->testcaseLen);
+      // exit(1);
+        goto target_crashed;
+
+    }
+
+    // recieve feedback
+    FuzzingFeedback feedback = {0};
+    structLen = sizeof(FuzzingFeedback);
+    int packetLen = recv(fsrv->clientFd, &feedback, structLen, 0);
+    if (packetLen != structLen)
+    {
+      goto target_crashed;
+    }
+
+    // printf("Feedback header recieved: %d\n", packetLen);
+
+
+
+    if (fsrv->remote_feedback_analyze)
+    {
+      fsrv->new_bits = feedback.new_bits;
+      fsrv->simplified_newbits = feedback.simplified_newbits;
+      u64 upper  = ((u64)ntohl(feedback.cksum_upper)) << 32;
+      u64 lower = ntohl(feedback.cksum_lower);
+      fsrv->cksum = upper + lower;
+      upper  = ((u64)ntohl(feedback.exec_cksum_upper)) << 32;
+      lower = ntohl(feedback.exec_cksum_lower);
+      fsrv->exec_cksum = upper + lower;
+
+      // printf("lower: %llu | upper: %llu | cksum: %llu\n", lower, upper, fsrv->exec_cksum);
+
+    }else 
+    {
+      int mapsize = ntohl(feedback.mapsize);
+      int readLen = recieve_buffer(fsrv->clientFd, fsrv->trace_bits, mapsize);
+      if (readLen != mapsize)
+      {
+          goto target_crashed;
+
+          // printf("mapsize: %d, readlen: %d\n", mapsize, readLen);
+          // exit(EXIT_FAILURE);
+      }          
+      // printf("feedback map recieved: %d\n", mapsize);
+      fsrv->map_size = mapsize;
+
+    }
+
+      // fsrv->total_execs++;
+
+    if (fsrv->main_fuzzer)
+    {
+      u64 upper  = ((u64)ntohl(feedback.total_execs_upper)) << 32;
+      u64 lower = ntohl(feedback.total_execs_lower);
+      fsrv->total_execs = upper + lower;
+      // printf("execs: %d - %d \n", fsrv->total_execs, upper+ lower);
+
+    } else 
+    {
+      fsrv->total_execs++;
+    }
+    // fsrv->real_map_size = ntohl(feedback.real_mapsize);
+    // fsrv->map_size = ntohl(feedback.mapsize);
+
+    ret = feedback.fault;
+
+
+    return ret;
+
+    target_crashed:
+      // Target crashed during testcase
+        while (true)
+        {
+            sleep(10);
+            puts("Trying to reconnect!");
+            ServerInfo info = {0};
+            info.ip = fsrv->ip;
+            info.port = fsrv->port;
+            
+            fsrv->clientFd = connect_server(&info);
+            if (fsrv->clientFd==-1)
+              continue;
+            fsrv->serverStarted = true;
+            puts("Waiting for a signal from client!\n");
+
+            FuzzingFeedback signalFeedback = {0};
+            size_t packetLen = sizeof(FuzzingFeedback);
+            int len = recv(fsrv->clientFd, &signalFeedback, packetLen, 0);
+            assert(len == packetLen);
+            fsrv->real_map_size = ntohl(signalFeedback.real_mapsize);
+            fsrv->map_size = ntohl(signalFeedback.mapsize);
+            puts("success!");
+            fsrv->total_execs++;
+            return 0;
+
+        }
+  }

```
   - **`afl-fuzz-bitmap.c`** → Add the required function for bitmap processing.
```c
  u8 __attribute__((hot))
save_if_interesting_remote_feedback(afl_state_t *afl, void *mem, u32 len, u8 fault) {
  bool one = false;
  if (unlikely(len == 0)) { return 0; }

  if (unlikely(fault == FSRV_RUN_TMOUT && afl->afl_env.afl_ignore_timeouts)) {

    if (likely(afl->schedule >= FAST && afl->schedule <= RARE)) {

      u64 cksum = afl->fsrv.cksum;

      // Saturated increment
      if (likely(afl->n_fuzz[cksum % N_FUZZ_SIZE] < 0xFFFFFFFF))
        afl->n_fuzz[cksum % N_FUZZ_SIZE]++;

    }

    return 0;

  }
  u8  fn[PATH_MAX];
  u8 *queue_fn = "";
  u8  new_bits = 0, keeping = 0, res, classified = 0, is_timeout = 0,
     need_hash = 1;
  s32 fd;
  u64 cksum = 0;

  /* Update path frequency. */

  /* Generating a hash on every input is super expensive. Bad idea and should
     only be used for special schedules */
  if (likely(afl->schedule >= FAST && afl->schedule <= RARE)) {

    classified = 1;
    need_hash = 0;

    cksum = afl->fsrv.cksum;

    /* Saturated increment */
    if (likely(afl->n_fuzz[cksum % N_FUZZ_SIZE] < 0xFFFFFFFF))
      afl->n_fuzz[cksum % N_FUZZ_SIZE]++;

  }

  if (likely(fault == afl->crash_mode)) {
    /* Keep only if there are new bits in the map, add to queue for
       future fuzzing, etc. */
    if (likely(classified)) {

      new_bits = afl->fsrv.new_bits;

    } else {

      new_bits = afl->fsrv.new_bits;

      if (unlikely(new_bits)) { classified = 1; }

    }

    if (likely(!new_bits)) {

      if (unlikely(afl->crash_mode)) { ++afl->total_crashes; }
      return 0;

    }

  save_to_queue:
#ifndef SIMPLE_FILES

    queue_fn =
        alloc_printf("%s/queue/id:%06u,%s", afl->out_dir, afl->queued_items,
                     describe_op(afl, new_bits + is_timeout,
                                 NAME_MAX - strlen("id:000000,")));

#else

    queue_fn =
        alloc_printf("%s/queue/id_%06u", afl->out_dir, afl->queued_items);

#endif                                                    /* ^!SIMPLE_FILES */

    fd = open(queue_fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
    if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", queue_fn); }
    ck_write(fd, mem, len, queue_fn);
    close(fd);

    add_to_queue(afl, queue_fn, len, 0);

    if (unlikely(afl->fuzz_mode) &&
        likely(afl->switch_fuzz_mode && !afl->non_instrumented_mode)) {

      if (afl->afl_env.afl_no_ui) {

        ACTF("New coverage found, switching back to exploration mode.");

      }

      afl->fuzz_mode = 0;

    }

#ifdef INTROSPECTION

    if (afl->custom_mutators_count && afl->current_custom_fuzz) {

      LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

        if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

          const char *ptr = el->afl_custom_introspection(el->data);

          if (ptr != NULL && *ptr != 0) {

            fprintf(afl->introspection_file, "QUEUE CUSTOM %s = %s\n", ptr,
                    afl->queue_top->fname);

          }

        }

      });

    } else if (afl->mutation[0] != 0) {

      fprintf(afl->introspection_file, "QUEUE %s = %s\n", afl->mutation,
              afl->queue_top->fname);

    }

#endif

    if (new_bits == 2) {

      afl->queue_top->has_new_cov = 1;
      ++afl->queued_with_cov;

    }

    if (unlikely(need_hash && new_bits)) {

      /* due to classify counts we have to recalculate the checksum */
      afl->queue_top->exec_cksum = afl->fsrv.exec_cksum;
      need_hash = 0;

    }

    /* For AFLFast schedules we update the new queue entry */
    if (likely(cksum)) {

      afl->queue_top->n_fuzz_entry = cksum % N_FUZZ_SIZE;
      afl->n_fuzz[afl->queue_top->n_fuzz_entry] = 1;

    }

    /* Try to calibrate inline; this also calls  () when
       successful. */
    one = true;
    res = calibrate_case(afl, afl->queue_top, mem, afl->queue_cycle - 1, 0);

    if (unlikely(res == FSRV_RUN_ERROR)) {

      FATAL("Unable to execute target application");

    }

    if (likely(afl->q_testcase_max_cache_size)) {

      queue_testcase_store_mem(afl, afl->queue_top, mem);

    }

    keeping = 1;

  }

  switch (fault) {

    case FSRV_RUN_TMOUT:
      if (one) { FATAL("one is true!");}
      /* Timeouts are not very interesting, but we're still obliged to keep
         a handful of samples. We use the presence of new bits in the
         hang-specific bitmap as a signal of uniqueness. In "non-instrumented"
         mode, we just keep everything. */

      ++afl->total_tmouts;

      if (afl->saved_hangs >= KEEP_UNIQUE_HANG) { return keeping; }

      if (likely(!afl->non_instrumented_mode)) {

        if (unlikely(!classified)) {

          classified = 1;

        }


        if (!afl->fsrv.simplified_newbits) { return keeping; }

      }

      is_timeout = 0x80;
#ifdef INTROSPECTION
      if (afl->custom_mutators_count && afl->current_custom_fuzz) {

        LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

          if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

            const char *ptr = el->afl_custom_introspection(el->data);

            if (ptr != NULL && *ptr != 0) {

              fprintf(afl->introspection_file,
                      "UNIQUE_TIMEOUT CUSTOM %s = %s\n", ptr,
                      afl->queue_top->fname);

            }

          }

        });

      } else if (afl->mutation[0] != 0) {

        fprintf(afl->introspection_file, "UNIQUE_TIMEOUT %s\n", afl->mutation);

      }

#endif

      /* Before saving, we make sure that it's a genuine hang by re-running
         the target with a more generous timeout (unless the default timeout
         is already generous). */

      if (afl->fsrv.exec_tmout < afl->hang_tmout) {

        u8  new_fault;
        u32 tmp_len = write_to_testcase(afl, &mem, len, 0);

        if (likely(tmp_len)) {

          len = tmp_len;

        } else {

          len = write_to_testcase(afl, &mem, len, 1);

        }

        new_fault = fuzz_run_target(afl, &afl->fsrv, afl->hang_tmout);
        classify_counts(&afl->fsrv);

        /* A corner case that one user reported bumping into: increasing the
           timeout actually uncovers a crash. Make sure we don't discard it if
           so. */

        if (!afl->stop_soon && new_fault == FSRV_RUN_CRASH) {

          goto keep_as_crash;

        }

        if (afl->stop_soon || new_fault != FSRV_RUN_TMOUT) {

          if (afl->afl_env.afl_keep_timeouts) {

            ++afl->saved_tmouts;
            goto save_to_queue;

          } else {

            return keeping;

          }

        }

      }

#ifndef SIMPLE_FILES

      snprintf(fn, PATH_MAX, "%s/hangs/id:%06llu,%s", afl->out_dir,
               afl->saved_hangs,
               describe_op(afl, 0, NAME_MAX - strlen("id:000000,")));

#else

      snprintf(fn, PATH_MAX, "%s/hangs/id_%06llu", afl->out_dir,
               afl->saved_hangs);

#endif                                                    /* ^!SIMPLE_FILES */

      ++afl->saved_hangs;

      afl->last_hang_time = get_cur_time();

      break;

    case FSRV_RUN_CRASH:

    keep_as_crash:
      if (one) { FATAL("one is true!");}

      /* This is handled in a manner roughly similar to timeouts,
         except for slightly different limits and no need to re-run test
         cases. */

      ++afl->total_crashes;

      if (afl->saved_crashes >= KEEP_UNIQUE_CRASH) { return keeping; }

      if (likely(!afl->non_instrumented_mode)) {

        if (unlikely(!classified)) {

          classified = 1;

        }


        if (!afl->fsrv.simplified_newbits) { return keeping; }

      }

      if (unlikely(!afl->saved_crashes) &&
          (afl->afl_env.afl_no_crash_readme != 1)) {

        write_crash_readme(afl);

      }

#ifndef SIMPLE_FILES

      snprintf(fn, PATH_MAX, "%s/crashes/id:%06llu,sig:%02u,%s", afl->out_dir,
               afl->saved_crashes, afl->fsrv.last_kill_signal,
               describe_op(afl, 0, NAME_MAX - strlen("id:000000,sig:00,")));

#else

      snprintf(fn, PATH_MAX, "%s/crashes/id_%06llu_%02u", afl->out_dir,
               afl->saved_crashes, afl->fsrv.last_kill_signal);

#endif                                                    /* ^!SIMPLE_FILES */

      ++afl->saved_crashes;
#ifdef INTROSPECTION
      if (afl->custom_mutators_count && afl->current_custom_fuzz) {

        LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

          if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

            const char *ptr = el->afl_custom_introspection(el->data);

            if (ptr != NULL && *ptr != 0) {

              fprintf(afl->introspection_file, "UNIQUE_CRASH CUSTOM %s = %s\n",
                      ptr, afl->queue_top->fname);

            }

          }

        });

      } else if (afl->mutation[0] != 0) {

        fprintf(afl->introspection_file, "UNIQUE_CRASH %s\n", afl->mutation);

      }

#endif
      if (unlikely(afl->infoexec)) {

        // if the user wants to be informed on new crashes - do that
#if !TARGET_OS_IPHONE
        // we dont care if system errors, but we dont want a
        // compiler warning either
        // See
        // https://stackoverflow.com/questions/11888594/ignoring-return-values-in-c
        (void)(system(afl->infoexec) + 1);
#else
        WARNF("command execution unsupported");
#endif

      }

      afl->last_crash_time = get_cur_time();
      afl->last_crash_execs = afl->fsrv.total_execs;

      break;

    case FSRV_RUN_ERROR:
      FATAL("Unable to execute target application");

    default:
      return keeping;

  }


  /* If we're here, we apparently want to save the crash or hang
     test case, too. */

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
  if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", fn); }
  ck_write(fd, mem, len, fn);
  close(fd);

#ifdef __linux__
  if (afl->fsrv.nyx_mode && fault == FSRV_RUN_CRASH) {

    u8 fn_log[PATH_MAX];

    (void)(snprintf(fn_log, PATH_MAX, "%s.log", fn) + 1);
    fd = open(fn_log, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
    if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", fn_log); }

    u32 nyx_aux_string_len = afl->fsrv.nyx_handlers->nyx_get_aux_string(
        afl->fsrv.nyx_runner, afl->fsrv.nyx_aux_string,
        afl->fsrv.nyx_aux_string_len);

    ck_write(fd, afl->fsrv.nyx_aux_string, nyx_aux_string_len, fn_log);
    close(fd);
  }

#endif

  return keeping;

}
```

