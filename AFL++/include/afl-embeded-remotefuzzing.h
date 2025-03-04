#include <stdio.h>
#include <stdlib.h>
#include "stdbool.h"



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


enum {

  /* 00 */ EXPLORE, /* AFL default, Exploration-based constant schedule */
  /* 01 */ MMOPT,   /* Modified MOPT schedule           */
  /* 02 */ EXPLOIT, /* AFL's exploitation-based const.  */
  /* 03 */ FAST,    /* Exponential schedule             */
  /* 04 */ COE,     /* Cut-Off Exponential schedule     */
  /* 05 */ LIN,     /* Linear schedule                  */
  /* 06 */ QUAD,    /* Quadratic schedule               */
  /* 07 */ RARE,    /* Rare edges                       */
  /* 08 */ SEEK,    /* EXPLORE that ignores timings     */

  POWER_SCHEDULES_NUM

};

typedef enum fsrv_run_result {

  /* 00 */ FSRV_RUN_OK = 0,
  /* 01 */ FSRV_RUN_TMOUT,
  /* 02 */ FSRV_RUN_CRASH,
  /* 03 */ FSRV_RUN_ERROR,
  /* 04 */ FSRV_RUN_NOINST,
  /* 05 */ FSRV_RUN_NOBITS,

} fsrv_run_result_t;

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
