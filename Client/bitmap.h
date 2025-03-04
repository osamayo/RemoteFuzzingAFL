
#include "../include/forkserver.h"
#include "types.h"


typedef struct {
    u64 cksum;
    u64 exec_cksum;
    u8 new_bits;
    u8 simplified_newbits;
} Feedback;

void analyze_feedback(Feedback* feedback, afl_forkserver_t *fsrv, bool trim_operation, u8 schedule, u8 ignore_timeout, u8 crash_mode, u64 saved_crashes, u64 saved_hangs,  u32 len, u8 fault, u8** virgin_bits_arr, u8** virgin_crash_arr, u8** virgin_tmout_arr, u8 client);

void init_count_class16(void) ;