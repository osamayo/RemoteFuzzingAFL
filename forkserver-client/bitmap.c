#include "bitmap.h"
#include "../include/afl-fuzz.h"


const u8 simplify_lookup[256] = {

    [0] = 1, [1 ... 255] = 128

};

/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */

const u8 count_class_lookup8[256] = {

    [0] = 0,
    [1] = 1,
    [2] = 2,
    [3] = 4,
    [4 ... 7] = 8,
    [8 ... 15] = 16,
    [16 ... 31] = 32,
    [32 ... 127] = 64,
    [128 ... 255] = 128

};

u16 count_class_lookup16[65536];

void init_count_class16(void) {

  u32 b1, b2;

  for (b1 = 0; b1 < 256; b1++) {

    for (b2 = 0; b2 < 256; b2++) {

      count_class_lookup16[(b1 << 8) + b2] =
          (count_class_lookup8[b1] << 8) | count_class_lookup8[b2];

    }

  }

}


#ifdef WORD_SIZE_64
  #include "../include/coverage-64.h"
#else
  #include "../include/coverage-32.h"
#endif

void simplify_trace_remote(afl_forkserver_t *fsrv, u8 *bytes) {

  u64 *mem = (u64 *)bytes;
  u32  i = (fsrv->map_size >> 3);

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u8 *mem8 = (u8 *)mem;

      mem8[0] = simplify_lookup[mem8[0]];
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];
      mem8[4] = simplify_lookup[mem8[4]];
      mem8[5] = simplify_lookup[mem8[5]];
      mem8[6] = simplify_lookup[mem8[6]];
      mem8[7] = simplify_lookup[mem8[7]];

    } else

      *mem = 0x0101010101010101ULL;

    mem++;

  }

}


u8 has_new_bits_remote(afl_forkserver_t *fsrv, u8 *virgin_map) {

#ifdef WORD_SIZE_64
  u64 *current = (u64 *)fsrv->trace_bits;
  u64 *virgin = (u64 *)virgin_map;

  u32 i = ((fsrv->real_map_size + 7) >> 3);

#else
  puts("x86");
  exit(1);

  u32 *current = (u32 *)fsrv->trace_bits;
  u32 *virgin = (u32 *)virgin_map;

  u32 i = ((fsrv->real_map_size + 3) >> 2);

#endif                                                     /* ^WORD_SIZE_64 */

  u8 ret = 0;
  while (i--) {

    if (unlikely(*current)) discover_word(&ret, current, virgin);

    current++;
    virgin++;

  }

  // if (unlikely(ret) && likely(virgin_map == afl->virgin_bits)) // TODO
  //   afl->bitmap_changed = 1;

  return ret;

}

u8 has_new_bits_unclassified_remote(afl_forkserver_t *fsrv, u8 *virgin_map) {

  /* Handle the hot path first: no new coverage */
  u8 *end = fsrv->trace_bits + fsrv->map_size;

#ifdef WORD_SIZE_64

  if (!skim((u64 *)virgin_map, (u64 *)fsrv->trace_bits, (u64 *)end))
    return 0;

#else

  if (!skim((u32 *)virgin_map, (u32 *)fsrv->trace_bits, (u32 *)end))
    return 0;

#endif                                                     /* ^WORD_SIZE_64 */
  classify_counts(fsrv);
  return has_new_bits_remote(fsrv, virgin_map);

}


void analyze_feedback(Feedback* feedback, afl_forkserver_t *fsrv, bool trim_operation, u8 schedule, u8 ignore_timeout, u8 crash_mode, u64 saved_crashes, u64 saved_hangs,  u32 len, u8 fault, u8** virgin_bits_arr, u8** virgin_crash_arr, u8** virgin_tmout_arr, u8 client) {

    if (trim_operation)
    {
        classify_counts(fsrv);
        feedback->cksum = hash64(fsrv->trace_bits, fsrv->map_size, HASH_CONST);
      return;
    }

    if (unlikely(len == 0)) { return; }


    if (unlikely(fault == FSRV_RUN_TMOUT && ignore_timeout)) {
        if (likely(schedule >= FAST && schedule <= RARE)) {
            classify_counts(fsrv);
            u64 cksum = hash64(fsrv->trace_bits, fsrv->map_size, HASH_CONST);
            feedback->cksum = cksum;
        }

        return;
    }

    u8  classified = 0, need_hash = 1;

    if (likely(schedule >= FAST && schedule <= RARE)) {
        classify_counts(fsrv);
        classified = 1;
        need_hash = 0;

        feedback->cksum = hash64(fsrv->trace_bits, fsrv->map_size, HASH_CONST);
    }

    if (likely(fault == crash_mode)) {
        if (likely(classified)) {
            feedback->new_bits = has_new_bits_remote(fsrv, *(virgin_bits_arr+client));

        } else {
            feedback->new_bits = has_new_bits_unclassified_remote(fsrv, *(virgin_bits_arr+client));

            if (unlikely(feedback->new_bits)) { classified = 1; }

        }

        if (likely(!feedback->new_bits)) {

            return;
        }


        if (unlikely(need_hash && feedback->new_bits)) {
            feedback->exec_cksum = hash64(fsrv->trace_bits, fsrv->map_size, HASH_CONST);
            need_hash = 0;
        }

    }

    switch (fault) {

        case FSRV_RUN_TMOUT:
            if (saved_hangs >= KEEP_UNIQUE_HANG) { return; }

            if (unlikely(!classified)) {

            classify_counts(fsrv);
            classified = 1;

            }

            simplify_trace_remote(fsrv, fsrv->trace_bits);

            feedback->simplified_newbits = has_new_bits_remote(fsrv, *(virgin_tmout_arr+client));
            if (!feedback->new_bits) { return; }
            break;

        case FSRV_RUN_CRASH:

            if (saved_crashes >= KEEP_UNIQUE_CRASH) { return; }


            if (unlikely(!classified)) {

            classify_counts(fsrv);
            classified = 1;

            }

            simplify_trace_remote(fsrv, fsrv->trace_bits);

            feedback->simplified_newbits = has_new_bits_remote(fsrv, *(virgin_crash_arr+client));
            if (!feedback->new_bits) { return ; }


            break;

        case FSRV_RUN_ERROR:
            FATAL("Unable to execute target application");

        default:
            return ;

    }

    return ;

}

