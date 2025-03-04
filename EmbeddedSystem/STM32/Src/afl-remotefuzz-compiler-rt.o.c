/*
   american fuzzy lop++ - instrumentation bootstrap
   ------------------------------------------------

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0


*/


#include "types.h"
#include "cmplog.h"
#include "llvm-alternative-coverage.h"

#include "afl-remotefuzz-communication.h"

#define XXH_INLINE_ALL
#include "xxhash.h"
#undef XXH_INLINE_ALL

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <errno.h>


#define CTOR_PRIO 3
#define EARLY_FS_PRIO 5


// Remote fuzzing libs
#include "afl-embeded-remotefuzzing.h"
#include "main.h"

uint32_t time0 =0 ;
uint32_t time1 = 0;

/* Globals needed by the injected instrumentation. The __afl_area_initial region
   is used for instrumentation output before __afl_map_shm() has a chance to
   run. It will end up as .comm, so it shouldn't be too wasteful. */



char *strcasestr(const char *haystack, const char *needle);

static u8  __afl_area_initial[4000]; // TODO: MAP_INITIAL_SIZE
static u8 *__afl_area_ptr_dummy = __afl_area_initial;

u8        *__afl_area_ptr = __afl_area_initial;
u8        *__afl_dictionary;
u8        *__afl_fuzz_ptr;
static u32 __afl_fuzz_len_dummy;
u32       *__afl_fuzz_len = &__afl_fuzz_len_dummy;
int        __afl_sharedmem_fuzzing __attribute__((weak));

u32 __afl_final_loc;
u32 __afl_map_size = MAP_SIZE;
u32 __afl_dictionary_len;
u64 __afl_map_addr;
u32 __afl_first_final_loc;


u32 __afl_connected = 0;


// Remote fuzzing vars
FuzzingTestcase testcaseHeader = {0};
size_t halfSize = 100;
uint8_t RxData[100*2] = {0}; // double of halfSize
uint32_t testcaseSize = 0;
#undef MAX_FILE
#define MAX_FILE 3000 // Added + bytes for padding to prevent heap overflow

size_t HeaderSize =  sizeof(FuzzingTestcase);
int HTC=0;
int FTC=0;
uint32_t rxIndex=0;
int isHeaderRxed = 0;
uint32_t DMASize = 0;
bool receivingVirginBits = false;
u8 InstanceId=0;

size_t testcaseStructLen = sizeof(FuzzingTestcase);
int packetLen;
bool ready=false;
bool feedbackSent = true; // at the begining there is no need to send the feedback
bool main_fuzzer = false;
u64 total_execs=0;

u32 remote_fuzzing_mapsize;
//u8* trace_bits;
u8* testcase;
u32 testcaseLength;
u8** virgin_bits;

// vars for every testcase run
bool analyzeFeedback = false;
bool trim_operation = false;;
uint8_t schedule;
uint8_t crash_mode;





// for the __AFL_COVERAGE_ON/__AFL_COVERAGE_OFF features to work:
int        __afl_selective_coverage __attribute__((weak));
int        __afl_selective_coverage_start_off __attribute__((weak));
static int __afl_selective_coverage_temp = 1;

__thread PREV_LOC_T __afl_prev_loc[NGRAM_SIZE_MAX];
__thread PREV_LOC_T __afl_prev_caller[CTX_MAX_K];
__thread u32        __afl_prev_ctx;

struct cmp_map *__afl_cmp_map;
struct cmp_map *__afl_cmp_map_backup;


/* Running in persistent mode? */

static u8 is_persistent;

/* Are we in sancov mode? */

static u8 _is_sancov;

/* Debug? */

/*static*/ u32 __afl_debug;

/* Already initialized markers */

u32 __afl_already_initialized_shm;
u32 __afl_already_initialized_forkserver;
u32 __afl_already_initialized_first;
u32 __afl_already_initialized_second;
u32 __afl_already_initialized_early;
u32 __afl_already_initialized_init;

/* Dummy pipe for area_is_valid() */

static int __afl_dummy_fd[2] = {2, 2};


// Remote fuzzing bitmap analysis
typedef struct {
    u64 cksum;
    u64 exec_cksum;
    u8 new_bits;
    u8 simplified_newbits;
} Feedback;


u8 FuzzingInstancesCount=1;
bool DEBUG_UART=false;
void DebugWrapper(char* msg)
{
	if (DEBUG_UART)
		send_buffer(msg, strlen(msg));
}

u64 hash64(u8 *key, u32 len, u64 seed) {

  (void)seed;
  u64 ret= XXH3_64bits(key, len);
  // printf("Hash(%p: %x, %d) = %d\n", key, *key, ret);
  return ret;
}


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



#define IGNORE_SIMPLIFY_TRACE 1
#define IGNORE_CLASSIFY_COUNTS 1
#ifdef WORD_SIZE_64
  #include "coverage-64.h"
#else
  #include "coverage-32.h"
#endif


#ifdef WORD_SIZE_64
void simplify_trace_remote(u32 map_size, u8 *bytes) {

  u64 *mem = (u64 *)bytes;
  u32  i = (map_size >> 3);

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

#else
void simplify_trace_remote(u32 map_size, u8 *bytes) {

  u32 *mem = (u32 *)bytes;
  u32  i = (map_size >> 2);

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u8 *mem8 = (u8 *)mem;

      mem8[0] = simplify_lookup[mem8[0]];
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];

    } else

      *mem = 0x01010101;

    mem++;

  }
}


#endif



u8 has_new_bits_remote(u8* trace_bits, u32 real_map_size, u8 *virgin_map) {

#ifdef WORD_SIZE_64
  u64 *current = (u64 *)trace_bits;
  u64 *virgin = (u64 *)virgin_map;

  u32 i = ((real_map_size + 7) >> 3);

#else

  u32 *current = (u32 *)trace_bits;
  u32 *virgin = (u32 *)virgin_map;

  u32 i = ((real_map_size + 3) >> 2);

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


#ifdef WORD_SIZE_64
void classify_counts_remote(u8* trace_bits, u32 map_size) {

  u64 *mem = (u64 *)trace_bits;
  u32  i = (map_size >> 3);

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) { *mem = classify_word(*mem); }

    mem++;

  }

}
#else
void classify_counts_remote(u8* trace_bits, u32 map_size) {

  u32 *mem = (u32 *)trace_bits;
  u32  i = (map_size >> 2);

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) { *mem = classify_word(*mem); }

    mem++;

  }

}
#endif

u8 has_new_bits_unclassified_remote(u8* trace_bits, u32 map_size, u32 real_map_size, u8 *virgin_map) {

  /* Handle the hot path first: no new coverage */
  u8 *end = trace_bits + map_size;
puts("has_new_bits_unclassified_remote");
#ifdef WORD_SIZE_64
  if (!skim((u64 *)virgin_map, (u64 *)trace_bits, (u64 *)end))
    return 0;
#else

  if (!skim((u32 *)virgin_map, (u32 *)trace_bits, (u32 *)end))
    return 0;

#endif                                                     /* ^WORD_SIZE_64 */
puts("calling classify & has new bits");
  classify_counts_remote(trace_bits, map_size);
  return has_new_bits_remote(trace_bits, real_map_size, virgin_map);

}

void analyze_feedback(Feedback* feedback, u8* trace_bits, u32 map_size, u32 real_mapsize, bool trim_operation, u8 schedule, u8 crash_mode,  u32 len, u8 fault, u8* virgin_bits) {

    if (trim_operation)
    {
        classify_counts_remote(trace_bits, map_size);
        feedback->cksum = hash64(trace_bits, map_size, HASH_CONST);
      return;
    }

    if (unlikely(len == 0)) {return ; }



    u8  classified = 0, need_hash = 1;

    if (likely(schedule >= FAST && schedule <= RARE)) {
        classify_counts_remote(trace_bits, map_size);
        classified = 1;
        need_hash = 0;
        feedback->cksum = hash64(trace_bits, map_size, HASH_CONST);
    }

    if (likely(fault == crash_mode)) {
        if (likely(classified)) {
            feedback->new_bits = has_new_bits_remote(trace_bits, real_mapsize, virgin_bits);

        } else {
            feedback->new_bits = has_new_bits_unclassified_remote(trace_bits, map_size, real_mapsize, virgin_bits);

            if (unlikely(feedback->new_bits)) { classified = 1; }

        }

        if (likely(!feedback->new_bits)) {
            return;
        }


        if (unlikely(need_hash && feedback->new_bits)) {
            feedback->exec_cksum = hash64(trace_bits, map_size, HASH_CONST);
            need_hash = 0;
        }

    }

    return ;
}



#define default_hash(a, b) XXH3_64bits(a, b)


/* SHM setup. */

static void __afl_map_shm(void) {
  DebugWrapper("__afl_map_shm()\n");
  char msg[100]={0};
  sprintf(msg, "map_size: %lu\n", __afl_map_size);
  DebugWrapper(msg);
  // printf("map_size: %lu\n", __afl_map_size);
  if (__afl_already_initialized_shm) return;
  __afl_already_initialized_shm = 1;

  // if we are not running in afl ensure the map exists
  if (!__afl_area_ptr) { __afl_area_ptr = __afl_area_ptr_dummy; }


  if (__afl_final_loc) {
    puts("afl_map_shm final_loc");
    abort();
  } 


  if (true) {

    u32 val = 0;
    u8 *ptr;


    if (val > MAP_INITIAL_SIZE) {
      __afl_map_size = val;

    } else {
      if (__afl_first_final_loc > MAP_INITIAL_SIZE) {

        // done in second stage constructor
        __afl_map_size = __afl_first_final_loc;
      } else {

        __afl_map_size = MAP_INITIAL_SIZE;
      }

    }

    if (__afl_map_size > MAP_INITIAL_SIZE && __afl_final_loc < __afl_map_size) {
      __afl_final_loc = __afl_map_size;

    }

    if (__afl_debug) {

      fprintf(stderr, "DEBUG: (0) init map size is %u to %p\n", __afl_map_size,
              __afl_area_ptr_dummy);

    }

  }

}

/* unmap SHM. */

static void __afl_unmap_shm(void) {
DebugWrapper("shared unmap\n");
  if (!__afl_already_initialized_shm) return;


if ((!__afl_area_ptr || __afl_area_ptr == __afl_area_initial) &&

             __afl_map_addr) {

    DebugWrapper("TODO: free\n");
    // munmap((void *)__afl_map_addr, __afl_map_size);

  }

  __afl_area_ptr = __afl_area_ptr_dummy;


  __afl_already_initialized_shm = 0;

}


/* Fork server logic. */

static void __afl_start_forkserver(void) {
  DebugWrapper("afl_start_forkserver\n");
  char msg[100]={0};
  sprintf(msg, "map_size: %lu\n", __afl_map_size);
  DebugWrapper(msg);


  if (__afl_map_size % 64) {

      remote_fuzzing_mapsize = (((__afl_map_size + 63) >> 6) << 6);
  }

/*
  trace_bits = (u8*) malloc(sizeof(u8) * remote_fuzzing_mapsize);
  if (trace_bits == NULL)
  {
      exit(EXIT_FAILURE);
  }
  memset(trace_bits, 0, remote_fuzzing_mapsize);
*/

  testcase = (u8*) malloc(MAX_FILE);
  if (testcase == NULL )
  {
      exit(EXIT_FAILURE);
  }
  
  testcaseLength=0;


// Receiving number of instances
  HAL_UART_Receive(&huart2, &FuzzingInstancesCount, 1, HAL_MAX_DELAY);


  // Init virgin maps
  virgin_bits = (u8**) malloc(sizeof(u8*) * FuzzingInstancesCount);

  if (!virgin_bits)
  {
      exit(EXIT_FAILURE);
  }

  for (int i=0; i<FuzzingInstancesCount; i++)
  {
	  *(virgin_bits +i ) = (u8*) malloc(remote_fuzzing_mapsize);
      if ((*(virgin_bits+i) == NULL))
      {
          exit(EXIT_FAILURE);
      }

	  memset(*(virgin_bits+i), 255, remote_fuzzing_mapsize);
  }


  
  // sending signal with mapsize
  size_t FeedbackStructLen = sizeof(FuzzingFeedback);
  FuzzingFeedback signalFeedback = {0};
  signalFeedback.mapsize = htonlwrapper(remote_fuzzing_mapsize);
  signalFeedback.real_mapsize = htonlwrapper(__afl_map_size);
  signalFeedback.sync = true;
  if (!DEBUG_UART)
  {
 	  send_buffer(&signalFeedback, FeedbackStructLen);
  }


  DebugWrapper("Clearing __afl_area_ptr\n");
  memset(__afl_area_ptr, 0, __afl_map_size);
  __afl_area_ptr[0] = 1;
  memset(__afl_prev_loc, 0, NGRAM_SIZE_MAX * sizeof(PREV_LOC_T));

  return;


}

// UART Communication
void send_buffer(uint8_t* buffer, uint32_t len)
{
//	HAL_GPIO_TogglePin(GPIOD, GPIO_PIN_13);

	HAL_StatusTypeDef ret = HAL_UART_Transmit(&huart2, buffer, len, HAL_MAX_DELAY);
	if (ret == HAL_ERROR)
	{
//		HAL_GPIO_TogglePin(GPIOD, GPIO_PIN_13);
		HAL_GPIO_TogglePin(GPIOD, GPIO_PIN_14);

		exit(0);
	}

}

/* A simplified persistent mode handler, used as explained in
 * README.llvm.md. */

int __afl_persistent_loop( uint32_t dummy) {

	char msg[100] ={0};
  /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
  On subsequent calls, the parent will take care of that, but on the first
  iteration, it's our job to erase any trace of whatever happened
  before the loop. */

  memset(__afl_area_ptr, 0, __afl_map_size);
  __afl_area_ptr[0] = 1;
  memset(__afl_prev_loc, 0, NGRAM_SIZE_MAX * sizeof(PREV_LOC_T));

  __afl_selective_coverage_temp = 1;
  DebugWrapper("first_pass\n");


  // Enable Interrupt Handler
  memset(RxData, 0, halfSize*2);
  memset(&testcaseHeader, 0, sizeof(FuzzingTestcase));
  HAL_UART_Receive_DMA(&huart2, RxData, halfSize*2);

  while (1)
  {
	  // should we send the feedback ?
	  if (!feedbackSent)
	  {
//		  memcpy(trace_bits, __afl_area_ptr, __afl_map_size); // removed

		  DebugWrapper("Sending feedback!\n");
	      u8 ret = 0;


		  if (!analyzeFeedback)
		  {
			  DebugWrapper("Sending bitmap!\n");
			  FuzzingFeedback feedback = {0};
			  size_t FeedbackStructLen = sizeof(FuzzingFeedback);

			  feedback.fault = ret;

			  feedback.mapsize = htonlwrapper(remote_fuzzing_mapsize);
			  feedback.real_mapsize = htonlwrapper(__afl_map_size);
			  if (main_fuzzer) // main_fuzzer
			  {
				  printf("total execs: %d\n", total_execs);
				  feedback.total_execs_lower = htonlwrapper((uint32_t)total_execs);
				  feedback.total_execs_upper = htonlwrapper(total_execs >> 32);
			  }

			  send_buffer(&feedback, FeedbackStructLen);

			  send_buffer(__afl_area_ptr, remote_fuzzing_mapsize);


		  }else
		  {
			  DebugWrapper("Sending bitmap analysis!\n");

			  // remote feedback analysis
			  Feedback feedback2 = {0};

			  analyze_feedback(&feedback2, __afl_area_ptr, remote_fuzzing_mapsize, __afl_map_size, trim_operation, schedule, crash_mode, testcaseLength, ret, *(virgin_bits+InstanceId));

			  printf("Feedback: %llu | %d\n", feedback2.cksum, feedback2.new_bits);

			  FuzzingFeedback feedback = {0};
			  size_t FeedbackStructLen = sizeof(FuzzingFeedback);

			  feedback.fault = ret;

			  feedback.mapsize = 0;
			  feedback.real_mapsize = htonlwrapper(__afl_map_size);
			  feedback.cksum_lower = htonlwrapper((uint32_t)feedback2.cksum);
			  feedback.cksum_upper = htonlwrapper(feedback2.cksum >> 32);
			  u64 lower = (uint32_t)feedback2.exec_cksum;
			  feedback.exec_cksum_lower = htonlwrapper(lower);
			  u64 upper = feedback2.exec_cksum >> 32;
			  feedback.exec_cksum_upper = htonlwrapper(upper);
			  // printf("lower: %llu | upper: %llu | exec_cksum: %llu\n", lower, upper, feedback2.exec_cksum);
			  feedback.new_bits = feedback2.new_bits;
			  feedback.simplified_newbits = feedback2.simplified_newbits;
			  feedback.total_execs_lower = 0;
			  feedback.total_execs_upper = 0;
			  if (main_fuzzer)
			  {
				  feedback.total_execs_lower = htonlwrapper((uint32_t) total_execs);
				  feedback.total_execs_upper = htonlwrapper(total_execs >> 32);
//				  feedback.total_execs_lower = htonlwrapper(time0);
//				  feedback.total_execs_upper = htonlwrapper(time1);
			  }

			 send_buffer(&feedback, FeedbackStructLen);

				printf("cksum: %llu | new_bits: %d\n", feedback2.cksum, feedback2.new_bits);

		  }

		  feedbackSent = true;

	  }

//		time0 = HAL_GetTick();
	HAL_GPIO_TogglePin(GPIOD, GPIO_PIN_12);

	  while (1) {
		  HAL_GPIO_TogglePin(GPIOD, GPIO_PIN_15);

		  if (!receivingVirginBits && (rxIndex == DMASize) && ((HTC == 1 ) || (FTC == 1)))
			  break;

	  }

	  HAL_GPIO_TogglePin(GPIOD, GPIO_PIN_12);

//	  time1 = HAL_GetTick();


	  total_execs++;
	  feedbackSent = false;


	  memset(__afl_area_ptr, 0, __afl_map_size);
	  __afl_area_ptr[0] = 1;
	  memset(__afl_prev_loc, 0, NGRAM_SIZE_MAX * sizeof(PREV_LOC_T));



	  testcaseLength = testcaseSize;

		__afl_fuzz_ptr = testcase;
		*__afl_fuzz_len = testcaseLength;

	  // Calling Target Function
	  targetfunc();


	  *__afl_fuzz_len = 0;

	  // clear previous testcase
//	  memset(testcase, 0, testcaseSize); //TODO: Remove

//	  HAL_GPIO_TogglePin(GPIOD, GPIO_PIN_13);
		// Reset DMA
		HTC=0;
		FTC=0;
		isHeaderRxed = 0;
		DMASize = 1; // set to 1 to fix concurrency bug when DMASize == rxIndex in main while loop
		rxIndex=0;
		testcaseSize = 0;
		receivingVirginBits=false;
		HAL_UART_DMAStop(&huart2);
		HAL_UART_Receive_DMA(&huart2, RxData, halfSize * 2);

  }


}

void HAL_UART_RxHalfCpltCallback(UART_HandleTypeDef *huart)
{
	if (isHeaderRxed == 0)
	{
//		time0 = HAL_GetTick();
		memcpy(&testcaseHeader, RxData, HeaderSize);
		rxIndex = 0;
		isHeaderRxed = 1;
		testcaseSize = ntohlwrapper(testcaseHeader.length);


		if (testcaseSize+HeaderSize <= halfSize)
		{
			DMASize = halfSize-HeaderSize;
		} else
		{
			uint32_t dummy = (testcaseSize+HeaderSize) % halfSize;
			DMASize = testcaseSize +   (halfSize-dummy);

		}
		if (testcaseHeader.sync && testcaseHeader.update_virgin_bits)
		{

			// Reset DMA
			HTC=0;
			FTC=0;
			isHeaderRxed = 0;
			DMASize = 1; // set to 1 to fix concurrency bug when DMASize == rxIndex in main while loop
			rxIndex=0;
			testcaseSize = 0;
			receivingVirginBits=false;
			HAL_UART_DMAStop(&huart2);
			HAL_UART_Receive_DMA(&huart2, RxData, halfSize * 2);

			// send virgin_bits maps
//			DebugWrapper("sending virgin bits!\n");
			FuzzingFeedback update_res = {0};
			size_t s = sizeof(FuzzingFeedback);
			update_res.mapsize = htonlwrapper(remote_fuzzing_mapsize);
			InstanceId=testcaseHeader.instance_id;
			send_buffer(&update_res, s);


			u8* buffer = *(virgin_bits+InstanceId);

			send_buffer(buffer, remote_fuzzing_mapsize);


		}	else if (testcaseHeader.update_virgin_bits)
		{

			receivingVirginBits = true;
			InstanceId=testcaseHeader.instance_id;
			// TODO: ADD Check of bytes copied
			size_t bytesToCopy = halfSize - HeaderSize;
			memcpy((*(virgin_bits+InstanceId)), RxData+HeaderSize, bytesToCopy);
//			memset(RxData, 0, halfSize);
			rxIndex += bytesToCopy;

			// Reset DMA
			if ( receivingVirginBits && (rxIndex == DMASize))
			{
				HTC=0;
				FTC=0;
				isHeaderRxed = 0;
				DMASize = 1; // set to 1 to fix concurrency bug when DMASize == rxIndex in main while loop
				rxIndex=0;
				testcaseSize = 0;
				receivingVirginBits=false;
				HAL_UART_DMAStop(&huart2);
				HAL_UART_Receive_DMA(&huart2, RxData, halfSize * 2);

			}

		}	else
		{

			InstanceId=testcaseHeader.instance_id;


			analyzeFeedback = testcaseHeader.analyze_feedback;
			trim_operation = testcaseHeader.trim_operation;
			printf("Analyze feedback? %d\n", analyzeFeedback);
			if (analyzeFeedback)
			{
				schedule = testcaseHeader.schedule;
				crash_mode = testcaseHeader.crash_mode;
			}
			main_fuzzer = testcaseHeader.main_fuzzer;// TODO: Restore
			size_t bytesToCopy = halfSize - HeaderSize;
			memcpy(testcase, RxData+HeaderSize, bytesToCopy);
//			memset(RxData, 0, halfSize);
			rxIndex += bytesToCopy;

		}
	} else
	{
		if (!receivingVirginBits)
		{
			memcpy(testcase+rxIndex, RxData, halfSize);
//			memset(RxData, 0, halfSize);
			rxIndex += halfSize;

		} else
		{

			memcpy((*(virgin_bits+InstanceId))+rxIndex, RxData, halfSize);
//			memset(RxData, 0, halfSize);
			rxIndex += halfSize;

			// Reset DMA
			if ( receivingVirginBits && (rxIndex == DMASize))
			{
//				HAL_GPIO_TogglePin(GPIOD, GPIO_PIN_13);
				HTC=0;
				FTC=0;
				isHeaderRxed = 0;
				DMASize = 1; // set to 1 to fix concurrency bug when DMASize == rxIndex in main while loop
				rxIndex=0;
				testcaseSize = 0;
				receivingVirginBits=false;
				HAL_UART_DMAStop(&huart2);
				HAL_UART_Receive_DMA(&huart2, RxData, halfSize * 2);

			}
		}
	}

	HTC=1;
	FTC=0;
}

void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart){
	if (!receivingVirginBits)
	{

		memcpy(testcase+rxIndex, RxData+halfSize, halfSize);
//		memset(RxData+halfSize, 0, halfSize);
		rxIndex+=halfSize;
		HTC=0;
		FTC=1;

	} else
	{
		memcpy((*(virgin_bits+InstanceId))+rxIndex, RxData+halfSize, halfSize);
//		memset(RxData+halfSize, 0, halfSize);
		rxIndex+=halfSize;
		HTC=0;
		FTC=1;
		// Reset DMA
		if ( receivingVirginBits && (rxIndex == DMASize))
		{
			HTC=0;
			FTC=0;
			isHeaderRxed = 0;
			DMASize = 1; // set to 1 to fix concurrency bug when DMASize == rxIndex in main while loop
			rxIndex=0;
			testcaseSize = 0;
			receivingVirginBits=false;
			HAL_UART_DMAStop(&huart2);
			HAL_UART_Receive_DMA(&huart2, RxData, halfSize * 2);

		}
	}
}



/* This one can be called from user code when deferred forkserver mode
    is enabled. */

void __afl_manual_init(void) {
  
  static u8 init_done;

  DebugWrapper("afl_manual_init()\n");

  if (!init_done) {

    __afl_start_forkserver();
    init_done = 1;

  }

}




/* Initialization of the shmem - earliest possible because of LTO fixed mem. */

__attribute__((constructor(CTOR_PRIO))) void __afl_auto_early(void) {
	init();

	DebugWrapper("__afl_auto_early\n");

  if (__afl_already_initialized_early) return;
  __afl_already_initialized_early = 1;

  is_persistent = !!getenv(PERSIST_ENV_VAR);

  if (getenv("AFL_DISABLE_LLVM_INSTRUMENTATION")) return;

  __afl_map_shm();

}




/* Init callback. Populates instrumentation IDs. Note that we're using
   ID of 0 as a special value to indicate non-instrumented bits. That may
   still touch the bitmap, but in a fairly harmless way. */

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
  // TODO: Improve
	init();

	*start=0;
	*stop=0;
  char msg[100]={0};
  sprintf(msg, "guard_init: %p %p %d %d\n", start, stop, *start, *stop);
  DebugWrapper(msg);

  u32   inst_ratio = 100;
  char *x;

  _is_sancov = 1;

  if (!getenv("AFL_DUMP_MAP_SIZE")) {

    // __afl_auto_first();
    // __afl_auto_second();
    __afl_auto_early();

  }


  if (start == stop || *start) { return; }




  /* Make sure that the first element in the range is always set - we use that
     to avoid duplicate calls (which can happen as an artifact of the underlying
     implementation in LLVM). */

  if (__afl_final_loc < 5) __afl_final_loc = 5;  // we skip the first 5 entries

  *(start++) = ++__afl_final_loc;



  while (start < stop) {

    if (likely(inst_ratio == 100) || R(100) < inst_ratio) {

      *(start++) = ++__afl_final_loc;

    } else {

      *(start++) = 0;  // write to map[0]

    }


  }

  sprintf(msg, "__afl_final_loc: %d | __afl_map_size: %d\n", __afl_final_loc, __afl_map_size);
  DebugWrapper(msg);



  if (__afl_already_initialized_shm) {
    DebugWrapper("Already Initialized shm\n");
    if (__afl_final_loc > __afl_map_size) {
      DebugWrapper("Calling remap\n");
      if (__afl_debug) {

        fprintf(stderr, "DEBUG: Reinit shm necessary (+%u)\n",
                __afl_final_loc - __afl_map_size);

      }

      __afl_unmap_shm();
      __afl_map_shm();

    }

    __afl_map_size = __afl_final_loc + 1;
    sprintf(msg, "__afl_final_loc: %d | __afl_map_size: %d\n", __afl_final_loc, __afl_map_size);
    DebugWrapper(msg);

  }

}

///// CmpLog instrumentation


void __cmplog_ins_hook2(uint16_t arg1, uint16_t arg2, uint8_t attr) {

  if (unlikely(!__afl_cmp_map || arg1 == arg2)) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (uintptr_t)(default_hash((u8 *)&k, sizeof(uintptr_t)) & (CMP_MAP_W - 1));

  u32 hits;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
    hits = 0;
    __afl_cmp_map->headers[k].hits = 1;
    __afl_cmp_map->headers[k].shape = 1;

  } else {

    hits = __afl_cmp_map->headers[k].hits++;

    if (!__afl_cmp_map->headers[k].shape) {

      __afl_cmp_map->headers[k].shape = 1;

    }

  }

  __afl_cmp_map->headers[k].attribute = attr;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = arg1;
  __afl_cmp_map->log[k][hits].v1 = arg2;

}

void __cmplog_ins_hook4(uint32_t arg1, uint32_t arg2, uint8_t attr) {

  // fprintf(stderr, "hook4 arg0=%x arg1=%x attr=%u\n", arg1, arg2, attr);

  if (unlikely(!__afl_cmp_map || arg1 == arg2)) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (uintptr_t)(default_hash((u8 *)&k, sizeof(uintptr_t)) & (CMP_MAP_W - 1));

  u32 hits;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
    hits = 0;
    __afl_cmp_map->headers[k].hits = 1;
    __afl_cmp_map->headers[k].shape = 3;

  } else {

    hits = __afl_cmp_map->headers[k].hits++;

    if (__afl_cmp_map->headers[k].shape < 3) {

      __afl_cmp_map->headers[k].shape = 3;

    }

  }

  __afl_cmp_map->headers[k].attribute = attr;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = arg1;
  __afl_cmp_map->log[k][hits].v1 = arg2;

}

void __cmplog_ins_hook8(uint64_t arg1, uint64_t arg2, uint8_t attr) {

  // fprintf(stderr, "hook8 arg0=%lx arg1=%lx attr=%u\n", arg1, arg2, attr);

  if (unlikely(!__afl_cmp_map || arg1 == arg2)) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (uintptr_t)(default_hash((u8 *)&k, sizeof(uintptr_t)) & (CMP_MAP_W - 1));

  u32 hits;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
    hits = 0;
    __afl_cmp_map->headers[k].hits = 1;
    __afl_cmp_map->headers[k].shape = 7;

  } else {

    hits = __afl_cmp_map->headers[k].hits++;

    if (__afl_cmp_map->headers[k].shape < 7) {

      __afl_cmp_map->headers[k].shape = 7;

    }

  }

  __afl_cmp_map->headers[k].attribute = attr;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = arg1;
  __afl_cmp_map->log[k][hits].v1 = arg2;

}

#ifdef INSTRUMENTATION_WORD_SIZE_64
// support for u24 to u120 via llvm _ExitInt(). size is in bytes minus 1
void __cmplog_ins_hookN(uint128_t arg1, uint128_t arg2, uint8_t attr,
                        uint8_t size) {

  // fprintf(stderr, "hookN arg0=%llx:%llx arg1=%llx:%llx bytes=%u attr=%u\n",
  // (u64)(arg1 >> 64), (u64)arg1, (u64)(arg2 >> 64), (u64)arg2, size + 1,
  // attr);

  if (unlikely(!__afl_cmp_map || arg1 == arg2)) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (uintptr_t)(default_hash((u8 *)&k, sizeof(uintptr_t)) & (CMP_MAP_W - 1));

  u32 hits;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
    hits = 0;
    __afl_cmp_map->headers[k].hits = 1;
    __afl_cmp_map->headers[k].shape = size;

  } else {

    hits = __afl_cmp_map->headers[k].hits++;

    if (__afl_cmp_map->headers[k].shape < size) {

      __afl_cmp_map->headers[k].shape = size;

    }

  }

  __afl_cmp_map->headers[k].attribute = attr;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = (u64)arg1;
  __afl_cmp_map->log[k][hits].v1 = (u64)arg2;

  if (size > 7) {

    __afl_cmp_map->log[k][hits].v0_128 = (u64)(arg1 >> 64);
    __afl_cmp_map->log[k][hits].v1_128 = (u64)(arg2 >> 64);

  }

}

void __cmplog_ins_hook16(uint128_t arg1, uint128_t arg2, uint8_t attr) {

  if (likely(!__afl_cmp_map)) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (uintptr_t)(default_hash((u8 *)&k, sizeof(uintptr_t)) & (CMP_MAP_W - 1));

  u32 hits;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
    hits = 0;
    __afl_cmp_map->headers[k].hits = 1;
    __afl_cmp_map->headers[k].shape = 15;

  } else {

    hits = __afl_cmp_map->headers[k].hits++;

    if (__afl_cmp_map->headers[k].shape < 15) {

      __afl_cmp_map->headers[k].shape = 15;

    }

  }

  __afl_cmp_map->headers[k].attribute = attr;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = (u64)arg1;
  __afl_cmp_map->log[k][hits].v1 = (u64)arg2;
  __afl_cmp_map->log[k][hits].v0_128 = (u64)(arg1 >> 64);
  __afl_cmp_map->log[k][hits].v1_128 = (u64)(arg2 >> 64);

}

#endif

void __sanitizer_cov_trace_cmp2(uint16_t arg1, uint16_t arg2) {

  __cmplog_ins_hook2(arg1, arg2, 0);

}

void __sanitizer_cov_trace_const_cmp2(uint16_t arg1, uint16_t arg2) {

  __cmplog_ins_hook2(arg1, arg2, 0);

}

void __sanitizer_cov_trace_cmp4(uint32_t arg1, uint32_t arg2) {

  __cmplog_ins_hook4(arg1, arg2, 0);

}

void __sanitizer_cov_trace_const_cmp4(uint32_t arg1, uint32_t arg2) {

  __cmplog_ins_hook4(arg1, arg2, 0);

}

void __sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2) {

  __cmplog_ins_hook8(arg1, arg2, 0);

}

void __sanitizer_cov_trace_const_cmp8(uint64_t arg1, uint64_t arg2) {

  __cmplog_ins_hook8(arg1, arg2, 0);

}

#ifdef INSTRUMENTATION_WORD_SIZE_64
void __sanitizer_cov_trace_cmp16(uint128_t arg1, uint128_t arg2) {

  __cmplog_ins_hook16(arg1, arg2, 0);

}

void __sanitizer_cov_trace_const_cmp16(uint128_t arg1, uint128_t arg2) {

  __cmplog_ins_hook16(arg1, arg2, 0);

}

#endif

void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases) {

  if (likely(!__afl_cmp_map)) return;

  for (uint64_t i = 0; i < cases[0]; i++) {

    uintptr_t k = (uintptr_t)__builtin_return_address(0) + i;
    k = (uintptr_t)(default_hash((u8 *)&k, sizeof(uintptr_t)) &
                    (CMP_MAP_W - 1));

    u32 hits;

    if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS) {

      __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
      hits = 0;
      __afl_cmp_map->headers[k].hits = 1;
      __afl_cmp_map->headers[k].shape = 7;

    } else {

      hits = __afl_cmp_map->headers[k].hits++;

      if (__afl_cmp_map->headers[k].shape < 7) {

        __afl_cmp_map->headers[k].shape = 7;

      }

    }

    __afl_cmp_map->headers[k].attribute = 1;

    hits &= CMP_MAP_H - 1;
    __afl_cmp_map->log[k][hits].v0 = val;
    __afl_cmp_map->log[k][hits].v1 = cases[i + 2];

  }

}

__attribute__((weak)) void *__asan_region_is_poisoned(void *beg, size_t size) {

  return NULL;

}


