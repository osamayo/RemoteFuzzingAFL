
/**************************************************

file: demo_tx.c
purpose: simple demo that transmits characters to
the serial port and print them on the screen,
exit the program by pressing Ctrl-C

compile with the command: gcc demo_tx.c rs232.c -Wall -Wextra -o2 -o test_tx

**************************************************/

#include <stdlib.h>
#include <stdio.h>

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

#include <stdint.h>
#include "rs232.h"

#include <stdbool.h>

  int i=0,
      cport_nr=16,        /* /dev/ttyS0 (COM1 on windows) */
      bdrate=115200;       /* 9600 baud */

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


size_t SerialRead(uint8_t* OutBuffer, uint32_t len)
{
      int ret=0;
      int recievedLen=0;

      while (recievedLen < len && (ret = RS232_PollComport(cport_nr, OutBuffer + recievedLen, len - recievedLen))>=0 ) // TODO: Improve >0
      {
          recievedLen += ret;
          //printf("Recieved: %d | len: %d | ret: %d\n", recievedLen, len, ret);
      }    

      return recievedLen;
    
        // return RS232_PollComport(cport_nr, OutBuffer, len);

}


size_t SerialWrite(uint8_t* buffer, uint32_t len)
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


    //    return RS232_SendBuf(cport_nr, buffer, len);

}
int main()
{

  char mode[]={'8','N','1',0},
       str[2][512];


  strcpy(str[0], "foo!!!");

  strcpy(str[1], "Happy serial programming!\n");

  if(RS232_OpenComport(cport_nr, bdrate, mode, 0))
  {
    printf("Can not open comport\n");

    return(0);
  }

  puts("Connected!");
//   while(1)
//   {
//     RS232_cputs(cport_nr, str[i]);

//     printf("sent: %s\n", str[i]);

// #ifdef _WIN32
//     Sleep(1000);
// #else
//     usleep(1000000);  /* sleep for 1 Second */
// #endif

//     i++;

//     i %= 2;
//   }

  char testcase[2000] = {0};
  memset(testcase, 0, sizeof(testcase));
  FILE* f = fopen("crash.bin", "rb");
  fseek(f, 0L, SEEK_END);
  size_t fileLen = ftell(f);
  fseek(f, 0L, SEEK_SET);
  int ret = fread(testcase, 1, fileLen, f);
  printf("ret: %d | len: %d\n", ret, fileLen);
  FuzzingTestcase testcaseHeader = {0};
  printf("FuzzingTestcase: %d\n", sizeof(FuzzingTestcase));
  testcaseHeader.length = htonl(fileLen);
  SerialWrite(&testcaseHeader, sizeof(FuzzingTestcase));
  sleep(2);
  SerialWrite(testcase, fileLen);

  // char msg[100] = {0};
  // char buf[33] = {0};
  // for (int i=0; i<999; i++)
  // {

  //   // sprintf(msg, "hello, world: %05dAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", i);
  //   sprintf(msg, "hello, world: %05dAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", i);
    
  //   puts(msg);
  //   testcase.length = htonl(strlen(msg));
  //   char chunk[96] = {0};
  //   memset(chunk, 0, 96);
  //   memcpy(chunk, msg, strlen(msg));
  //   SerialWrite(&testcase, sizeof(FuzzingTestcase));
  //   SerialWrite(chunk, 96);
  //   SerialRead(buf, 32);
  //   printf("Received: %s\n", buf);
  //   memset(buf, 0, 32);
  // }
  // sprintf(msg, "hello, world: %05dAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", 999);
  // puts(msg);
  // testcase.length = htonl(strlen(msg));
  // char chunk[96] = {0};
  // memset(chunk, 0, 96);
  // memcpy(chunk, msg, 96);
  // SerialWrite(&testcase, sizeof(FuzzingTestcase));
  // SerialWrite(chunk, 96);

  //usleep(200000);
  sleep(5);
  char buf[4095] = {0};
  int n=0;
  while(1)
  {
    n = RS232_PollComport(cport_nr, buf, 4095);

    if(n > 0)
    {
      buf[n] = 0;   /* always put a "null" at the end of a string! */

      printf("received %i bytes\n", n);
      puts(buf);
    }
  }
  return(0);
}

