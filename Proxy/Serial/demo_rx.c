
/**************************************************

file: demo_rx.c
purpose: simple demo that receives characters from
the serial port and print them on the screen,
exit the program by pressing Ctrl-C

compile with the command: gcc demo_rx.c rs232.c -Wall -Wextra -o2 -o test_rx

**************************************************/

#include <stdlib.h>
#include <stdio.h>

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

#include <stdint.h>
#include <assert.h>
#include "rs232.h"

  int i, n,
  cport_nr=16,        /* /dev/ttyUSB0  */
  bdrate=115200;       /* 9600 baud */


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


int main()
{
  unsigned char buf[4096];

  char mode[]={'8','N','1',0};


  if(RS232_OpenComport(cport_nr, bdrate, mode, 0))
  {
    printf("Can not open comport\n");

    return(0);
  }
  puts("Connected!");
  uint8_t dummy = 2; // instances count
  RS232_SendBuf(cport_nr, &dummy, 1);

  while(1)
  {
    n = RS232_PollComport(cport_nr, buf, 4095);

    if(n > 0)
    {
      buf[n] = 0;   /* always put a "null" at the end of a string! */

      printf("received %i bytes\n", n);
      puts(buf);
    }

#ifdef _WIN32
    Sleep(100);
#else
    usleep(100000);  /* sleep for 100 milliSeconds */
#endif

    // sleep(20);
    // puts("Start reading");
    // int ret=0;
    // char msg[100] = {0};

    // for (int i=0; i<1000; i++)
    // {
    //   sprintf(msg, "hello, world: %05d", i); // expected result

    //   memset(buf, 0, sizeof(buf));

    //   ret=SerialRead(buf, 19);
    //   if (ret!= 19)
    //   {
    //     printf("recieved %d: %s\n", i, buf);
    //   }
    //   if (strcmp(msg, buf) != 0)
    //   {
    //     printf("expected: %s | recieved: %s\n", msg, buf);
    //     break;
    //   }
    //   printf("%d: %s\n", i, buf);

  }

  return 0;
}

