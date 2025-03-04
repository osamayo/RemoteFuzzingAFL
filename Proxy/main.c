
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "rs232.h"



int main()
{
  int i, n,
    cport_nr=16,        /* /dev/ttyUSB0  */
    bdrate=115200;       /* 9600 baud */

  unsigned char buf[4096];

  char mode[]={'8','N','1',0};


  if(RS232_OpenComport(cport_nr, bdrate, mode, 0))
  {
    printf("Can not open comport\n");

    return(0);
  }
  puts("Connected!");
  char command[256] = {0};
  fgets(command, 255, stdin);

  while(1)
  {
    RS232_SendBuf(cport_nr, command, sizeof(command));
    printf("sent: %s\n", command);

    while (1)
    {
        n = RS232_PollComport(cport_nr, buf, 4095);

        if(n > 0)
        {
            buf[n] = 0;   /* always put a "null" at the end of a string! */

            printf("received %i bytes: %s\n", n, (char *)buf);
            break;
        }

    }
    

    usleep(100000);  /* sleep for 100 milliSeconds */
  }

  return(0);
}

