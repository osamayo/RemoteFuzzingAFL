#include "afl-remotefuzz-communication.h"

#ifdef SOCK_COMMUNICATION
#include <stdlib.h>
#include <stdio.h>
#include "types.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
// Remote fuzzing methods



int start_server()
{
int serversock=0;
int remoteClientStructLen=0;

  struct sockaddr_in fuzzingServerAddr = {0};
  struct sockaddr_in remoteClient = {0} ;
  int remoteClientFd=0;
  char* ip = "127.0.0.1";
  uint32_t port = 4444;
  
  printf("Starting server: %s %d!\n", ip, port);
  int opt=1;
  serversock = socket(AF_INET, SOCK_STREAM, 0);
  if (serversock == -1)
  {
      perror("socket creation failed!\n");
      exit(1);
  }

  fuzzingServerAddr.sin_family = AF_INET;
  fuzzingServerAddr.sin_port = htons(port);
  fuzzingServerAddr.sin_addr.s_addr = inet_addr(ip);

  if (setsockopt(serversock, SOL_SOCKET,
                  SO_REUSEADDR | SO_REUSEPORT, &opt,
                  sizeof(opt))) {
      perror("setsockopt\n");
      exit(EXIT_FAILURE);
  }

  if ((bind(serversock, &fuzzingServerAddr, sizeof(fuzzingServerAddr)))!=0)
  {
      perror("socket bind failed!\n");
      exit(EXIT_FAILURE);
  }

  if ((listen(serversock, 4))!=0) {
      perror("listen failed!\n");
      exit(EXIT_FAILURE);
  }

  puts("Listening!");
  if ((remoteClientFd  = accept(serversock, &remoteClient, &remoteClientStructLen)) < 0 ) {
      perror("Accept client failed!\n");
      exit(EXIT_FAILURE);
  }
  puts("Successfully connected!");
  return remoteClientFd;
}

uint32_t recieve_buffer(int sock, u8* buffer, u32 len)
{
  int ret;
    int recievedLen=0;

    while (recievedLen < len && (ret = recv(sock, buffer + recievedLen, len - recievedLen, 0)) > 0)
        recievedLen += ret;

    return recievedLen;
}

uint32_t send_buffer(int sock, u8* buffer, u32 len)
{
    int bytes_sent = 0;
    while (len > 0)
    {
        bytes_sent = send(sock, buffer, len, 0);
        if (bytes_sent == -1)
        {
            printf("Error: %d %d %d\n", sock, len, bytes_sent);
            return -1;
        }

        buffer += bytes_sent;
        len -= bytes_sent;
    }
    return bytes_sent;
}

uint32_t htonlwrapper(uint32_t hostlong)
{
  return htonl(hostlong);
}


uint32_t ntohlwrapper(uint32_t netlong)
{
  return ntohl(netlong);
}

void DebugWrapper(char* msg)
{
    puts(msg);
}
#else
int start_server()
{
  // unused, already initialized in firmware
  return 0;
}


uint32_t recieve_buffer(int sock, uint8_t* buffer, uint32_t len)
{
    return recieve_buffer_uart(buffer, len);
}

uint32_t send_buffer(int sock, uint8_t* buffer, uint32_t len)
{
    return send_buffer_uart(buffer, len);
}

void DebugWrapper(char* msg)
{
    send_buffer_uart(msg, strlen(msg));
}
uint32_t htonlwrapper(uint32_t x)
{
	return	((x << 24) & 0xff000000 ) |
		((x <<  8) & 0x00ff0000 ) |
		((x >>  8) & 0x0000ff00 ) |
		((x >> 24) & 0x000000ff );
}


uint32_t ntohlwrapper(uint32_t x)
{
	return	((x << 24) & 0xff000000 ) |
		((x <<  8) & 0x00ff0000 ) |
		((x >>  8) & 0x0000ff00 ) |
		((x >> 24) & 0x000000ff );
}
#endif


