#include <stdint.h>

int start_server();
uint32_t recieve_buffer(int sock, uint8_t* buffer, uint32_t len);
uint32_t send_buffer(int sock, uint8_t* buffer, uint32_t len);

uint32_t htonlwrapper(uint32_t x);


uint32_t ntohlwrapper(uint32_t x);

void DebugWrapper(char*);