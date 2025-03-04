# Instrumenting STM32 Firmware Source Code

To enable communication with the proxy via UART and receive test cases, you need to add specific components to the STM32 firmware source code.

---

## Required Source and Header Files
Include the following files in the appropriate directories:

### Source Files (Place in `src` Directory):
- `afl-remotefuzz-communication.c`
- `afl-remotefuzz-compiler-rt.o.c`

### Header Files (Place in `Inc` Directory):
- `afl-embedded-remotefuzzing.h`
- `afl-remotefuzz-communication.h`
- `cmplog.h`
- `config.h`
- `coverage-32.h`
- `llvm-alternative-coverage.h`
- `types.h`
- `xxhash.h`

---

## Modifications to `main.h`
Add the following declarations:

```c
extern void targetfunc();
extern UART_HandleTypeDef huart2;
```

**Note:** `huart2` is the UART interface used in `afl-remotefuzz-compiler-rt.o.c` to communicate with the proxy.

---

## Modifications to `main.c`

### Define `targetfunc`
Modify `main.c` to declare `targetfunc` and implement the function you want to fuzz:

```c
void targetfunc()
{
    size_t len = 0;                   /* Amount of input read */
    unsigned char *buf;                /* Test case buffer pointer */
    
    buf = __afl_fuzz_ptr;
    len = *__afl_fuzz_len;
    
    if (len == 0) return;
    
    mbedtls_x509_crt crt = {0};
    unsigned char output[4096] = {0};
    
    mbedtls_x509_crt_init(&crt);
    int ret = mbedtls_x509_crt_parse(&crt, buf, len);
}
```

### Modify `main()`
In the `main()` function, initialize the UART interface and start fuzzing `targetfunc`:

```c
int main(void)
{
    init();
    __afl_manual_init();
    __afl_persistent_loop(0xdeadbeaf);
}
```

---

## Configuration Modifications Before Compilation
Due to limited memory resources in embedded systems, specify the maximum length of a test case by modifying the `MAX_FILE` declaration in `afl-remotefuzz-compiler-rt.o.c`. Ensure this matches the maximum length set in the proxy to avoid communication issues.

---

## Compilation Instructions
After including the required source and header files, instrument the modules that need fuzzing using `SanitizerCoveragePCGUARD` from AFL++.

For example, to instrument `x509` modules, use the following command:

```sh
for i in pem base64 x509 x509_crt rsa; do
    clang --target=arm-none-eabi \
          "../Middlewares/Third_Party/mbedTLS/library/$i.c" \
          -mcpu=cortex-m4 -std=gnu11 -DUSE_HAL_DRIVER -DSTM32F407xx \
          '-DMBEDTLS_CONFIG_FILE=<mbedtls_config.h>' -c \
          -I../Core/Inc -I../Drivers/STM32F4xx_HAL_Driver/Inc \
          -I../Drivers/STM32F4xx_HAL_Driver/Inc/Legacy \
          -I../Drivers/CMSIS/Device/ST/STM32F4xx/Include \
          -I../Drivers/CMSIS/Include -I../MBEDTLS/App \
          -I../Middlewares/Third_Party/mbedTLS/include/mbedtls \
          -I../Middlewares/Third_Party/mbedTLS/include \
          -ffunction-sections -fdata-sections -Wall \
          --specs=nano.specs -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb \
          -o "Middlewares/Third_Party/mbedTLS/library/$i.o" \
          --sysroot=/usr/lib/arm-none-eabi/ \
          -fpass-plugin=/home/kali/RemoteFuzzing/SanitizerCoveragePCGUARD.so 
done
```

---

## Limitations
- Currently, only UART is supported for communication with the embedded system.
- Performance is constrained by the UART protocol, which is not ideal for large test cases.
- To use a different communication protocol, modify `afl-remotefuzz-compiler-rt.o.c` as follows:
  - **Initialize communication** in the `__afl_start_forkserver` function.
  - **Modify `send_buffer` and `receive_buffer`** functions to utilize the new communication channel.

