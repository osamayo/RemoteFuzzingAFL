# Proxy

The proxy acts as an intermediary between multiple instances of AFL++ and the target system. It opens a TCP socket to receive test cases from AFL++ instances and communicates with the embedded system via UART.

### Serial Library:
This project uses a forked serial library from:  
[https://gitlab.com/Teuniz/RS-232](https://gitlab.com/Teuniz/RS-232)

---

## Usage

```sh
proxy -l <listen-ip> -p <listen-port> -M <max-testcase-length> -N <number-of-fuzzing-instances>
```

### Parameters:
- `-l <listen-ip>` → IP address the proxy will listen on.
- `-p <listen-port>` → Port number the proxy will listen on.
- `-M <max-testcase-length>` → Maximum length of a test case.
- `-N <number-of-fuzzing-instances>` → Number of AFL++ instances connecting to the proxy.

---

## Limitations
- The proxy currently only supports UART for communication with the embedded system.
- Performance is limited by the UART protocol, which is not suitable to use with large test cases.
- To use a different communication protocol, replace the `SerialInit`, `SerialRead`, and `SerialWrite` functions with your own implementation.

---


