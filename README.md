# Remote Fuzzing Using AFL++

This project enhances the remote fuzzing experience by implementing a framework that supports remote feedback analysis. This approach minimizes the amount of data sent as feedback by avoiding the transmission of the full bitmap to AFL++, significantly reducing overhead. Additionally, the project supports parallel fuzzing and embedded systems.

## Project Components
The project consists of three main components:

- **Modified AFL++**: A customized version of AFL++ that enables sending test cases and receiving feedback over TCP/IP. [Read more](AFL++/README.md).
- **Proxy Program**: Acts as an intermediary between multiple AFL++ instances and the target system. [Read more](Proxy/README.md).
- **Remote Fuzzing Library**: A library to be included in firmware source code, allowing communication with the proxy and enabling in-process fuzzing. [Read more](EmbeddedSystem/README.md).

---

## Limitations
- Currently, the project supports only source-based fuzzing.
- Only UART is supported for communication with the embedded system.
- Performance is constrained by the UART protocol, which is not ideal for large test cases.
- To use a different communication protocol, refer to:
  - [Firmware Limitations](EmbeddedSystem/README.md#limitations)
  - [Proxy Limitations](Proxy/README.md#limitations)


