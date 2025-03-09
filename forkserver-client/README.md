# Forkserver Client

Forkserver Client is a TCP server that receives test cases from fuzzing instances, executes the target program using AFL's forkserver, and returns bitmap analysis results. This facilitates efficient fuzzing by leveraging AFL's forkserver mechanism for fast target execution.

---

## Features
- Acts as an intermediary between fuzzing instances and the target program.
- Uses AFL forkserver for optimized execution speed.
- Processes test cases and returns bitmap analysis as feedback to reduce the amount of data sent as feedback..
- Supports multiple fuzzing instances simultaneously.

---

## Usage

```sh
Usage: forkserver-client -c <LISTEN-IP> -p <LISTEN-PORT> -N <Number of Fuzzing Instances> -- /path/to/fuzzed_app [ ... ]
```

### Parameters:
- `-c <LISTEN-IP>`: The IP address where the server listens for connections.
- `-p <LISTEN-PORT>`: The port on which the server listens.
- `-N <Number of Fuzzing Instances>`: Number of concurrent fuzzing instances.
- `-- /path/to/fuzzed_app [ ... ]`: The target application to be fuzzed, along with its optional arguments.

---

