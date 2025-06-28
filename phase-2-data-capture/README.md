# Phase 1 Proof of Concept

This is a simple eBPF program that traces the `write` syscall of a spawned process.

## Building and Running

1.  **Navigate to the `phase-1-poc` directory:**

    ```bash
    cd phase-1-poc
    ```

2.  **Build the eBPF program and the userspace application:**

    ```bash
    cargo build
    ```

3.  **Run the application:**

    You need to run the application with `sudo` because it loads eBPF programs into the kernel.
    Set the `RUST_LOG` environment variable to `info` to see the log output.

    ```bash
    sudo RUST_LOG=info ../target/debug/phase-1-poc
    ```

## Expected Output

You should see the "hello world" message from the child process, followed by log output similar to this:

```
[2025-06-27T19:51:24Z INFO  phase_1_poc] Child process started with PID: 288088
[2025-06-27T19:51:24Z INFO  phase_1_poc] BPF program loaded.
[2025-06-27T19:51:24Z INFO  phase_1_poc] Signatures map initialized.
[2025-06-27T19:51:24Z INFO  phase_1_poc] Child process exited with status: exit status: 0
[2025-06-27T19:51:24Z INFO  phase_1_poc] Map Entry: PID=288088, Signature=0xdeadbeef
[2025-06-27T19:51:24Z INFO  phase_1_poc] Exiting...
```

## How It Works

1.  The Rust application loads an eBPF program and attaches it to the `sys_enter_write` tracepoint.
2.  The application spawns a child process (`/bin/echo "hello world"`).
3.  The PID of this child process is sent to the eBPF program using a special-purpose eBPF map (`config_map`).
4.  The eBPF program executes every time any process on the system enters a `write` syscall. It checks the process's PID against the target PID it received from the userspace application.
5.  If the PIDs match, the eBPF program records a signature into a different eBPF map (`signatures`).
6.  The Rust application waits for the child process to complete, then reads the `signatures` map and prints any entries it finds.
