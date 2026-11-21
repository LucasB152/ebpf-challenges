# eBPF Challenges — Kernel Tracing and Security with eBPF

> University project · *Operating Systems* (INFO0940, University of Liège) · Project 2 · C, eBPF

Five small programs that use **eBPF** to observe and control the behaviour of other processes **from inside the Linux kernel**, without modifying the kernel or the target programs. Each challenge uses a different kind of eBPF hook:

| # | Challenge | eBPF hook | What it does |
|---|---|---|---|
| 1 | [Anti-debugger](#1--anti-debugger) | uprobe | Kills a game as soon as it is run under `gdb` |
| 2 | [Protected file](#2--protected-file) | LSM (`file_open`) | Prevents a malicious process from writing to files, without killing it |
| 3 | [Ciphered writes](#3--ciphered-writes) | tracepoint (`sys_enter_write`) | Transparently applies a Caesar cipher to what a process writes to files |
| 4 | [Fork rate limiting](#4--fork-rate-limiting) | tracepoint (`sys_exit_clone`) | Kills child processes created too quickly (sliding window) |
| 5 | [Page fault frequency monitoring](#5--page-fault-frequency-monitoring) | kprobe (`handle_mm_fault`) + perf buffer | Notifies user space when a process's page fault frequency leaves a range |

Each challenge has the same structure: an eBPF program running in the kernel (`src/prog.bpf.c`), a user-space loader that configures and attaches it (`src/prog.c`), and a target program to test it.

## Requirements

- Linux with BTF enabled (`/sys/kernel/btf/vmlinux` must exist)
- `clang`, `gcc`, `libbpf`, `libelf`, `zlib` and `bpftool`
- Root privileges: every eBPF program is loaded with `sudo`

```bash
# Debian / Ubuntu
sudo apt install clang gcc libbpf-dev libelf-dev zlib1g-dev linux-tools-common linux-tools-$(uname -r)
```

Each `src/Makefile` generates `vmlinux.h` from the running kernel with `bpftool`, then builds the eBPF object and the loader.

---

## 1 — Anti-debugger

A terminal hangman game must be killed as soon as it is started from `gdb`, before the player can type a letter.

An **uprobe** is attached to the game's `make_hangman` function. When it runs, the eBPF program checks the name of the parent process. If it is `gdb`, the game is killed.

> ⚠️ The path of the hangman binary is hard-coded in the `SEC("uprobe/…")` line of `Challenge1_Antidebug/src/prog.bpf.c` (it points to the course VM). Replace it with the absolute path of your own `hangman` binary before building.

```bash
# Terminal 1: load the eBPF program
cd Challenge1_Antidebug/src && make && sudo ./prog

# Terminal 2: build and test the game
cd Challenge1_Antidebug/hangman && make
./hangman            # works normally
gdb ./hangman
(gdb) run            # the game is killed immediately
```

Opening `gdb` without running the game does not affect it.

---

## 2 — Protected file

A suspicious program called `scanner` reads a file, then overwrites it with `"You have been pwned!"`. The goal is to block all its writes **without killing it**.

The eBPF program uses **BPF LSM** (Linux Security Modules): on the `file_open` hook, it refuses to open a file for writing when the calling process is named `scanner`, and returns `-EPERM`.

> ⚠️ BPF LSM is not enabled by default on most distributions. Add `bpf` to the `lsm=` kernel boot parameter, then reboot. `cat /sys/kernel/security/lsm` must list `bpf`.

```bash
# Terminal 1
cd Challenge2_Protected_file/src && make && sudo ./prog

# Terminal 2
cd Challenge2_Protected_file/scanner && make
echo "Cool Recipe: I love cake" > recipe.txt
./scanner recipe.txt
```

Expected output with the eBPF program loaded:

```
Using provided file: recipe.txt
Read: Cool Recipe: I love cake
Error when trying to write: Operation not permitted
Read after write: Cool Recipe: I love cake
```

Without the eBPF program, `recipe.txt` contains `You have been pwned!`.

---

## 3 — Ciphered writes

Every `write()` made by a process called `echo_test` **to a file** is encrypted with a **Caesar cipher**, directly in the kernel. Only letters are shifted. Digits, punctuation and spaces are unchanged, and writes to stdout or stderr are not affected.

The shift is set with `--shift` (default: 3, applied modulo 26).

```bash
# Terminal 1
cd Challenge3_Ciphered/src && make && sudo ./prog --shift 3

# Terminal 2
cd Challenge3_Ciphered/echo_test && make && ./echo_test
cat output.txt
```

| Shift | `output.txt` |
|---|---|
| no eBPF program | `Hello123` |
| `--shift 3` | `Khoor123` |
| `--shift 10` | `Rovvy123` |

---

## 4 — Fork rate limiting

A program called `forking` creates 100 child processes in a loop. Without control, this kind of behaviour can saturate the system (fork bomb). The eBPF program applies a **sliding-window rate limit** to the children of processes named `forking`:

- A new child is **killed** if it was created less than *t* seconds after the child created *n* positions before it, among the children that survived.
- The first *n* children are always allowed.
- A killed child does not enter the window.

| Option | Meaning | Default |
|---|---|---|
| `--n_process` | Window size *n* (max 32) | 1 |
| `--time_separation_sec` | Minimum delay *t* in seconds | 1 |

```bash
# Terminal 1
cd Challenge4_Fork/src && make && sudo ./prog --n_process 1 --time_separation_sec 1

# Terminal 2
cd Challenge4_Fork/forking && make && ./forking
```

With `n = 1` and `t = 1 s`, about one child per second survives, so far fewer than 100 children are created.

---

## 5 — Page fault frequency monitoring

The eBPF program monitors the **page fault frequency** (PFF) of a process called `page_fault_gen`, and notifies user space through a **perf buffer** when it leaves the range [L, U] over a time window of *T* ms:

- `PFF too high for process with PID …` when more than U × T page faults happen in the window. Detected in the kernel, at each page fault.
- `PFF too low for process with PID …` when fewer than L × T page faults happen in the window. Detected by a timer in user space, since no event happens in the kernel when there are no page faults.

| Option | Meaning | Default |
|---|---|---|
| `--upper_bound_freq_ms` | U, in page faults per ms | 100 |
| `--lower_bound_freq_ms` | L, in page faults per ms | 10 |
| `--time_window_ms` | T, in ms (U × T must be ≤ 10,000) | 50 |

```bash
# Terminal 1 (the output is redirected because it can be very verbose)
cd Challenge5_Page_fault_frequency_monitoring/src && make
sudo ./prog --lower_bound_freq_ms 20 --upper_bound_freq_ms 100 --time_window_ms 10 > /tmp/pff_output

# Terminal 2: page faults oscillating between 10 and 110 per ms, with a period of 1 s
cd Challenge5_Page_fault_frequency_monitoring/page_fault_gen && make
./page_fault_gen 10 110 1000
```

After a few seconds, stop the eBPF program with `Ctrl+C`:

```bash
uniq /tmp/pff_output
```

```
PFF monitor: lower=20, upper=100, window=10ms
Monitoring started (filtering by process name). Press Ctrl+C to stop.
PFF too high for process with PID 35180
PFF too low for process with PID 35180
PFF too high for process with PID 35180
...
```

The messages alternate with the high and low phases of the generator.

---

## Notes

- Race conditions were out of the scope of this project.
- The hangman game used in challenge 1 is a third-party project under the MIT license (see `Challenge1_Antidebug/hangman/LICENSE`).
