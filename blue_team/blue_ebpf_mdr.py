#!/usr/bin/env python3
"""
blue_ebpf_mdr.py - eBPF Real-time Fileless Malware Detection & Response
================================================================================
MITRE ATT&CK Detection: T1620 T1059 T1095
Kill Chain              : Defense across Phases 2–6

PRINCIPLE 1 — What is eBPF?
-----------------------------
eBPF (extended Berkeley Packet Filter) is a technology that allows sandboxed
programs to run inside the Linux kernel WITHOUT modifying kernel source code
or loading kernel modules.

Key properties:
  - eBPF programs are written in a restricted C dialect
  - They are compiled to eBPF bytecode, then JIT-compiled to native machine
    code by the kernel for near-native execution speed
  - The kernel VERIFIER statically analyzes every program before loading:
      * No unbounded loops (must have provable termination)
      * No out-of-bounds memory access
      * No arbitrary pointer dereference
      * Stack size limited to 512 bytes
  - This guarantees that an eBPF program CANNOT crash or hang the kernel

Why eBPF is ideal for security monitoring:
  - Runs in kernel space → zero context-switch overhead
  - Sees ALL syscalls before they execute (tracepoints on sys_enter_*)
  - Can read process metadata (PID, UID, comm) from kernel task_struct
  - Can actively respond: bpf_send_signal() kills processes from kernel space
  - Cannot be evaded by userspace anti-debugging or rootkit techniques
    (the hook is in the kernel, not in any userspace library)

PRINCIPLE 2 — Tracepoints vs Kprobes
--------------------------------------
Linux offers two syscall instrumentation mechanisms:

  Tracepoint (sys_enter_*, sys_exit_*):
    - Static instrumentation points compiled into the kernel
    - Stable ABI across kernel versions
    - Fire at the ENTRY or EXIT of a syscall
    - sys_enter_memfd_create fires BEFORE memfd_create executes
      → we can kill the process before the fd is even created

  Kprobe (dynamic):
    - Can hook ANY kernel function at runtime
    - Less stable (function signatures change between kernel versions)
    - More flexible but more fragile

We use TRACEPOINTS because:
  1. They are stable across kernel 5.x–6.x
  2. sys_enter_* fires BEFORE the syscall → we can preemptively kill
  3. BCC provides clean TRACEPOINT_PROBE() macros

PRINCIPLE 3 — bpf_send_signal(SIGKILL)
----------------------------------------
Available since Linux 5.3.  This BPF helper sends a signal to the CURRENT
task (the process that triggered the tracepoint).

Why this is more effective than userspace kill():
  1. No userspace round-trip: the signal is delivered within the kernel,
     during the syscall entry path, BEFORE the syscall handler runs
  2. The process is killed before memfd_create/execve/socket completes
  3. There is no race condition: between detection and response, the
     process cannot execute any instructions (it's in kernel mode)
  4. Userspace kill() requires: kernel → userspace event → Python handler
     → kill() syscall → kernel delivery.  This adds milliseconds of
     latency during which the malware could complete its operation.

PRINCIPLE 4 — Detection Strategy
----------------------------------
We hook three syscall entry points and use correlation:

  Hook 1: memfd_create (syscall 319)
    WHY: memfd_create has very few legitimate uses (Chrome's IPC, some
    JIT engines).  In a server context, it's a strong fileless-malware
    indicator.  We record the PID for later correlation.

  Hook 2: execve with /proc/<pid>/fd/* path
    WHY: Normal execve targets files on disk (/usr/bin/python3).
    Executing from /proc/<pid>/fd/* means the binary lives only in
    memory (anonymous fd from memfd_create).  This is the "smoking gun"
    for fileless execution.
    HOW: We read the filename argument, check prefix "/proc/" and
    scan for substring "/fd/" within the first 20 characters.

  Hook 3: socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
    WHY: Raw ICMP sockets are used by ping(1) and network diagnostics.
    A process that ALSO called memfd_create and creates a raw ICMP
    socket is almost certainly a fileless C2 agent using ICMP as a
    covert channel.
    CORRELATION: We check memfd_pids hash map — if the current PID
    or its parent PID was recorded, we have HIGH CONFIDENCE of malware.

  Combined detection (multi-indicator):
    memfd_create alone       → HIGH severity (kill if --kill)
    execve from /proc/fd     → CRITICAL severity (kill if --kill)
    memfd + ICMP socket      → CRITICAL + CORRELATED (always kill if --kill)

Requires: Linux >= 5.3, BCC (python3-bpfcc), root

Usage:
  sudo python3 blue_ebpf_mdr.py             # monitor only
  sudo python3 blue_ebpf_mdr.py --kill       # detect + auto-kill
  sudo python3 blue_ebpf_mdr.py --kill --whitelist 1234,5678
================================================================================
"""
import os
import sys
import ctypes
import argparse
import time
import signal
import glob as _glob

# ═══════════════════════════════════════════════════════════════
#  eBPF C Program
#
#  This C code is compiled to eBPF bytecode by BCC at runtime,
#  verified by the kernel verifier, JIT-compiled to x86_64
#  machine code, and attached to kernel tracepoints.
#
#  Data flow:
#    Syscall entry → tracepoint fires → eBPF program runs →
#    → optionally sends SIGKILL → submits event to perf ring buffer →
#    → Python userspace reads event and logs it
# ═══════════════════════════════════════════════════════════════

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

/* ── event type constants ────────────────────────────────── */
#define EVT_MEMFD_CREATE   1
#define EVT_MEMFD_EXEC     2
#define EVT_ICMP_RAW_SOCK  3

/* ── event structure: passed from kernel to userspace via
      the perf ring buffer (BPF_PERF_OUTPUT) ──────────────── */
struct event_t {
    u32 pid;               /* Process ID */
    u32 ppid;              /* Parent process ID */
    u32 uid;               /* User ID */
    u8  event_type;        /* EVT_* constant */
    u8  killed;            /* 1 if bpf_send_signal(SIGKILL) was called */
    char comm[16];         /* Process name (from task_struct->comm) */
    char detail[128];      /* Context: filename, memfd name, etc. */
};

/* Perf ring buffer: kernel writes events, Python reads them.
   This is a lock-free circular buffer shared between kernel and
   userspace via mmap'd memory. */
BPF_PERF_OUTPUT(events);

/* Hash map: tracks PIDs that called memfd_create.
   Key = PID (u32), Value = timestamp (u64).
   Used for correlation with ICMP socket creation. */
BPF_HASH(memfd_pids, u32, u64);

/* Hash map: whitelisted PIDs (never killed).
   Populated from Python userspace at startup. */
BPF_HASH(whitelist, u32, u8);

/* ── helper: check if a PID is whitelisted ───────────────── */
static inline int is_whitelisted(u32 pid) {
    return whitelist.lookup(&pid) != NULL;
}

/* ── helper: populate common event fields ────────────────── */
static inline void fill_common(struct event_t *e, u8 etype) {
    /* bpf_get_current_pid_tgid() returns:
         upper 32 bits = TGID (thread group ID = process ID)
         lower 32 bits = TID (thread ID)
       We use TGID as the "PID" since we care about the process. */
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid  = bpf_get_current_uid_gid();
    e->pid        = pid_tgid >> 32;
    e->uid        = uid_gid & 0xFFFFFFFF;
    e->event_type = etype;
    e->killed     = 0;
    /* bpf_get_current_comm() reads task_struct->comm (16 bytes max) */
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* Read parent PID from task_struct->real_parent->tgid.
       bpf_get_current_task() returns a pointer to the current
       task_struct, which is the kernel's process descriptor. */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel(&e->ppid, sizeof(e->ppid),
                          &task->real_parent->tgid);
}

/* ═════════════════════════════════════════════════════════════
 *  HOOK 1: memfd_create — fileless malware staging detector
 *
 *  This tracepoint fires at the ENTRY of the memfd_create(2)
 *  syscall, BEFORE the kernel creates the anonymous fd.
 *
 *  Detection rationale:
 *    memfd_create has very few legitimate uses on servers.
 *    Common legitimate callers: Chrome (IPC), systemd, pulseaudio.
 *    In a web server context (Flask/Python), memfd_create is
 *    a strong indicator of fileless malware staging.
 *
 *  If --kill is enabled, bpf_send_signal(9) sends SIGKILL to the
 *  current process.  Because we are in sys_enter (before the syscall
 *  handler runs), the process is killed BEFORE the memfd is created.
 *  The attack chain is broken at the very first step.
 * ═════════════════════════════════════════════════════════════ */
TRACEPOINT_PROBE(syscalls, sys_enter_memfd_create) {
    struct event_t e = {};
    fill_common(&e, EVT_MEMFD_CREATE);
    if (is_whitelisted(e.pid)) return 0;

    /* Read the name argument passed to memfd_create(name, flags).
       bpf_probe_read_user_str() safely copies a userspace string
       into the eBPF stack (with bounds checking). */
    bpf_probe_read_user_str(e.detail, sizeof(e.detail), args->uname);

    /* Record this PID + timestamp for correlation with future
       ICMP socket creation (Hook 3). */
    u64 ts = bpf_ktime_get_ns();
    memfd_pids.update(&e.pid, &ts);

    __KILL_MEMFD__             /* → replaced with bpf_send_signal(9) if --kill */

    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

/* ═════════════════════════════════════════════════════════════
 *  HOOK 2: execve — detect execution from /proc/<pid>/fd/*
 *
 *  After memfd_create + fork, the child calls:
 *    execve("/usr/bin/python3", ["python3", "/proc/<pid>/fd/N"])
 *
 *  The second argument points to the memfd, and python3 reads the
 *  script from that path.  We detect this by pattern-matching the
 *  execve filename argument.
 *
 *  Detection logic:
 *    1. Check prefix: starts with "/proc/"  (6 bytes)
 *    2. Scan for "/fd/" substring at positions 6–19
 *       (PID can be 1–7 digits, so "/fd/" starts at byte 7–13)
 *    3. If both match → fileless execution detected
 *
 *  The bounded loop (i < 20) satisfies the eBPF verifier's
 *  requirement for provably terminating loops.
 * ═════════════════════════════════════════════════════════════ */
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t e = {};
    fill_common(&e, EVT_MEMFD_EXEC);
    if (is_whitelisted(e.pid)) return 0;

    char fname[128];
    bpf_probe_read_user_str(fname, sizeof(fname), args->filename);

    /* Prefix check: /proc/ = bytes 2f 70 72 6f 63 2f */
    if (fname[0] != '/' || fname[1] != 'p' || fname[2] != 'r' ||
        fname[3] != 'o' || fname[4] != 'c' || fname[5] != '/')
        return 0;

    /* Scan for "/fd/" substring.
       The path format is /proc/<PID>/fd/<N> where PID is 1-7 digits.
       So "/fd/" appears at positions 7 (1-digit PID) through 13 (7-digit).
       We scan 6..19 to cover all cases with a safety margin.
       This bounded loop (14 iterations) passes the eBPF verifier. */
    int found = 0;
    for (int i = 6; i < 20; i++) {
        if (fname[i]   == '/' && fname[i+1] == 'f' &&
            fname[i+2] == 'd' && fname[i+3] == '/') {
            found = 1;
            break;
        }
    }
    if (!found) return 0;

    __builtin_memcpy(e.detail, fname, 128);

    __KILL_EXEC__              /* → replaced with bpf_send_signal(9) if --kill */

    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

/* ═════════════════════════════════════════════════════════════
 *  HOOK 3: socket — detect raw ICMP socket creation
 *
 *  socket(AF_INET=2, SOCK_RAW=3, IPPROTO_ICMP=1)
 *
 *  Raw ICMP sockets are used by:
 *    - /bin/ping (legitimate, usually setuid)
 *    - Network monitoring tools (legitimate)
 *    - ICMP covert channels (malicious)
 *
 *  Standalone raw ICMP is only an ALERT (could be legitimate).
 *  But if the PID or its parent was seen calling memfd_create,
 *  we have a CORRELATION: fileless staging + covert C2 channel.
 *  This combination is extremely unlikely to be legitimate.
 *
 *  The memfd_pids hash map lookup is O(1) — no performance impact.
 * ═════════════════════════════════════════════════════════════ */
TRACEPOINT_PROBE(syscalls, sys_enter_socket) {
    /* Filter: only match AF_INET(2) + SOCK_RAW(3) + IPPROTO_ICMP(1) */
    if (args->family != 2 || args->type != 3 || args->protocol != 1)
        return 0;

    struct event_t e = {};
    fill_common(&e, EVT_ICMP_RAW_SOCK);
    if (is_whitelisted(e.pid)) return 0;

    /* Correlation: check if this PID or its parent called memfd_create */
    u64 *t1 = memfd_pids.lookup(&e.pid);
    u64 *t2 = memfd_pids.lookup(&e.ppid);
    if (t1 || t2) {
        /* HIGH CONFIDENCE: memfd + raw ICMP = fileless C2 agent */
        __builtin_memcpy(e.detail, "CORRELATED:memfd+icmp", 22);
        __KILL_ICMP_CORR__     /* → replaced with bpf_send_signal(9) if --kill */
    } else {
        __builtin_memcpy(e.detail, "raw_icmp_socket", 16);
    }

    events.perf_submit(args, &e, sizeof(e));
    return 0;
}
"""

# ═══════════════════════════════════════════════════════════════
#  ctypes mirror of struct event_t
#
#  This Python Structure must match the C struct layout exactly
#  (field order, sizes, alignment).  ctypes.cast() reinterprets
#  raw bytes from the perf buffer as this structure.
# ═══════════════════════════════════════════════════════════════

class Event(ctypes.Structure):
    _fields_ = [
        ('pid',        ctypes.c_uint32),
        ('ppid',       ctypes.c_uint32),
        ('uid',        ctypes.c_uint32),
        ('event_type', ctypes.c_uint8),
        ('killed',     ctypes.c_uint8),
        ('comm',       ctypes.c_char * 16),
        ('detail',     ctypes.c_char * 128),
    ]


EVENT_LABEL = {1: 'MEMFD_CREATE', 2: 'MEMFD_EXEC', 3: 'ICMP_RAW_SOCK'}
SEVERITY_FMT = {
    1: '\033[93mHIGH\033[0m',       # yellow
    2: '\033[91mCRITICAL\033[0m',    # red
    3: '\033[91mCRITICAL\033[0m',
}

# ═══════════════════════════════════════════════════════════════
#  /proc scanner — find ALREADY-RUNNING memfd processes
#
#  eBPF tracepoints only fire on NEW syscalls.  If the attacker
#  deployed the agent BEFORE the blue team started monitoring,
#  the eBPF hooks won't catch it.
#
#  This scanner checks /proc/*/exe for every running process.
#  If the exe symlink points to "memfd:*", the process is running
#  from an anonymous in-memory file — likely fileless malware.
#
#  This is the "cold start" detection complement to the "hot"
#  eBPF real-time detection.
# ═══════════════════════════════════════════════════════════════

def scan_existing_memfd():
    """Walk /proc/*/exe to find processes running from memfd."""
    found = []
    for exe in _glob.glob('/proc/[0-9]*/exe'):
        try:
            target = os.readlink(exe)
            if 'memfd:' in target:
                pid = int(exe.split('/')[2])
                try:
                    comm = open(f'/proc/{pid}/comm').read().strip()
                except OSError:
                    comm = '?'
                found.append((pid, comm, target))
        except OSError:
            continue
    return found


# ═══════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(description='Blue Team eBPF MDR Engine')
    ap.add_argument('--kill', action='store_true',
                    help='Auto-kill malicious processes via bpf_send_signal')
    ap.add_argument('--whitelist', type=str, default='',
                    help='Comma-separated PIDs to never kill')
    args = ap.parse_args()

    if os.geteuid() != 0:
        print('[!] eBPF requires root.  Run with: sudo')
        sys.exit(1)

    # Late import: bcc may not be installed on all systems
    try:
        from bcc import BPF
    except ImportError:
        print('[!] python3-bpfcc not installed.  Run:')
        print('    sudo apt-get install -y bpfcc-tools python3-bpfcc')
        sys.exit(1)

    # ── Inject kill logic based on --kill flag ───────────────
    # The eBPF C source contains placeholder strings (__KILL_*__)
    # that are replaced with either:
    #   - bpf_send_signal(9) for active response mode
    #   - empty string for monitor-only mode
    # This approach avoids maintaining two versions of the eBPF code.
    src = BPF_PROGRAM
    if args.kill:
        kill_stmt = 'e.killed = 1; bpf_send_signal(9);'
        src = src.replace('__KILL_MEMFD__',     kill_stmt)
        src = src.replace('__KILL_EXEC__',      kill_stmt)
        src = src.replace('__KILL_ICMP_CORR__', kill_stmt)
    else:
        src = src.replace('__KILL_MEMFD__',     '')
        src = src.replace('__KILL_EXEC__',      '')
        src = src.replace('__KILL_ICMP_CORR__', '')

    # ── Banner ───────────────────────────────────────────────
    print('\033[94m')
    print('+' + '=' * 52 + '+')
    print('|   Blue Team  eBPF MDR Engine  v1.0               |')
    print('|   Real-time Fileless Malware Detection            |')
    print('+' + '=' * 52 + '+')
    print('\033[0m')
    kill_str = ('\033[91mENABLED\033[0m' if args.kill
                else '\033[93mDISABLED (monitor)\033[0m')
    print(f'  Auto-kill : {kill_str}')

    # ── Scan for existing memfd processes (cold-start check) ─
    existing = scan_existing_memfd()
    if existing:
        print(f'\n  \033[91m[!] Found {len(existing)} existing '
              f'memfd process(es):\033[0m')
        for pid, comm, exe in existing:
            print(f'      PID={pid}  COMM={comm}  EXE={exe}')
            if args.kill:
                os.kill(pid, signal.SIGKILL)
                print(f'      \033[91m  -> KILLED\033[0m')
    else:
        print('  Existing  : no memfd processes found (clean)')

    # ── Load & JIT-compile eBPF program ──────────────────────
    # BCC compiles the C source to eBPF bytecode using Clang/LLVM,
    # then loads it into the kernel.  The kernel verifier checks it,
    # then the JIT compiler converts it to native x86_64 instructions.
    print('\n[*] Compiling & loading eBPF probes...')
    b = BPF(text=src)
    print('    tracepoint/syscalls/sys_enter_memfd_create  OK')
    print('    tracepoint/syscalls/sys_enter_execve        OK')
    print('    tracepoint/syscalls/sys_enter_socket         OK')

    # ── Populate whitelist from userspace ────────────────────
    # The whitelist BPF_HASH is shared between kernel and userspace.
    # We write PIDs from Python; the eBPF program reads them.
    wl = b['whitelist']
    wl_pids = set()
    if args.whitelist:
        for s in args.whitelist.split(','):
            s = s.strip()
            if s.isdigit():
                wl_pids.add(int(s))
    wl_pids.add(os.getpid())   # always whitelist our own PID
    for pid in wl_pids:
        wl[ctypes.c_uint32(pid)] = ctypes.c_uint8(1)
    print(f'  Whitelist : {sorted(wl_pids)}')

    # ── Monitoring header ────────────────────────────────────
    print('\n[*] Monitoring...  (Ctrl+C to stop)\n')
    hdr = (f"{'TIME':<10} {'EVENT':<16} {'SEVERITY':<20} "
           f"{'PID':<8} {'PPID':<8} {'UID':<6} "
           f"{'COMM':<16} {'ACT':<10} DETAIL")
    print(hdr)
    print('\u2500' * 120)

    evt_count = 0
    kill_count = 0

    def on_event(cpu, data, size):
        """Callback: invoked for each event from the perf ring buffer."""
        nonlocal evt_count, kill_count
        e = ctypes.cast(data, ctypes.POINTER(Event)).contents
        evt_count += 1

        label = EVENT_LABEL.get(e.event_type, '?')
        sev   = SEVERITY_FMT.get(e.event_type, 'LOW')
        comm  = e.comm.decode(errors='replace')
        det   = e.detail.decode(errors='replace').rstrip('\x00')
        act   = '\033[91mKILLED\033[0m' if e.killed else 'ALERT'
        ts    = time.strftime('%H:%M:%S')

        if e.killed:
            kill_count += 1

        print(f'{ts:<10} {label:<16} {sev:<20} '
              f'{e.pid:<8} {e.ppid:<8} {e.uid:<6} '
              f'{comm:<16} {act:<10} {det}')

        if e.event_type == 3 and det.startswith('CORRELATED'):
            print(f'\033[91m    \u2570\u2500\u25b6 '
                  f'CORRELATION: PID {e.pid} = memfd_create + '
                  f'raw ICMP socket \u2192 Fileless C2 confirmed!\033[0m')

    # Open perf buffer with 64 pages (256KB) — sufficient for burst events
    b['events'].open_perf_buffer(on_event, page_cnt=64)

    try:
        while True:
            # Poll with 100ms timeout — balances latency and CPU usage
            b.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        pass

    print(f'\n[*] MDR stopped.  Events={evt_count}  Kills={kill_count}')


if __name__ == '__main__':
    main()
