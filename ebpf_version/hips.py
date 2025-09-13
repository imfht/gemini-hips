#!/usr/bin/python3
import fnmatch
import os
import sys
import signal
import json
import hashlib
import ctypes
import datetime
from bcc import BPF

CONFIG_FILE = "/root/hids_demo/config.json"
LOG_FILE = "/root/hids_demo/hips.log.json"

# Final BPF program using an enter/exit probe correlation for 100% cmdline accuracy.
bpf_text_template = """
#include <linux/sched.h>
#include <linux/limits.h>
#include <linux/signal.h>

typedef char path_t[NAME_MAX];

// Map to pass data from enter probe to exit probe
BPF_HASH(exec_data_map, u32, path_t);

// Map for kernel-side fast-path allowlist
BPF_HASH(kernel_allowlist_map, path_t, u32);

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char filename[NAME_MAX];
};

BPF_PERF_OUTPUT(events);

// 1. ENTER probe: quickly records the filename associated with a PID.
TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    path_t filename = {};
    bpf_probe_read_user_str(&filename, sizeof(filename), (void *)args->filename);
    exec_data_map.update(&pid, &filename);
    return 0;
}

// 2. EXIT probe: fires after execve is complete and /proc is stable.
TRACEPOINT_PROBE(syscalls, sys_exit_execve)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    path_t* filename_ptr = exec_data_map.lookup(&pid);

    if (filename_ptr == 0) {
        return 0; // This exec was not tracked.
    }

    // Check against kernel allowlist first for performance.
    if (kernel_allowlist_map.lookup(filename_ptr) != NULL) {
        exec_data_map.delete(&pid); // Cleanup and exit
        return 0;
    }

    // Not on the fast-path, prepare to send to userspace for full inspection.
    struct data_t data = {};
    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_kernel(&data.filename, sizeof(data.filename), filename_ptr);

    events.perf_submit(args, &data, sizeof(data));

    // __SIGSTOP_PLACEHOLDER__

    exec_data_map.delete(&pid); // Always cleanup the map entry
    return 0;
}
"""

def log_event(data):
    """Appends a JSON log entry to the log file."""
    data['timestamp'] = datetime.datetime.utcnow().isoformat() + 'Z'
    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(data) + '\n')

# --- Helper functions ---
def get_process_info(pid, key):
    try:
        with open(f"/proc/{pid}/{key}", "r") as f:
            if key == 'cmdline': return f.read().replace('\x00', ' ').strip()
            return f.read().strip()
    except FileNotFoundError: return None

def get_ppid(pid):
    status = get_process_info(pid, 'status')
    if status:
        for line in status.split('\n'):
            if line.startswith('PPid:'): return int(line.split()[1])
    return None

def get_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
    except: return None

def check_rule(rule, details):
    for key, pattern in rule.items():
        if key == 'comment': continue
        detail_value = details.get(key)
        if detail_value is None or not fnmatch.fnmatch(detail_value, pattern):
            return False
    return True

def main():
    # --- Mode Selection via argv ---
    mode = 'secure' # Default mode
    if len(sys.argv) > 1 and sys.argv[1] == '--functional':
        mode = 'functional'
    
    bpf_text = bpf_text_template
    if mode == 'secure':
        bpf_text = bpf_text.replace('// __SIGSTOP_PLACEHOLDER__', 'bpf_send_signal(SIGSTOP);')

    try:
        with open(CONFIG_FILE, 'r') as f: config = json.load(f)
        kernel_allowlist = config.get('kernel_allowlist', [])
        allowlist = config.get('allowlist', [])
        blocklist = config.get('blocklist', [])
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading config file {CONFIG_FILE}: {e}. Exiting."); return

    print(f"HIPS starting in '{mode.upper()}' mode (Logging to hips.log.json)...")

    try:
        b = BPF(text=bpf_text)
        kernel_map = b["kernel_allowlist_map"]
        
        value = ctypes.c_uint32(1)
        NAME_MAX = 255
        for path in kernel_allowlist:
            key = ctypes.create_string_buffer(path.encode('utf-8'), NAME_MAX)
            kernel_map[key] = value

        print(f"Loaded {len(kernel_allowlist)} paths into kernel fast-path allowlist.")
    except Exception as e:
        print(f"Error loading BPF: {e}. Make sure you are root and have kernel headers."); return

    def process_event(cpu, data, size):
        event = b["events"].event(data)
        try: filename = event.filename.decode('utf-8')
        except: return
        if not filename: return

        details = {
            'pid': event.pid,
            'comm': event.comm.decode('utf-8', 'replace'),
            'filename': filename,
            'cmdline': get_process_info(event.pid, 'cmdline'),
            'filehash': get_file_hash(filename),
        }
        ppid = get_ppid(event.pid)
        if ppid: details['ppid'] = ppid; details['ppcmdline'] = get_process_info(ppid, 'cmdline')

        log_entry = {"event_type": "process_inspect", "mode": mode, **details}
        log_event(log_entry)

        try:
            for rule in allowlist:
                if check_rule(rule, details):
                    log_event({"event_type": "action", "pid": event.pid, "action": "allowed", "reason": "allowlist", "rule": rule})
                    if mode == 'secure': os.kill(event.pid, signal.SIGCONT)
                    return
            for rule in blocklist:
                if check_rule(rule, details):
                    log_event({"event_type": "action", "pid": event.pid, "action": "blocked", "reason": "blocklist", "rule": rule})
                    os.kill(event.pid, signal.SIGKILL); return
            
            log_event({"event_type": "action", "pid": event.pid, "action": "allowed", "reason": "implicit_allow"})
            if mode == 'secure': os.kill(event.pid, signal.SIGCONT)

        except ProcessLookupError:
            log_event({"event_type": "action", "pid": event.pid, "action": "error", "error": "Process disappeared before decision"})
        except Exception as e:
            log_event({"event_type": "action", "pid": event.pid, "action": "error", "error": str(e)})
            try: os.kill(event.pid, signal.SIGKILL)
            except: pass

    b["events"].open_perf_buffer(process_event)
    print("\nMonitoring for process creation...")
    while True:
        try: b.perf_buffer_poll()
        except KeyboardInterrupt: print("\nShutting down."); exit()

if __name__ == "__main__":
    main()
