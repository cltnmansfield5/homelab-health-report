# Capture intermittent memory and I/O stalls

Capture a five-minute window while the slowdown is happening, preferably outside
accepted scheduled maintenance. A quiet snapshot cannot attribute a past stall.
These commands read counters and process metadata; they do not clear caches/swap,
change limits, run storage benchmarks, or perform operations on a NAS share.

Start the following in three terminals at approximately the same time. The
filenames include UTC capture-start times and do not depend on shell variables
shared between terminals. Keep normal workload running and note what was slow.

Process CPU, memory faults, I/O and context switches:

```bash
sudo env LC_ALL=C TZ=UTC S_TIME_FORMAT=ISO S_COLORS=never pidstat -d -r -u -w 5 60 | tee "$HOME/homelab-stall-pidstat-$(date -u +%Y%m%dT%H%M%SZ).txt"
```

Local block-device latency, queue depth and throughput (omit the since-boot report):

```bash
env LC_ALL=C TZ=UTC S_COLORS=never iostat -xz -y -t 5 60 | tee "$HOME/homelab-stall-iostat-$(date -u +%Y%m%dT%H%M%SZ).txt"
```

Synchronized host/container pressure, memory-limit events, blocked process wait
channels and CIFS counters. This loop requires Bash, even if the login shell is Zsh:

```bash
sudo bash <<'BASH' | tee "$HOME/homelab-stall-pressure-$(date -u +%Y%m%dT%H%M%SZ).txt"
export LC_ALL=C TZ=UTC
shopt -s nullglob
lsblk -o NAME,TYPE,SIZE,MODEL,MOUNTPOINTS
sysctl kernel.task_delayacct
for ((sample=0; sample<60; sample++)); do
  date -u +%Y-%m-%dT%H:%M:%SZ
  grep -H . /proc/sys/kernel/random/boot_id /proc/uptime /proc/pressure/memory /proc/pressure/io
  grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree|Dirty|Writeback):' /proc/meminfo
  grep -E '^(pswpin|pswpout|pgmajfault|oom_kill|allocstall.*|pgscan.*|pgsteal.*|compact_stall|compact_fail|compact_success|nr_dirty|nr_writeback) ' /proc/vmstat
  files=(/sys/fs/cgroup/system.slice/docker-*.scope/{memory.current,memory.high,memory.max,memory.swap.current,memory.swap.max,memory.events,memory.pressure,io.pressure,io.stat} /sys/fs/cgroup/user.slice/user-*.slice/{memory.current,memory.high,memory.max,memory.swap.current,memory.events,memory.pressure,io.pressure,io.stat})
  if ((${#files[@]})); then grep -H . "${files[@]}"; fi
  ps -e -o pid,ppid,stat,wchan:40,comm,cgroup:100 | awk 'NR==1 || $3 ~ /^D/'
  if [[ -r /proc/fs/cifs/Stats ]]; then cat /proc/fs/cifs/Stats; fi
  sleep 5
done
BASH
```

Before or immediately after capture, save the current container ID/name mapping:

```bash
sudo docker ps --no-trunc --format '{{.ID}} {{.Names}}' | tee "$HOME/homelab-stall-containers-$(date -u +%Y%m%dT%H%M%SZ).txt"
```

Check stderr for access errors or disappearing cgroups. The sampler currently
targets Docker's standard systemd cgroup driver and native user slices; another
driver/layout needs a different cgroup selection. Missing CIFS Stats is a coverage gap, not proof of
working NAS access. Preserve original private output; redact share names before
publishing anything. Do not put real captures in the repository or PR.

## Interpretation

- Rising per-container pressure and `memory.events` high/max counters can locate
  reclaim/limit pressure even when the host has available RAM. Compare counter
  changes during valid same-boot/container intervals, not lifetime totals.
- Rising local disk latency/queue depth together with blocked processes points
  toward local storage waits. Throughput or `%util` alone is insufficient.
- CIFS-related wait channels/counter changes during stalls with quiet local disks
  warrant checking NAS/server/network evidence. They do not by themselves prove
  which remote component failed.
- `pidstat` I/O delay can be zero when delay accounting is disabled; zero is not
  evidence of no waits. Process throughput is not a complete latency measure.
- Do not assume memory and I/O pressure peaks are the same incident. Match actual
  UTC times, boot IDs, monotonic intervals, device identities and container IDs.
  Task states and wait channels are samples and may miss short-lived waits.
  Do not derive CIFS rates across mount/session changes or counter resets.

[Kernel PSI](https://docs.kernel.org/accounting/psi.html) ·
[Cgroup memory events](https://docs.kernel.org/admin-guide/cgroup-v2.html)
