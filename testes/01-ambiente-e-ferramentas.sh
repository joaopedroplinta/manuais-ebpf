#!/usr/bin/env bash
# Testa os comandos eBPF dos capitulos 2 a 7 do Manual 1. Rodar com: sudo bash testes/01-ambiente-e-ferramentas.sh
# Cada comando roda por ate 4 s e e encerrado com SIGINT; PASS = saiu com codigo 0.
[ "$(id -u)" -eq 0 ] || { echo "rode com sudo"; exit 1; }
T=4
pass=0; fail=0
run() {  # run "rotulo" comando...
  local rot="$1"; shift
  local out; out=$(timeout --preserve-status -s INT $T "$@" 2>&1); local rc=$?
  if [ $rc -eq 0 ]; then echo "PASS  $rot"; pass=$((pass+1))
  else echo "FAIL  $rot (rc=$rc)"; echo "$out" | head -4 | sed 's/^/      /'; fail=$((fail+1)); fi
}
have() { command -v "$1" >/dev/null 2>&1 || { echo "SKIP  $1 nao instalado (apt: bpfcc-tools)"; return 1; }; }

echo "== cap. 2: ambiente"
run "bpftool prog show" bpftool prog show
run "bpftrace openat" bpftrace -e 'tracepoint:syscalls:sys_enter_openat { @[comm] = count(); }'

echo "== cap. 4: monitoramento (bpftrace)"
run "execve"      bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("%-6d %-16s -> %s\n", pid, comm, str(args->filename)); }'
run "raw_syscalls" bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'
run "profile hz"  bpftrace -e 'profile:hz:99 { @[comm] = count(); }'
run "mm_page_alloc" bpftrace -e 'tracepoint:kmem:mm_page_alloc { @[comm] = count(); }'
cat > /tmp/biolat.bt <<'EOF'
tracepoint:block:block_rq_issue { @inicio[args->dev, args->sector] = nsecs; }
tracepoint:block:block_rq_complete /@inicio[args->dev, args->sector]/ {
    @us = hist((nsecs - @inicio[args->dev, args->sector]) / 1000);
    delete(@inicio[args->dev, args->sector]);
}
EOF
run "biolat.bt"   bpftrace /tmp/biolat.bt

echo "== cap. 4: monitoramento (BCC)"
for t in execsnoop opensnoop biosnoop tcpconnect tcpretrans oomkill; do have $t-bpfcc && run "$t-bpfcc" $t-bpfcc; done
have syscount-bpfcc  && run "syscount-bpfcc -i 2" syscount-bpfcc -i 2
have runqlat-bpfcc   && run "runqlat-bpfcc 1 2"   runqlat-bpfcc 1 2
have cpudist-bpfcc   && run "cpudist-bpfcc 1 2"   cpudist-bpfcc 1 2
have profile-bpfcc   && run "profile-bpfcc -F 99 2" profile-bpfcc -F 99 2
have cachestat-bpfcc && run "cachestat-bpfcc 1 2" cachestat-bpfcc 1 2
have biolatency-bpfcc && run "biolatency-bpfcc -D 2 1" biolatency-bpfcc -D 2 1
have ext4slower-bpfcc && run "ext4slower-bpfcc 10" ext4slower-bpfcc 10
have tcplife-bpfcc   && run "tcplife-bpfcc -L 8080" tcplife-bpfcc -L 8080

echo "== cap. 5 e 6: bpftrace"
run "listar openat"  bpftrace -l 'tracepoint:syscalls:*openat*'
run "args openat"    bpftrace -lv tracepoint:syscalls:sys_enter_openat
run "tcp_sendmsg sum" bpftrace -e 'kprobe:tcp_sendmsg { @bytes[comm] = sum(arg2); } interval:s:1 { print(@bytes); clear(@bytes); }'
run "kprobe tcp_*"   bpftrace -l 'kprobe:tcp_*'
run "vfs_read latencia" bpftrace -e 'kprobe:vfs_read { @inicio[tid] = nsecs; } kretprobe:vfs_read /@inicio[tid]/ { @us = hist((nsecs - @inicio[tid]) / 1000); delete(@inicio[tid]); }'
run "sched tracepoints" bpftrace -l 'tracepoint:sched:*'
run "block_rq_issue args" bpftrace -lv tracepoint:block:block_rq_issue
run "sched_process_exec" bpftrace -e 'tracepoint:sched:sched_process_exec { printf("%s\n", str(args->filename)); }'
run "uretprobe bash readline" bpftrace -e 'uretprobe:/bin/bash:readline { printf("%s\n", str(retval)); }'
run "profile kstack" bpftrace -e 'profile:hz:99 { @[kstack] = count(); }'
run "page-faults"    bpftrace -e 'software:page-faults:1 { @[comm] = count(); }'

echo "== cap. 5: BCC em Python"
if python3 -c 'import bcc' 2>/dev/null; then
cat > /tmp/hello.py <<'EOF'
from bcc import BPF
programa = """
int hello(void *ctx) {
    bpf_trace_printk("openat\\n");
    return 0;
}
"""
b = BPF(text=programa)
b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="hello")
b.trace_print()
EOF
  run "hello.py (BCC)" python3 /tmp/hello.py
else echo "SKIP  modulo python bcc nao instalado (apt: python3-bpfcc)"; fi

echo
echo "RESUMO: $pass PASS, $fail FAIL"
