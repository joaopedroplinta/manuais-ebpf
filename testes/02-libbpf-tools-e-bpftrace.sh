#!/usr/bin/env bash
# Rodada 2: ferramentas libbpf-tools (CO-RE) e alternativas em bpftrace. Rodar com: sudo bash testes/02-libbpf-tools-e-bpftrace.sh
[ "$(id -u)" -eq 0 ] || { echo "rode com sudo"; exit 1; }
T=4
pass=0; fail=0
run() {  # run "rotulo" comando...   PASS = rc 0 ou 130 (Ctrl-C do python)
  local rot="$1"; shift
  local out; out=$(timeout --preserve-status -s INT $T "$@" 2>&1); local rc=$?
  if [ $rc -eq 0 ] || [ $rc -eq 130 ]; then echo "PASS  $rot"; pass=$((pass+1))
  else echo "FAIL  $rot (rc=$rc)"; echo "$out" | tail -6 | sed 's/^/      /'; fail=$((fail+1)); fi
}
have() { command -v "$1" >/dev/null 2>&1 || { echo "SKIP  $1 nao instalado (sudo apt install libbpf-tools)"; return 1; }; }

echo "== libbpf-tools (CO-RE)"
for t in execsnoop opensnoop biosnoop tcpconnect oomkill; do have $t-libbpf && run "$t-libbpf" $t-libbpf; done
have syscount-libbpf  && run "syscount-libbpf -i 2"     syscount-libbpf -i 2
have runqlat-libbpf   && run "runqlat-libbpf 1 2"       runqlat-libbpf 1 2
have cpudist-libbpf   && run "cpudist-libbpf 1 2"       cpudist-libbpf 1 2
have profile-libbpf   && run "profile-libbpf -F 99 2"   profile-libbpf -F 99 2
have cachestat-libbpf && run "cachestat-libbpf 1 2"     cachestat-libbpf 1 2
have biolatency-libbpf && run "biolatency-libbpf -D 2 1" biolatency-libbpf -D 2 1
have ext4slower-libbpf && run "ext4slower-libbpf 10"    ext4slower-libbpf 10
have tcplife-libbpf   && run "tcplife-libbpf -L 8080"   tcplife-libbpf -L 8080
have memleak-libbpf   && run "memleak-libbpf -p 1"      memleak-libbpf -p 1

echo "== bpftrace (alternativas)"
cat > /tmp/runqlat.bt <<'EOF'
tracepoint:sched:sched_wakeup, tracepoint:sched:sched_wakeup_new { @qtime[args->pid] = nsecs; }
tracepoint:sched:sched_switch {
    if (args->prev_state == 0) { @qtime[args->prev_pid] = nsecs; }
    $ns = @qtime[args->next_pid];
    if ($ns) { @usecs = hist((nsecs - $ns) / 1000); delete(@qtime[args->next_pid]); }
}
EOF
run "runqlat.bt" bpftrace /tmp/runqlat.bt
run "tcp_retransmit_skb" bpftrace -e 'tracepoint:tcp:tcp_retransmit_skb { printf("%s sport=%d dport=%d\n", comm, args->sport, args->dport); }'
run "oom mark_victim"    bpftrace -e 'tracepoint:oom:mark_victim { printf("OOM: PID %d\n", args->pid); }'
run "inet_sock_set_state" bpftrace -e 'tracepoint:sock:inet_sock_set_state { printf("%s %d -> %d sport=%d dport=%d\n", comm, args->oldstate, args->newstate, args->sport, args->dport); }'
cat > /tmp/tcplife.bt <<'EOF'
tracepoint:sock:inet_sock_set_state /args->newstate == 1/ { @ini[args->skaddr] = nsecs; }
tracepoint:sock:inet_sock_set_state /args->newstate == 7 && @ini[args->skaddr]/ {
    printf("%s %d -> %d duracao %d ms\n", comm, args->sport, args->dport, (nsecs - @ini[args->skaddr]) / 1000000);
    delete(@ini[args->skaddr]);
}
EOF
run "tcplife.bt" bpftrace /tmp/tcplife.bt

echo "== BCC: motivo da falha (ultimas linhas)"
for t in execsnoop-bpfcc runqlat-bpfcc; do
  echo "--- $t"; timeout --preserve-status -s INT 3 $t 2>&1 | grep -iE 'error|exception|fatal|failed' | head -5
done

echo
echo "RESUMO: $pass PASS, $fail FAIL"
