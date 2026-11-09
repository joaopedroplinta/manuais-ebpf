#!/usr/bin/env bash
# Rodada 7: cenarios do cap. 8 (Exemplos Praticos). Rodar com: sudo bash testes/07-exemplos-praticos.sh 2>&1 | tee testes/resultados/07-exemplos-praticos.txt
[ "$(id -u)" -eq 0 ] || { echo "rode com sudo"; exit 1; }
run() { # run SEGUNDOS comando... : roda o comando e encerra com SIGINT
  local t=$1; shift
  timeout --preserve-status -s INT "$t" "$@" 2>&1 | head -15
}

echo "== A. execsnoop: processos curtos"
( run 5 execsnoop-libbpf > /tmp/ex-a.out ) &
sleep 2; for i in 1 2 3; do date > /dev/null; sleep 0.2; done; wait
cat /tmp/ex-a.out

echo "== A2. contagem de execve por processo"
( run 5 bpftrace -e 'tracepoint:syscalls:sys_enter_execve { @[comm] = count(); }' > /tmp/ex-a2.out ) &
sleep 2; for i in 1 2 3; do date > /dev/null; done; wait
cat /tmp/ex-a2.out

echo "== B. servidor http: opensnoop -p e syscount -p"
python3 -m http.server 8080 --directory /tmp > /dev/null 2>&1 &
SRV=$!; sleep 1
( run 6 opensnoop-libbpf -p "$SRV" > /tmp/ex-b1.out ) &
( run 6 syscount-libbpf -p "$SRV" -i 5 > /tmp/ex-b2.out ) &
sleep 2; for i in 1 2 3; do curl -s http://localhost:8080/ > /dev/null; done; wait
echo "-- opensnoop"; cat /tmp/ex-b1.out
echo "-- syscount"; cat /tmp/ex-b2.out

echo "== C. tcplife -L 8080"
( run 6 tcplife-libbpf -L 8080 > /tmp/ex-c.out ) &
sleep 2; for i in $(seq 1 5); do curl -s http://localhost:8080/ > /dev/null; done; wait
cat /tmp/ex-c.out
kill "$SRV" 2>/dev/null

echo "== D. USDT: modulos importados"
P=/usr/bin/python3.14
( run 5 bpftrace -e "usdt:$P:python:import__find__load__start { printf(\"%s\\n\", str(arg0)); }" > /tmp/ex-d.out ) &
sleep 2; $P -c "import json, csv"; wait
grep -vE "warning|WARNING|HINT|^ *[0-9]+ \||\^~|include/" /tmp/ex-d.out | head -12
echo "== fim"
