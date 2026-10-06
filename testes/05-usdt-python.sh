#!/usr/bin/env bash
# Rodada 5: sondas USDT que existem no python3.14 do Ubuntu. Rodar com: sudo bash testes/05-usdt-python.sh
[ "$(id -u)" -eq 0 ] || { echo "rode com sudo"; exit 1; }
P=/usr/bin/python3.14
echo "== sondas disponiveis"
bpftrace -l "usdt:$P:*" 2>&1 | sed "s#usdt:$P:##"

echo "== A. modulos importados (import__find__load__start)"
( timeout --preserve-status -s INT 5 bpftrace -e "usdt:$P:python:import__find__load__start { printf(\"%s\\n\", str(arg0)); }" > /tmp/usdt-a.out 2>&1 ) &
sleep 2
$P -c "import json, decimal, sqlite3"
wait
head -12 /tmp/usdt-a.out

echo "== B. pausa do coletor de lixo (gc__start/gc__done)"
cat > /tmp/gc.bt <<EOF
usdt:$P:python:gc__start { @ini[tid] = nsecs; }
usdt:$P:python:gc__done /@ini[tid]/ {
    @us = hist((nsecs - @ini[tid]) / 1000);
    delete(@ini[tid]);
}
EOF
( timeout --preserve-status -s INT 6 bpftrace /tmp/gc.bt > /tmp/usdt-b.out 2>&1 ) &
sleep 2
$P -c "
import gc
dados = [[i] * 10 for i in range(200000)]
for _ in range(50): gc.collect()
"
wait
cat /tmp/usdt-b.out | head -20
echo "== fim"
