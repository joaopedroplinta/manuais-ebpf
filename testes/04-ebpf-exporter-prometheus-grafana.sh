#!/usr/bin/env bash
# Rodada 4: apt em ambiente limpo (docker), saida do bpftrace, USDT (python3.14), ebpf_exporter, Prometheus e Grafana.
# Rodar com: sudo bash testes/04-ebpf-exporter-prometheus-grafana.sh   (precisa de internet e docker; leva alguns minutos)
[ "$(id -u)" -eq 0 ] || { echo "rode com sudo"; exit 1; }
command -v docker >/dev/null || { echo "FALTA docker"; exit 1; }
W=/tmp/ebpf-teste4; rm -rf $W; mkdir -p $W; cd $W
EE_VER=v2.5.1; PROM_VER=3.15.0
PIDS=""
cleanup() {
  kill $PIDS 2>/dev/null
  docker rm -f grafana-teste >/dev/null 2>&1
  rm -f $W/io.bin
}
trap cleanup EXIT
pyjson() { python3 -c "import sys,json; d=json.load(sys.stdin); $1"; }

echo "== 1. apt em ambiente limpo (ubuntu:26.04 em contêiner)"
docker run --rm ubuntu:26.04 bash -c '
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null 2>&1
  apt-get install -y -qq clang llvm libbpf-dev libelf-dev \
      linux-tools-$(uname -r) linux-headers-$(uname -r) \
      bpftrace libbpf-tools python3 python3-pip >/tmp/apt.log 2>&1 \
    && echo "apt: OK" || { echo "apt: FALHOU"; tail -8 /tmp/apt.log; }
  for c in clang bpftool bpftrace execsnoop-libbpf python3; do
    printf "  %-18s " $c; command -v $c || echo "NAO ENCONTRADO"
  done
  bpftool version 2>&1 | head -1
' 2>&1 | tail -15

echo "== 2. saida de exemplo do bpftrace (cap. 2)"
timeout --preserve-status -s INT 3 bpftrace -e 'tracepoint:syscalls:sys_enter_openat { @[comm] = count(); }' 2>&1 | tail -8

echo "== 3. USDT no python3.14 (cap. 6)"
bpftrace -l 'usdt:/usr/bin/python3.14:*' 2>&1 | head -6
( timeout --preserve-status -s INT 6 bpftrace -e 'usdt:/usr/bin/python3.14:python:function__entry { @[str(arg1)] = count(); }' > $W/usdt.out 2>&1 ) &
BP=$!
sleep 2
python3.14 -c "import json
for i in range(20000): json.dumps({'a': i})"
wait $BP
echo "--- top funcoes Python (trecho):"; sort -t: -k2 -nr $W/usdt.out | head -6

echo "== 4. ebpf_exporter (cap. 5)"
mkdir -p ee && cd ee
curl -sL -o ee.tar.gz https://github.com/cloudflare/ebpf_exporter/releases/download/$EE_VER/ebpf_exporter_with_examples.x86_64.tar.gz
tar xzf ee.tar.gz && ls | head -8
EXBIN=$(find . -name ebpf_exporter -type f | head -1); EXDIR=$(dirname $EXBIN)
echo "binario: $EXBIN"
( cd $EXDIR && ./ebpf_exporter --config.dir=examples --config.names=timers,biolatency > $W/ee.log 2>&1 ) & PIDS="$PIDS $!"
sleep 5
echo "--- metricas em :9435 (trecho):"
curl -s http://localhost:9435/metrics | grep -E '^ebpf_exporter_timer_starts_total' | head -4
echo "--- log do exporter:"; head -5 $W/ee.log
cd $W

echo "== 5. Prometheus (cap. 7)"
curl -sL -o prom.tar.gz https://github.com/prometheus/prometheus/releases/download/v$PROM_VER/prometheus-$PROM_VER.linux-amd64.tar.gz
tar xzf prom.tar.gz
cat > prom.yml <<'EOF'
scrape_configs:
  - job_name: ebpf
    scrape_interval: 5s
    static_configs:
      - targets: ['localhost:9435']
EOF
./prometheus-$PROM_VER.linux-amd64/prometheus --config.file=prom.yml --storage.tsdb.path=$W/promdata --web.listen-address=127.0.0.1:9090 > prom.log 2>&1 & PIDS="$PIDS $!"
sleep 4
dd if=/dev/zero of=$W/io.bin bs=1M count=300 oflag=direct status=none; sync
sleep 30
dd if=/dev/zero of=$W/io.bin bs=1M count=300 oflag=direct status=none; sync
sleep 10
echo "--- alvo:"
curl -s http://127.0.0.1:9090/api/v1/targets | pyjson "t=d['data']['activeTargets'][0]; print(t['scrapeUrl'], t['health'], repr(t['lastError']))"
Q1='rate(ebpf_exporter_timer_starts_total[1m])'
Q2='histogram_quantile(0.95, sum by (le) (rate(ebpf_exporter_bio_latency_seconds_bucket[5m])))'
echo "--- consulta 1 (rate timers):"
curl -s -G http://127.0.0.1:9090/api/v1/query --data-urlencode "query=$Q1" | pyjson "r=d['data']['result']; print('status', d['status'], '| series:', len(r))"
echo "--- consulta 2 (p95 latencia de disco):"
curl -s -G http://127.0.0.1:9090/api/v1/query --data-urlencode "query=$Q2" | pyjson "r=d['data']['result']; print('status', d['status'], '| resultado:', r[0]['value'] if r else 'vazio')"

echo "== 6. Grafana (cap. 7)"
docker run -d --rm --network host --name grafana-teste grafana/grafana:latest >/dev/null 2>&1 || echo "FALHOU docker run grafana"
for i in $(seq 1 40); do curl -s http://localhost:3000/api/health 2>/dev/null | grep -q '"database": "ok"' && break; sleep 2; done
curl -s http://localhost:3000/api/health | head -c 200; echo
UID_DS=$(curl -s -u admin:admin -X POST -H 'Content-Type: application/json' \
  -d '{"name":"prom","type":"prometheus","url":"http://localhost:9090","access":"proxy"}' \
  http://localhost:3000/api/datasources | pyjson "print(d['datasource']['uid'])" 2>/dev/null)
echo "datasource uid: ${UID_DS:-FALHOU}"
for Q in "$Q1" "$Q2"; do
  curl -s -u admin:admin -G "http://localhost:3000/api/datasources/proxy/uid/$UID_DS/api/v1/query" --data-urlencode "query=$Q" \
    | pyjson "r=d['data']['result']; print('via Grafana:', d['status'], '| series:', len(r))" 2>&1 | head -2
done
echo "== fim"
