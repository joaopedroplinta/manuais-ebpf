#!/usr/bin/env bash
# Sobe ebpf_exporter + programa libbpf + exporter Python + Prometheus + Grafana com um painel pronto, para tirar print.
# Antes, testa de novo o USDT do python3.14 com --no-warnings.
# Rodar com: sudo bash testes/06-painel-grafana.sh   (precisa dos arquivos das rodadas 3 e 4 em /tmp)
[ "$(id -u)" -eq 0 ] || { echo "rode com sudo"; exit 1; }
W=/tmp/ebpf-painel; rm -rf $W; mkdir -p $W; cd $W
T3=/tmp/ebpf-teste; T4=/tmp/ebpf-teste4
EE=$(find $T4 -name ebpf_exporter -type f 2>/dev/null | head -1)
PROM=$(find $T4 -maxdepth 2 -name prometheus -type f 2>/dev/null | head -1)
[ -x "$EE" ] && [ -x "$PROM" ] && [ -f $T3/monitor.bpf.o ] || { echo "faltam arquivos das rodadas 3/4 em /tmp (ebpf_exporter, prometheus, monitor.bpf.o)"; exit 1; }
PIDS=""
cleanup() {
  echo; echo "encerrando..."
  kill $PIDS 2>/dev/null
  docker rm -f grafana-painel >/dev/null 2>&1
  rm -rf /sys/fs/bpf/monitor
  echo "ok"
}
trap cleanup EXIT
P=/usr/bin/python3.14

echo "== 0. USDT do python3.14 com --no-warnings"
cat > $W/gc.bt <<EOF
usdt:$P:python:gc__start { @ini[tid] = nsecs; }
usdt:$P:python:gc__done /@ini[tid]/ {
    @us = hist((nsecs - @ini[tid]) / 1000);
    delete(@ini[tid]);
}
EOF
( timeout --preserve-status -s INT 6 bpftrace --no-warnings $W/gc.bt > $W/usdt-b.out 2>&1 ) & BP=$!
sleep 2
$P -c "
import gc
dados = [[i] * 10 for i in range(200000)]
for _ in range(50): gc.collect()
"
wait $BP
echo "--- B (pausa do GC):"; head -25 $W/usdt-b.out
( timeout --preserve-status -s INT 5 bpftrace --no-warnings -e "usdt:$P:python:import__find__load__start { printf(\"%s\\n\", str(arg0)); }" > $W/usdt-a.out 2>&1 ) & BP=$!
sleep 2; $P -c "import json, decimal, sqlite3"; wait $BP
echo "--- A (imports, primeiras linhas):"; head -6 $W/usdt-a.out

echo "== 1. programa libbpf (cap. 5)"
rm -rf /sys/fs/bpf/monitor
bpftool prog loadall $T3/monitor.bpf.o /sys/fs/bpf/monitor autoattach 2>&1 | tail -2
cat > exporter.py <<'EOF'
import json
import subprocess
import time

from prometheus_client import start_http_server
from prometheus_client.core import CounterMetricFamily, REGISTRY

PORTAS = {80, 443, 8080, 8081}  # portas de servico de interesse


def ler_mapa(nome):
    saida = subprocess.run(["bpftool", "-j", "map", "dump", "name", nome],
                           capture_output=True, text=True, check=True).stdout
    return json.loads(saida)


class Coletor:
    def collect(self):
        m = CounterMetricFamily("ebpf_tcp_bytes_enviados",
                                "Bytes enviados por porta de destino",
                                labels=["porta"])
        for entrada in ler_mapa("bytes_por_porta"):
            f = entrada["formatted"]
            if f["key"] in PORTAS:
                m.add_metric([str(f["key"])], f["value"])
        yield m


REGISTRY.register(Coletor())
start_http_server(8000)
while True:
    time.sleep(1)
EOF
python3 exporter.py > exporter.log 2>&1 & PIDS="$PIDS $!"

echo "== 2. ebpf_exporter, geradores de carga, Prometheus"
( cd $(dirname $EE) && ./ebpf_exporter --config.dir=examples --config.names=timers,biolatency > $W/ee.log 2>&1 ) & PIDS="$PIDS $!"
python3 -m http.server 8081 --bind 127.0.0.1 >/dev/null 2>&1 & PIDS="$PIDS $!"
( while true; do curl -s http://127.0.0.1:8081/ >/dev/null; sleep 0.3; done ) & PIDS="$PIDS $!"
( while true; do dd if=/dev/zero of=$W/io.bin bs=$(( RANDOM % 128 + 4 ))k count=$(( RANDOM % 200 + 20 )) oflag=direct status=none; dd if=$W/io.bin of=/dev/null iflag=direct status=none; sleep 0.5; done ) & PIDS="$PIDS $!"
cat > prom.yml <<'EOF'
scrape_configs:
  - job_name: ebpf
    scrape_interval: 5s
    static_configs:
      - targets: ['localhost:9435', 'localhost:8000']
EOF
$PROM --config.file=prom.yml --storage.tsdb.path=$W/promdata --web.listen-address=127.0.0.1:9090 > prom.log 2>&1 & PIDS="$PIDS $!"
sleep 4

echo "== 3. Grafana + painel"
docker rm -f grafana-painel >/dev/null 2>&1
docker run -d --rm --network host --name grafana-painel \
  -e GF_AUTH_ANONYMOUS_ENABLED=true -e GF_AUTH_ANONYMOUS_ORG_ROLE=Admin \
  -e GF_AUTH_DISABLE_LOGIN_FORM=true -e GF_USERS_DEFAULT_THEME=light \
  grafana/grafana:latest >/dev/null || { echo "FALHOU docker run"; exit 1; }
for i in $(seq 1 40); do curl -s http://localhost:3000/api/health 2>/dev/null | grep -q '"database": "ok"' && break; sleep 2; done
curl -s -u admin:admin -X POST -H 'Content-Type: application/json' \
  -d '{"name":"Prometheus","uid":"prom-ebpf","type":"prometheus","url":"http://localhost:9090","access":"proxy","isDefault":true}' \
  http://localhost:3000/api/datasources | head -c 160; echo

python3 - <<'PY'
import json
ds = {"type": "prometheus", "uid": "prom-ebpf"}
def ts(i, title, exprs, unit, x, y):
    return {"id": i, "type": "timeseries", "title": title, "datasource": ds,
            "gridPos": {"x": x, "y": y, "w": 12, "h": 8},
            "fieldConfig": {"defaults": {"unit": unit}, "overrides": []},
            "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
            "targets": [{"refId": chr(65 + k), "expr": e, "legendFormat": l, "datasource": ds}
                        for k, (e, l) in enumerate(exprs)]}
panels = [
    ts(1, "Tráfego TCP enviado por porta de destino (bytes/s)",
       [("rate(ebpf_tcp_bytes_enviados_total[1m])", "porta {{porta}}")], "Bps", 0, 0),
    ts(2, "Latência de disco (percentis 50 e 95)",
       [("histogram_quantile(0.95, sum by (le) (rate(ebpf_exporter_bio_latency_seconds_bucket[1m])))", "p95"),
        ("histogram_quantile(0.50, sum by (le) (rate(ebpf_exporter_bio_latency_seconds_bucket[1m])))", "p50")],
       "s", 12, 0),
    {"id": 3, "type": "heatmap", "title": "Distribuição da latência de disco", "datasource": ds,
     "gridPos": {"x": 0, "y": 8, "w": 12, "h": 8},
     "targets": [{"refId": "A", "datasource": ds, "format": "heatmap", "legendFormat": "{{le}}",
                  "expr": "sum(increase(ebpf_exporter_bio_latency_seconds_bucket[$__rate_interval])) by (le)"}],
     "options": {"calculate": False, "cellGap": 1, "rowsFrame": {"layout": "le"},
                 "yAxis": {"axisPlacement": "left", "unit": "s"},
                 "color": {"mode": "scheme", "scheme": "Oranges", "fill": "dark-orange", "scale": "exponential", "exponent": 0.5, "steps": 64}}},
    ts(4, "Temporizadores do kernel disparados por segundo (5 maiores)",
       [("topk(5, rate(ebpf_exporter_timer_starts_total[1m]))", "{{function}}")], "ops", 12, 8),
]
dash = {"dashboard": {"uid": "ebpf-manual1", "title": "Observabilidade com eBPF", "timezone": "browser",
                      "schemaVersion": 39, "refresh": "5s", "time": {"from": "now-10m", "to": "now"},
                      "panels": panels}, "overwrite": True}
json.dump(dash, open("dash.json", "w"))
PY
curl -s -u admin:admin -X POST -H 'Content-Type: application/json' -d @dash.json http://localhost:3000/api/dashboards/db | head -c 250; echo

echo "== 4. aguardando dados (120 s)..."
sleep 120
echo "--- confere as consultas pelo Grafana:"
for Q in 'rate(ebpf_tcp_bytes_enviados_total[1m])' \
         'histogram_quantile(0.95, sum by (le) (rate(ebpf_exporter_bio_latency_seconds_bucket[1m])))' \
         'sum(increase(ebpf_exporter_bio_latency_seconds_bucket[1m])) by (le)' \
         'topk(5, rate(ebpf_exporter_timer_starts_total[1m]))'; do
  curl -s -u admin:admin -G "http://localhost:3000/api/datasources/proxy/uid/prom-ebpf/api/v1/query" --data-urlencode "query=$Q" \
   | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['status'], len(d['data']['result']), 'series  <-', '''$Q'''[:60])"
done
echo
echo "=============================================================="
echo " PAINEL PRONTO. Abra no navegador (sem login):"
echo "   http://localhost:3000/d/ebpf-manual1/observabilidade-com-ebpf?orgId=1&from=now-5m&to=now&refresh=5s"
echo " Espere ~1 min para os graficos encherem, tire o print, e volte aqui."
echo "=============================================================="
read -r -p "Pressione Enter para encerrar tudo... " _ < /dev/tty
