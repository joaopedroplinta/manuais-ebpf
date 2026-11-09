#!/usr/bin/env bash
# Manual 2 (seguranca), cap. 9: executa os comandos dos exemplos praticos.
# Rodar na raiz do repositorio, em um terminal normal:
#   sudo bash testes/08-seguranca-exemplos.sh 2>&1 | tee testes/resultados/08-seguranca-exemplos.txt
[ "$(id -u)" -eq 0 ] || { echo "rode com sudo"; exit 1; }
U=${SUDO_USER:-nobody}   # usuario comum que gera os eventos de teste

# run SEGUNDOS "COMANDO" -- "GERADOR": roda COMANDO em segundo plano, executa
# GERADOR para produzir eventos e mostra o inicio da saida.
run() {
  local t=$1 cmd=$2 gen=$4
  ( timeout --preserve-status -s INT "$t" bash -c "$cmd" > /tmp/m2-ex.out 2>&1 ) &
  sleep 3
  eval "$gen"
  wait
  head -15 /tmp/m2-ex.out
}

echo "== 1a. execsnoop-bpfcc"
run 8 "execsnoop-bpfcc" -- "sudo -u $U ls / >/dev/null; sudo -u $U id >/dev/null"

echo "== 1b. opensnoop-bpfcc filtrando /etc/shadow e /etc/passwd"
run 8 "opensnoop-bpfcc | grep --line-buffered -E '/etc/(shadow|passwd)'" -- "sudo -u $U cat /etc/shadow /etc/passwd >/dev/null 2>&1"

echo "== 1c. shadow.bt"
cat > /tmp/shadow.bt <<'BT'
tracepoint:syscalls:sys_enter_openat
/str(args->filename) == "/etc/shadow"/
{
    printf("[ALERTA] %s (pid=%d uid=%d) tentou abrir /etc/shadow\n",
           comm, pid, uid);
}
BT
run 8 "bpftrace /tmp/shadow.bt" -- "sudo -u $U cat /etc/shadow >/dev/null 2>&1"

echo "== 2a. contagem de syscalls por processo"
run 6 "bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'" -- "sleep 1"

echo "== 2b. ptrace.bt"
cat > /tmp/ptrace.bt <<'BT'
tracepoint:syscalls:sys_enter_ptrace
/uid != 0/
{
    printf("[ALERTA] ptrace por %s (pid=%d uid=%d) -> pid alvo: %d\n",
           comm, pid, uid, args->pid);
}
BT
if command -v strace >/dev/null; then
  run 8 "bpftrace /tmp/ptrace.bt" -- "sudo -u $U strace -f true >/dev/null 2>&1"
else
  echo "strace ausente (apt install strace)"
fi

echo "== 2c. finit_module (so o alerta; nenhum modulo e carregado)"
run 6 "bpftrace -e 'tracepoint:syscalls:sys_enter_finit_module { printf(\"[ALERTA] %s (pid=%d uid=%d) carregou um modulo\\n\", comm, pid, uid); }'" -- "sleep 1"

echo "== 3a. tcpconnect-bpfcc"
run 8 "tcpconnect-bpfcc" -- "sudo -u $U bash -c 'exec 3<>/dev/tcp/127.0.0.1/22' 2>&1"

echo "== 3b. sys_enter_connect com bpftrace"
run 8 "bpftrace -e 'tracepoint:syscalls:sys_enter_connect { printf(\"%s (pid=%d uid=%d) chamou connect()\\n\", comm, pid, uid); }'" -- "sudo -u $U bash -c 'exec 3<>/dev/tcp/127.0.0.1/22' 2>&1"
echo "== fim"
