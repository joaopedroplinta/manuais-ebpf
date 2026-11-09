#!/usr/bin/env bash
# Manual 2 (seguranca), cap. 9: executa os comandos dos exemplos praticos.
# Rodar na raiz do repositorio, em um terminal normal:
#   sudo bash testes/08-seguranca-exemplos.sh 2>&1 | tee testes/resultados/08-seguranca-exemplos.txt
[ "$(id -u)" -eq 0 ] || { echo "rode com sudo"; exit 1; }
U=${SUDO_USER:-nobody}
UID_=$(id -u "$U"); GID_=$(id -g "$U")
# gera eventos como usuario comum, sem passar pelo sudo/PAM (que abre /etc/passwd e chama connect)
as_user() { setpriv --reuid="$UID_" --regid="$GID_" --clear-groups "$@"; }

# cena SAIDA ESPERA CARGA CMD... : inicia CMD (sem bash -c, para o SIGINT chegar na ferramenta),
# espera ate anexar, roda CARGA, espera ESPERA s e encerra com SIGINT.
cena() {
  local out=$1 espera=$2 carga=$3; shift 3
  : > "$out"
  timeout -s INT 60 "$@" > "$out" 2>&1 &
  local pid=$! n=0
  until grep -qE "Attached|PID|PCOMM|Tracing" "$out" || [ $n -ge 30 ]; do sleep 1; n=$((n+1)); done
  sleep 1
  eval "$carga"
  sleep "$espera"
  kill -INT $pid 2>/dev/null; wait $pid 2>/dev/null
}
mostra() { tr -d '\000' < "$1" | grep -E "$2" | head -${3:-12}; }

echo "== 1a. execsnoop-libbpf (carga: ls e id como $U)"
cena /tmp/m2-1a.out 1 'as_user ls / >/dev/null; as_user id >/dev/null' execsnoop-libbpf
mostra /tmp/m2-1a.out "PCOMM|/usr/bin/(ls|id)( |$)"

echo "== 1b. opensnoop-libbpf filtrando /etc/shadow e /etc/passwd (carga: cat, head, bash e python como $U)"
cena /tmp/m2-1b.out 1 'as_user cat /etc/shadow /etc/passwd >/dev/null 2>&1; as_user head -c1 /etc/shadow >/dev/null 2>&1; as_user bash -c "exec 3< /etc/shadow" 2>/dev/null; as_user python3 -c "open(\"/etc/shadow\")" 2>/dev/null' opensnoop-libbpf
mostra /tmp/m2-1b.out "PID|/etc/(shadow|passwd)" 20

echo "== 1c. shadow.bt (carga: cat, head, bash e python como $U)"
cat > /tmp/shadow.bt <<'BT'
tracepoint:syscalls:sys_enter_openat
/str(args->filename) == "/etc/shadow"/
{
    printf("[ALERTA] %s (pid=%d uid=%d) tentou abrir /etc/shadow\n",
           comm, pid, uid);
}
BT
cena /tmp/m2-1c.out 1 'as_user cat /etc/shadow /etc/passwd >/dev/null 2>&1; as_user head -c1 /etc/shadow >/dev/null 2>&1; as_user bash -c "exec 3< /etc/shadow" 2>/dev/null; as_user python3 -c "open(\"/etc/shadow\")" 2>/dev/null' bpftrace /tmp/shadow.bt
mostra /tmp/m2-1c.out "Attached|ALERTA" 10

echo "== 2a. contagem de syscalls por processo"
cena /tmp/m2-2a.out 2 'sleep 1' bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'
mostra /tmp/m2-2a.out "Attached|^@" 8

echo "== 2b. ptrace.bt (carga: strace como $U)"
cat > /tmp/ptrace.bt <<'BT'
tracepoint:syscalls:sys_enter_ptrace
/uid != 0/
{
    printf("[ALERTA] ptrace por %s (pid=%d uid=%d) -> pid alvo: %d\n",
           comm, pid, uid, args->pid);
}
BT
if command -v strace >/dev/null; then
  cena /tmp/m2-2b.out 1 'as_user strace -f true >/dev/null 2>&1' bpftrace /tmp/ptrace.bt
  mostra /tmp/m2-2b.out "Attached|ALERTA" 5
else
  echo "strace ausente (apt install strace)"
fi

echo "== 2c. finit_module (so o alerta; nenhum modulo e carregado)"
cena /tmp/m2-2c.out 2 'sleep 1' bpftrace -e 'tracepoint:syscalls:sys_enter_finit_module { printf("[ALERTA] %s (pid=%d uid=%d) carregou um modulo\n", comm, pid, uid); }'
mostra /tmp/m2-2c.out "Attached|ALERTA"

echo "== 3a. tcpconnect-libbpf (carga: conexao a 127.0.0.1:22 como $U)"
cena /tmp/m2-3a.out 1 "as_user bash -c 'exec 3<>/dev/tcp/127.0.0.1/22' 2>&1" tcpconnect-libbpf
mostra /tmp/m2-3a.out "PID| bash "

echo "== 3b. sys_enter_connect com bpftrace (carga: conexao a 127.0.0.1:22 como $U)"
cena /tmp/m2-3b.out 1 "as_user bash -c 'exec 3<>/dev/tcp/127.0.0.1/22' 2>&1" bpftrace -e 'tracepoint:syscalls:sys_enter_connect { printf("%s (pid=%d uid=%d) chamou connect()\n", comm, pid, uid); }'
mostra /tmp/m2-3b.out "Attached|^bash"
echo "== fim"
