# Testes dos exemplos do Manual 1

Scripts que executam, em uma máquina real, os comandos e programas citados nos capítulos do Manual 1 (eBPF para Observabilidade). Cada exemplo do texto que não está marcado com `% TODO` foi validado por um destes scripts.

## Ambiente em que foram executados

Ubuntu 26.04.1 LTS, kernel 7.0.0-38-generic, `bpftrace` 0.25.0, `bpftool` 7.7.0, BCC 0.35.0, `libbpf-tools` 0.35.0, `ebpf_exporter` v2.5.1, Prometheus 3.15.0, Grafana 13.2.3. Em outros kernels ou distribuições, os resultados podem variar.

## Como rodar

Os scripts carregam programas no kernel e exigem `root`. Rode em um terminal normal (não pelo `!` do Claude Code, que não oferece terminal ao `sudo`), a partir da raiz do repositório, guardando a saída:

```bash
sudo bash testes/03-programa-libbpf-e-exporter.sh 2>&1 | tee testes/resultados/03-programa-libbpf-e-exporter.txt
```

Cada comando roda por poucos segundos e é encerrado com `SIGINT`. Os scripts criam arquivos em `/tmp` e limpam o que iniciaram ao terminar.

| Script | O que testa | Capítulos | Requisitos |
| --- | --- | --- | --- |
| `01-ambiente-e-ferramentas.sh` | `bpftool`, `bpftrace` e as ferramentas do BCC (`-bpfcc`) | 2, 4 a 6 | `bpfcc-tools` |
| `02-libbpf-tools-e-bpftrace.sh` | ferramentas `-libbpf` (CO-RE) e alternativas em `bpftrace` | 4 | `libbpf-tools` |
| `03-programa-libbpf-e-exporter.sh` | compila e carrega o `monitor.bpf.c`; lê o mapa; exporter em Python | 5, 7 | `clang`, `libbpf-dev`, `python3-prometheus-client` |
| `04-ebpf-exporter-prometheus-grafana.sh` | `apt` em contêiner limpo, `ebpf_exporter`, Prometheus, Grafana | 2, 5, 7 | `docker`, internet |
| `05-usdt-python.sh` | sondas USDT do `python3.14` | 6 | — |
| `06-painel-grafana.sh` | sobe o painel de exemplo para tirar print; repete o USDT | 6, 7 | arquivos dos scripts 03 e 04 em `/tmp` |
| `07-exemplos-praticos.sh` | cenários do cap. 8: `execsnoop`, `opensnoop -p`, `syscount -p`, `tcplife`, USDT | 8 | `libbpf-tools`, `curl`, `python3.14` |

## Resultados

A pasta `resultados/` guarda a saída de cada execução. Ela é a evidência dos números citados no texto, como as 11 de 14 ferramentas do BCC que falharam ao compilar neste kernel e as 13 de 14 versões `-libbpf` que rodaram. O resultado do `02` mostra a causa: erros de compilação do BCC nos cabeçalhos do kernel 7.0.
