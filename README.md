# Manuais sobre eBPF

Manuais do projeto de extensão do minicurso **Introdução ao eBPF**, desenvolvido na disciplina de Práticas de Extensão V do curso de Bacharelado em Ciência da Computação do IFPR, Campus Pinhais.

- **Orientador:** Prof. Guilherme Werneck de Oliveira
- **Autores:** Beatriz Regina Nahas e João Pedro dos Santos Henrique Plinta

## Manuais

| Manual | Tema | Main | Capítulos |
| --- | --- | --- | --- |
| 1 | eBPF para Observabilidade | `main-manual-1-observabilidade.tex` | `capitulos-manual-1-observabilidade/` (10) |
| 2 | eBPF para Segurança | `main-manual-2-seguranca.tex` | `capitulos-manual-2-seguranca/` (11) |
| 3 | eBPF para Redes | `main-manual-3-redes.tex` | `capitulos-manual-3-redes/` (12) |

Cada manual é compilado separadamente e gera seu próprio PDF, com capa, folha de rosto e sumário. Por enquanto os capítulos são esqueletos com os títulos das seções. O texto ainda será escrito.

## Estrutura

```
main-manual-N-<tema>.tex      main de cada manual
capitulos-manual-N-<tema>/    um arquivo .tex por capítulo (1.Introducao.tex, 2.PreRequisitos.tex, ...)
referencias.bib               referências, compartilhadas pelos três manuais
ifpr-pinhais.cls              classe do IFPR Pinhais (baseada em abntex2)
imagens/                      logos usados na capa
```

## Como compilar

**Overleaf:** importe a pasta como projeto, abra o menu e escolha o main do manual que quer compilar como documento principal.

**Local** (requer TeX Live com `abntex2`):

```bash
latexmk -pdf main-manual-1-observabilidade.tex
```

## Como escrever um capítulo

1. Edite o arquivo do capítulo em `capitulos-manual-N-<tema>/`. Ele começa com `\chapter{}` e usa `\section{}` para as seções.
2. Para um capítulo novo, crie o arquivo na pasta do manual e adicione o `\input{...}` no main, na posição desejada.
3. Para citar, use `\cite{chave}` com uma chave de `referencias.bib` e descomente a linha `\bibliography{referencias}` no fim do main. O BibTeX dá erro se a bibliografia estiver ativa sem nenhuma citação.
4. Trechos de código vão dentro de `\begin{lstlisting} ... \end{lstlisting}`.

## Licença

© 2026 Beatriz Regina Nahas e João Pedro dos Santos Henrique Plinta. Distribuído sob a licença [CC BY 4.0](LICENSE): é permitido copiar e adaptar, desde que haja crédito aos autores.
