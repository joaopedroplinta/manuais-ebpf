# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Projeto

Três manuais sobre eBPF (Observabilidade, Segurança, Redes) do projeto de extensão do minicurso "Introdução ao eBPF" (Práticas de Extensão V, IFPR Pinhais, orientador Guilherme Werneck de Oliveira). Cada manual é um documento LaTeX independente. Hoje os capítulos são só esqueletos de títulos, vindos do Google Doc "Esqueleto-CursoEbpf". O texto ainda será escrito.

O projeto vive no Overleaf, sincronizado com o GitHub (`joaopedroplinta/manuais-ebpf`). Esta pasta é o clone local, e `pdflatex` não está instalado na máquina. Antes de editar, `git pull`, pois o Overleaf também faz commits.

## Stack

- LaTeX com a classe `ifpr-pinhais.cls` (sobre `abntex2`/memoir), pdfLaTeX, babel `brazil`
- `referencias.bib` com estilo ABNT `alf` (via `abntex2cite`)
- Logos em `imagens/` (caminhos fixos `imagens/logo-ifpr` e `imagens/logo-mec` dentro da classe)

## Estrutura

```
main-manual-N-<tema>.tex         → um main por manual (capa, folha de rosto, sumário, \input dos capítulos)
capitulos-manual-N-<tema>/       → um arquivo por capítulo: 1.Introducao.tex, 2.PreRequisitos.tex, ...
referencias.bib                  → compartilhado pelos três mains
```

Cada capítulo começa com `\chapter{}` e usa `\section` para os subtítulos. O nome do arquivo é o título sem acento e em CamelCase, com o número na frente. Ao criar ou renomear um capítulo, atualize a lista de `\input` do main correspondente à mão, pois a ordem dos `\input` não é automática.

## Comandos

Compilação normal é pelo Overleaf, escolhendo o main no menu. Localmente, só se houver TeX Live:

```bash
latexmk -pdf main-manual-1-observabilidade.tex    # troque pelo manual desejado
latexmk -c                                        # limpa intermediários
```

## Convenções

- **`\imprimirfolhaderosto` sempre com argumento: `\imprimirfolhaderosto{\folhaderostoname}`.** No `abntex2` ele engole o próximo token como título do bookmark; sozinho, quebra o `\pdfbookmark` seguinte com "Argument of \pdfbookmark has an extra }". O `main.tex` original do modelo tinha esse bug.
- `\bibliography{referencias}` está comentado nos mains. Descomente quando houver o primeiro `\cite{}` no texto, porque o BibTeX dá erro com bibliografia vazia.
- Código vai em `lstlisting` (pacote `listings` já carregado nos mains).
- Autores, orientador, título e `\tipotrabalho{Manual}` ficam no bloco de metadados no topo de cada main. Os três mains são cópias do mesmo preâmbulo. Mudança comum (pacote, autor) precisa ser repetida nos três.
