# CyberRadar

Radar de notícias de cibersegurança (PT, BR e internacionais), traduzidas para PT-PT, com gerador de posts para LinkedIn, Instagram e Facebook. Gratuito e sem servidor próprio.

## Como funciona

- `feeds.json`: lista de fontes (RSS).
- `scripts/fetch_news.py`: vai buscar as notícias, traduz as estrangeiras e grava `data/news.json`.
- `.github/workflows/update.yml`: corre o script de 20 em 20 minutos no GitHub Actions.
- `index.html`: a app. Lê `data/news.json` e atualiza sozinha a cada 5 minutos.

## Publicar em 5 passos (uma vez)

1. No GitHub, cria um repositório **público** (ex: `cyberradar`) e envia todos estes ficheiros.
2. Em **Settings → Pages**, escolhe *Deploy from a branch → main → / (root)*.
3. Em **Actions**, abre "Atualizar notícias" e clica **Run workflow** para a primeira recolha.
4. Abre `https://craveirorj.github.io/cyberradar/` no telemóvel e no PC.
5. Instala como app: no Chrome/Edge, ícone de instalar na barra de endereço; no telemóvel, "Adicionar ao ecrã inicial".

Repositório público = GitHub Actions gratuito e sem limites práticos para isto.

## Acrescentar fontes

Edita `feeds.json` no GitHub e acrescenta uma linha:

```json
{"name": "Nome", "url": "https://site/feed/", "region": "PT", "lang": "pt"}
```

`region`: PT, BR ou INT. `lang`: `pt` ou `en` (qualquer língua diferente de `pt` é traduzida).
Uma fonte que falhe é ignorada e aparece com ⚠ nas definições da app (⚙).

## Posts

Funciona sem custos com o modelo base. Para posts mais naturais, cola uma chave gratuita do Gemini (aistudio.google.com) em "Chave Gemini" dentro do post. Fica guardada só no teu dispositivo. Os limites do plano grátis podem mudar.

## Limitações conhecidas

- Alguns sites mudam ou fecham o feed RSS: vê o ⚠ nas definições e corrige o URL.
- A tradução usa um serviço gratuito e pode falhar pontualmente; nesse caso fica no idioma original.
- Os feeds listados não foram testados ao vivo na construção: a primeira execução do Actions diz quais funcionam (ver o log).
