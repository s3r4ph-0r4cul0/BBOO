# Guia para Criação de Prompts Eficazes em Segurança Ofensiva

## Introdução

A eficácia de um agente de IA, especialmente em um domínio complexo como segurança ofensiva, depende diretamente da qualidade dos prompts que o guiam. Um prompt bem construído não é apenas uma pergunta, mas um conjunto de instruções claras que definem um especialista, detalham um plano de ação e especificam um resultado esperado.

Este guia, inspirado na análise de exemplos práticos de pentest e nos system prompts de modelos de IA avançados (como Gemini CLI e GitHub Copilot), apresenta uma estrutura e técnicas para criar prompts de elite para suas ferramentas de automação.

---

## A Estrutura de um Prompt de Elite

Adote a seguinte estrutura para transformar uma simples ideia em uma instrução que a IA possa executar com precisão. Esta abordagem foi extraída dos exemplos encontrados em `Presentations-2025-BXSec`.

### 1. Defina a Persona

**Por que é importante?** Define o "chapéu" que a IA deve vestir, ajustando seu tom, conhecimento e foco.

- **Ruim**: `Me dê um comando nmap.`
- **Bom**: `**Persona:** Você é um pentester experiente, especializado em reconhecimento de redes.`

### 2. Descreva a Tarefa

A missão geral. O que, em alto nível, precisa ser feito?

- **Exemplo**: `**Tarefa:** Executar um escaneamento de portas detalhado em um endereço IP para descobrir serviços ativos.`

### 3. Detalhe as Etapas (O Workflow)

Esta é a parte mais crítica. Em vez de pedir um resultado final, guie a IA através de um processo lógico. A abordagem do Gemini CLI de **Entender -> Planejar -> Implementar -> Verificar** é um excelente modelo mental.

- **Exemplo**: 
  `**Etapas:**
  1. Gerar um comando Nmap para um scan rápido das portas mais comuns (-F).
  2. Com base no resultado, gerar um segundo comando para um scan detalhado (-sV -sC) apenas nas portas abertas encontradas.
  3. Analisar a saída do segundo scan e listar os serviços e versões.`

### 4. Forneça o Contexto

Nenhuma tarefa existe no vácuo. Forneça todos os dados necessários para a execução.

- **Exemplo**: `**Contexto:** O IP alvo é '192.168.1.50'. A rede é considerada hostil, então evite scans muito ruidosos ou agressivos na primeira etapa.`

### 5. Estabeleça o Objetivo

Qual é o estado final desejado? O que define o sucesso da tarefa?

- **Exemplo**: `**Objetivo:** Identificar todos os pontos de entrada (portas abertas) e os serviços/versões executando neles, para priorizar a próxima fase de análise de vulnerabilidades.`

### 6. Especifique o Formato da Saída

Seja explícito sobre como você quer a resposta. Isso é fundamental para automação e para encadear tarefas (chaining).

- **Ruim**: `Me mostre o resultado.`
- **Bom**: `**Saída Esperada:** Um objeto JSON contendo duas chaves: 'comando_executado' (com o comando nmap exato que foi rodado) e 'portas_abertas' (uma lista de objetos, cada um com 'porta', 'servico' e 'versao').`

---

## Técnicas Avançadas (Inspirado nos Profissionais)

As técnicas a seguir, observadas nos system prompts de serviços como Claude e GitHub Copilot, adicionam uma camada de controle e precisão.

### 1. Imponha Regras e Restrições

Use diretivas claras e imperativas para forçar ou proibir comportamentos. O `main.py` que criamos já usa uma forma disso: `**Retorne APENAS o comando Nmap, sem nenhuma explicação...**`

- **Exemplo de Aplicação**: 
  - `Você **NÃO DEVE** usar o script 'smb-vuln-*' do nmap.`
  - `Você **DEVE** sempre usar a flag '-T4' para velocidade.`
  - `Se a palavra 'relatório' for mencionada, sua saída **DEVE** estar em formato Markdown.`

### 2. Forneça Exemplos (Few-Shot Prompting)

Mostrar à IA exatamente o que você quer é mais eficaz do que apenas descrever. O system prompt do Gemini CLI está repleto de exemplos de interações `user`/`model`.

- **Exemplo de Aplicação**: 
  `... **Saída Esperada:** Um objeto JSON.
  **Exemplo de Saída:**
  ```json
  {
    "comando_executado": "nmap -sV -p 80,443 192.168.1.50",
    "portas_abertas": [
      {"porta": 80, "servico": "http", "versao": "Apache 2.4.41"},
      {"porta": 443, "servico": "https", "versao": "OpenSSL"}
    ]
  }
  ```
  `

### 3. Force um Raciocínio (Chain of Thought)

Inspirado na tag `<thinking>` do Claude, você pode instruir o modelo a "pensar antes de responder", detalhando seu plano. Isso melhora a qualidade de tarefas complexas.

- **Exemplo de Aplicação**:
  `**Instrução:** Antes de gerar o comando final, escreva seu plano de ação dentro de uma tag <plano>. O plano deve detalhar por que você escolheu cada parâmetro do Nmap com base no meu objetivo.`

---

## Exemplo Prático Reconstruído

Vamos pegar um prompt do `Prompt_Example_01.md` e aprimorá-lo com essas técnicas.

**Prompt Original:**
> **Persona:** Analista de Pentest mapeando a superfície de ataque.
> **Tarefa:** Executar um escaneamento de portas detalhado...
> **Saída Esperada:** O comando Nmap completo e estruturado para cada etapa.

**Prompt de Elite (Reconstruído):**

`
**Persona:** Você é um agente de IA especialista em pentest, focado em eficiência e precisão. Seu nome é ReconBot.

**Tarefa:** Gerar uma sequência de comandos Nmap para mapear um alvo.

**Contexto:**
- Alvo: 'scanme.nmap.org'
- Restrição: O primeiro scan deve ser rápido e discreto para evitar detecção precoce.

**Workflow:**
1.  **Planejamento:** Descreva em uma tag <plano> sua estratégia em duas etapas: um scan rápido inicial e um scan detalhado subsequente.
2.  **Geração do 1º Comando:** Gere o comando Nmap para um scan TCP rápido das 100 portas mais comuns. A saída deve ser apenas o comando.
3.  **Geração do 2º Comando:** Supondo que o primeiro scan encontrou as portas 22, 80 e 9929 abertas, gere um segundo comando Nmap para rodar detecção de versão (-sV), scripts padrão (-sC) e detecção de OS (-O) **apenas nessas portas**.

**Regras:**
- Você **DEVE** usar a flag `-T4` em ambos os comandos.
- Você **NÃO DEVE** usar a flag `-A` (scan agressivo).
- A saída para os comandos deve ser **APENAS o comando**, sem nenhum texto adicional.

**Formato da Saída Final:**
Retorne um objeto JSON contendo as chaves `plano`, `comando_fase_1` e `comando_fase_2`.

**Exemplo de Saída:**
```json
{
  "plano": "<plano>Minha estratégia é... </plano>",
  "comando_fase_1": "nmap -T4 -F scanme.nmap.org",
  "comando_fase_2": "nmap -T4 -sV -sC -O -p 22,80,9929 scanme.nmap.org"
}
```
`

## Conclusão

Criar prompts eficazes é uma habilidade. Ao ser **estruturado, explícito, detalhado e fornecer exemplos**, você transforma a IA de uma ferramenta genérica em um especialista altamente focado e capaz de executar tarefas complexas de segurança ofensiva com precisão e segurança.
