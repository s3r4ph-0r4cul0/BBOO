# Agente: nmap-agent

## Objetivo do Agente

O `nmap-agent` é um agente de Inteligência Artificial projetado para auxiliar em operações de segurança ofensiva, especificamente na fase de reconhecimento de redes. Seu principal objetivo é traduzir metas de varredura de alto nível (ex: "encontrar todos os servidores web em uma sub-rede") em comandos `nmap` precisos e otimizados.

Além disso, o agente é capaz de analisar os resultados das varreduras e usar esse conhecimento para refinar e aprimorar comandos futuros, criando um ciclo de aprendizado contínuo.

## Funcionalidades Principais

- **Tradução de Linguagem Natural para Comandos Nmap**: Converte objetivos de reconhecimento em linguagem humana para comandos `nmap` funcionais.
- **Otimização de Comandos**: Utiliza um LLM para selecionar os melhores parâmetros do `nmap` com base no objetivo fornecido.
- **Análise de Resultados**: Processa a saída do `nmap` (formato XML) para extrair informações estruturadas, como portas abertas, serviços, versões e sistemas operacionais.
- **Auto-aperfeiçoamento (Self-Refinement)**: Usa os resultados de varreduras anteriores para refinar e sugerir comandos mais eficazes em iterações futuras.
- **Base de Conhecimento**: Mantém um histórico de operações e aprendizados para melhorar sua performance ao longo do tempo.

## Como Utilizar e Integrar ao Gemini

Este agente foi projetado para ser utilizado como uma ferramenta (`tool`) dentro de ambientes de IA como o Gemini. A integração permite que o Gemini delegue tarefas de reconhecimento de rede diretamente para o `nmap-agent`.

### Exemplo de Integração:

1.  **Definição da Ferramenta**: O `nmap-agent` é definido como uma ferramenta disponível para o Gemini, com parâmetros de entrada claros, como `objetivo` (a meta do scan) e `alvo` (o endereço IP ou range).
2.  **Chamada da Ferramenta**: Durante uma conversa, um usuário pode pedir:
    > "Gemini, faça uma varredura por portas abertas no host 192.168.1.10."
3.  **Execução pelo Gemini**: O Gemini identifica que esta é uma tarefa para o `nmap-agent` e o invoca, passando o objetivo e o alvo.
4.  **Operação do Agente**: O `nmap-agent` gera o comando `nmap` apropriado (ex: `nmap -sS -T4 192.168.1.10`), executa a varredura e analisa a saída.
5.  **Retorno do Resultado**: O agente retorna o resultado estruturado para o Gemini.
6.  **Resposta ao Usuário**: O Gemini formata e apresenta o resultado da varredura de forma clara para o usuário.

Para uma implementação prática, o agente expõe suas funcionalidades através de uma API REST, que pode ser chamada pelo ambiente do Gemini sempre que uma tarefa de reconhecimento de rede for solicitada.
