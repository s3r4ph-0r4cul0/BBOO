# Ferramenta: nmap-agent (Modo Autônomo)

Este diretório contém todos os arquivos necessários para a execução do `nmap-agent`, uma ferramenta de IA para reconhecimento de rede que opera de forma autônoma.

## Estrutura do Diretório

```
.  
├── Dockerfile
├── knowledge_base.json
├── main.py
├── prompts/
│   └── system_prompt.md
├── README.md
└── requirements.txt
```

## Descrição dos Arquivos

- **`main.py`**: O coração do agente. Contém a lógica para o modo de escaneamento autônomo e a API Flask para interagir com o agente.
- **`prompts/system_prompt.md`**: O "cérebro" do agente. Um prompt detalhado que define a identidade, as táticas e o processo de tomada de decisão do agente autônomo.
- **`Dockerfile`**: Arquivo de configuração para construir uma imagem Docker do agente, garantindo um ambiente de execução portável e com todas as dependências.
- **`requirements.txt`**: Especifica as dependências Python do projeto (Flask, Nmap, Gemini, Ollama).
- **`knowledge_base.json`**: Um arquivo JSON onde o agente armazena os resultados de suas missões de reconhecimento, criando uma base de conhecimento sobre os alvos analisados.

## Como Executar e Testar o Agente

### Pré-requisitos

- **Docker**: É necessário ter o Docker instalado e em execução.
- **Chave de API do Gemini**: Você precisará de uma chave de API válida do Google Gemini.
- **(Opcional) Ollama**: Se quiser usar modelos Llama locais, você precisa ter o [Ollama](https://ollama.com/) instalado e rodando com um modelo (ex: `ollama run llama3`).

### Passos para Execução

1.  **Construir a Imagem Docker**:
    Navegue até este diretório (`tool-nmap-agent`) e execute o comando:
    ```bash
    docker build -t nmap-agent .
    ```

2.  **Executar o Container**:
    Após a construção da imagem, inicie o container. Não se esqueça de substituir `"SUA_CHAVE_API_GEMINI"` pela sua chave real.
    ```bash
    docker run -p 5000:5000 -e GEMINI_API_KEY="SUA_CHAVE_API_GEMINI" nmap-agent
    ```
    O agente estará rodando e acessível na porta 5000 do seu localhost.

### Testando a API

Para iniciar uma missão de reconhecimento autônomo, envie uma requisição POST para o endpoint `/autonomous_scan` com o alvo desejado.

- **Exemplo de teste com `scanme.nmap.org`:**
  ```bash
  curl -X POST -H "Content-Type: application/json" -d '{"target": "scanme.nmap.org"}' http://agent:5000/autonomous_scan
  ```

O agente irá então executar sua série de scans e, ao final, retornará um JSON com o resumo completo da missão.