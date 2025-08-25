FROM python:3.11-slim-bookworm

# Instalação de dependências do sistema para Nmap e Pillow (imagens e fontes)
RUN apt-get update && apt-get install -y \
    nmap \
    libjpeg-dev \
    zlib1g-dev \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# A porta padrão do Flask
EXPOSE 5000

# Variáveis de ambiente com valores padrão
ENV GEMINI_API_KEY=""
ENV MAX_AUTONOMOUS_ITERATIONS="7"
ENV OLLAMA_MODEL="llama3"

# Comando para iniciar o servidor Flask
CMD ["python", "main.py"]