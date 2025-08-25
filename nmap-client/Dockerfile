FROM python:3.11-slim-bookworm

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# A porta que a aplicação cliente irá expor
EXPOSE 5001

# Comando para iniciar o servidor Flask do cliente
CMD ["python", "client.py"]
