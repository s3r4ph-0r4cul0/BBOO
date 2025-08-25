import requests
import json
from flask import Flask, render_template, request, flash

app = Flask(__name__)
# Adiciona uma chave secreta para usar o sistema de mensagens flash do Flask
app.secret_key = 'a_random_secret_key_for_flash_messages'

@app.route('/')
def index():
    """Renderiza a página inicial com o formulário."""
    return render_template('index.html')

@app.route('/proxy-request', methods=['POST'])
def proxy_request():
    """Recebe a requisição do formulário, a envia para o agente e renderiza o resultado."""
    endpoint = request.form.get('endpoint')
    target = request.form.get('target')
    model = request.form.get('model')

    if not endpoint or not target:
        flash("Endpoint e Target não podem estar vazios.")
        return render_template('index.html')

    # Constrói o JSON payload dinamicamente
    payload_json = {"target": target, "model": model}

    print(f"Encaminhando requisição para: {endpoint}")
    print(f"Payload: {payload_json}")

    try:
        # Envia a requisição para o endpoint do agente
        response = requests.post(endpoint, json=payload_json, timeout=600) # Timeout de 10 minutos
        response.raise_for_status() # Lança um erro para respostas HTTP 4xx/5xx
        
        # Tenta decodificar a resposta do agente como JSON
        response_data = response.json()
        
        # Renderiza a página de resultados com os dados recebidos
        return render_template('results.html', data=response_data)

    except requests.exceptions.RequestException as e:
        # Erros de conexão, timeout, etc.
        error_message = f"Erro ao se comunicar com o agente: {e}"
        print(error_message)
        return render_template('results.html', data={"error": error_message})
    except json.JSONDecodeError:
        # Se a resposta do agente não for um JSON válido
        error_message = "A resposta do agente não foi um JSON válido."
        print(error_message)
        return render_template('results.html', data={"error": error_message, "raw_response": response.text})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)