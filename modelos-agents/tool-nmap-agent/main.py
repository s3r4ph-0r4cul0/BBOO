import os
import json
import re
import subprocess
import base64
from io import BytesIO
from flask import Flask, request, jsonify
import google.generativeai as genai
import ollama
from PIL import Image, ImageDraw, ImageFont

# --- Configuração a partir de Variáveis de Ambiente ---
MAX_AUTONOMOUS_ITERATIONS = int(os.getenv("MAX_AUTONOMOUS_ITERATIONS", 15))
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# Constantes de arquivos e diretórios
KNOWLEDGE_BASE_FILE = 'knowledge_base.json'
SYSTEM_PROMPT_FILE = 'prompts/system_prompt.md'

# --- Inicialização da Aplicação Flask ---
app = Flask(__name__)

# --- Configuração do Cliente LLM (Ollama) ---
# A configuração do Ollama é feita implicitamente pelas chamadas a ollama.generate()

# --- Funções de Utilidade e Base de Conhecimento ---
def load_system_prompt():
    try:
        with open(SYSTEM_PROMPT_FILE, 'r') as f:
            return f.read()
    except FileNotFoundError:
        print(f"AVISO CRÍTICO: Arquivo de system prompt não encontrado em {SYSTEM_PROMPT_FILE}")
        return "Você é um assistente de Nmap."

def save_system_prompt(new_content):
    try:
        with open(SYSTEM_PROMPT_FILE, 'w') as f:
            f.write(new_content)
        print(f"System prompt salvo em {SYSTEM_PROMPT_FILE}")
    except IOError as e:
        print(f"ERRO ao salvar o system prompt: {e}")

def load_knowledge_base():
    if not os.path.exists(KNOWLEDGE_BASE_FILE):
        return {}
    try:
        with open(KNOWLEDGE_BASE_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"Erro ao carregar a base de conhecimento: {e}")
        return {}

def save_mission_report(target, report):
    try:
        kb = load_knowledge_base()
        if target not in kb:
            kb[target] = []
        # Remove a imagem base64 antes de salvar para não poluir o JSON
        for step in report.get('mission_summary', []):
            step.pop('output_image_base64', None)
        kb[target].append(report)
        with open(KNOWLEDGE_BASE_FILE, 'w') as f:
            json.dump(kb, f, indent=4)
        print(f"Relatório da missão para o alvo {target} salvo com sucesso.")
    except Exception as e:
        print(f"Erro ao salvar na base de conhecimento: {e}")

# --- Função de Geração de Imagem ---
def generate_image_from_text(text_content, command):
    """Gera uma imagem PNG a partir de um texto e a retorna como uma string Base64."""
    try:
        font_path = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
        font = ImageFont.truetype(font_path, 12) if os.path.exists(font_path) else ImageFont.load_default()
    except IOError:
        font = ImageFont.load_default()

    header = f"$ {command}"
    full_text = f"{header}\n={'=' * len(header)}\n{text_content}" # Changed separator for visual clarity
    lines = full_text.split('\n')

    # Calculate line dimensions using getbbox for modern Pillow versions
    line_dimensions = [font.getbbox(line) for line in lines]
    line_heights = [bbox[3] - bbox[1] for bbox in line_dimensions] # height = bottom - top
    line_widths = [bbox[2] - bbox[0] for bbox in line_dimensions] # width = right - left

    line_spacing = 4 # Spacing between lines
    total_height = sum(line_heights) + (len(lines) - 1) * line_spacing + 40 # Total height including padding
    width = max(line_widths) + 40 # Max width including padding

    img = Image.new('RGB', (width, total_height), color = (40, 42, 54)) # Dracula background color
    d = ImageDraw.Draw(img)

    y_text = 20
    for i, line in enumerate(lines):
        color = (80, 250, 123) if i == 0 else (248, 248, 242) # Green for command, white for rest
        d.text((20, y_text), line, font=font, fill=color)
        y_text += line_heights[i] + line_spacing

    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode('utf-8')

# --- Funções de Interação com LLM ---
def get_llm_response(prompt):
    clean_prompt = prompt.strip()
    try:
        response = ollama.generate(model=OLLAMA_MODEL, prompt=clean_prompt)
        return response['response']
    except Exception as e:
        return f"Erro ao contatar o Ollama: {e}"

def refine_system_prompt(current_system_prompt, mission_report):
    """
    Usa um LLM para propor um prompt de sistema refinado com base nos resultados da missão.
    """
    refinement_prompt = f"""
    Você é um engenheiro de prompts experiente, encarregado de otimizar o prompt de sistema de um agente de reconhecimento Nmap.
    O objetivo é melhorar a capacidade do agente de realizar varreduras Nmap abrangentes e eficazes, e de tomar decisões inteligentes para obter o "melhor output".

    Aqui está o PROMPT DE SISTEMA ATUAL do agente:
    ```
    {current_system_prompt}
    ```

    Aqui está o RELATÓRIO DA ÚLTIMA MISSÃO do agente (incluindo o histórico de scans e o output analisado):
    ```json
    {json.dumps(mission_report, indent=2)}
    ```

    Analise o relatório da missão. Considere se o agente poderia ter usado o Nmap de forma mais eficaz, explorado mais opções, ou tomado decisões mais inteligentes para obter um output mais "proveitoso" (conforme definido no prompt).

    Sua tarefa é propor uma VERSÃO REFINADA do PROMPT DE SISTEMA.
    Mantenha a estrutura e o formato do prompt original.
    Foque em:
    - Adicionar ou refinar táticas Nmap que o agente deveria ter usado ou priorizado.
    - Melhorar a lógica de decisão para guiar o agente a um output mais completo.
    - Reforçar a busca por informações detalhadas e acionáveis.
    - Corrigir quaisquer deficiências percebidas no comportamento do agente com base no relatório.

    Responda APENAS com o conteúdo COMPLETO do PROMPT DE SISTEMA REFINADO. Não inclua nenhum texto adicional, explicações ou formatação além do próprio prompt.
    """
    print("Propondo refinamento do system prompt...")
    refined_prompt = get_llm_response(refinement_prompt)
    return refined_prompt.strip()

# --- Função de Execução do Nmap ---
def execute_nmap_scan(command):
    if not command or not isinstance(command, str) or not re.match(r"^nmap", command.strip(), re.IGNORECASE):
        raise ValueError(f"Comando Nmap inválido ou vazio fornecido: '{command}'")
    command_to_run = command.strip()
    print(f"Executando comando: {command_to_run}")
    
    process = None # Initialize process to None
    full_output = []
    try:
        process = subprocess.Popen(command_to_run, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Read stdout and stderr in real-time
        while True:
            stdout_line = process.stdout.readline()
            stderr_line = process.stderr.readline()

            if stdout_line:
                yield f"stdout: {stdout_line}" # Yield for real-time streaming
                full_output.append(stdout_line)
            if stderr_line:
                yield f"stderr: {stderr_line}" # Yield for real-time streaming
                full_output.append(stderr_line)

            if not stdout_line and not stderr_line and process.poll() is not None:
                break
        
        # Wait for the process to terminate and get the final return code
        process.wait(timeout=300) # Add a timeout for the wait

        if process.returncode != 0:
            error_output = f"Nmap falhou com código de erro {process.returncode}.\nOutput:\n{''}\nErro:\n{''}"
            raise RuntimeError(error_output)
        
        yield f"complete: {''.join(full_output)}" # Yield final complete output
    except subprocess.TimeoutExpired:
        if process:
            process.kill() # Terminate the process if timeout occurs
        yield f"error: O comando '{command_to_run}' demorou demais para executar (timeout de 300s)."
        raise RuntimeError(f"O comando '{command_to_run}' demorou demais para executar (timeout de 300s).")
    except Exception as e:
        if process:
            process.kill()
        yield f"error: Erro inesperado ao executar Nmap: {e}"
        raise RuntimeError(f"Erro inesperado ao executar Nmap: {e}")


def analyze_nmap_output(raw_output):
    """
    Analisa a saída de texto bruta do Nmap e extrai informações estruturadas.
    Retorna um dicionário com portas abertas, serviços, versões, etc.
    """
    analyzed_data = {
        "host_status": "unknown",
        "open_ports": [],
        "os_detection": "unknown",
        "services": []
    }

    # Host status
    if "Host is up" in raw_output:
        analyzed_data["host_status"] = "up"
    elif "Host seems down" in raw_output:
        analyzed_data["host_status"] = "down"
    elif "Nmap scan report for" in raw_output:
        analyzed_data["host_status"] = "up" # Assume up if report exists

    # Open ports and services
    port_pattern = re.compile(r"(\d+)/tcp\s+(open|filtered|closed)\s+([\w-]+)\s*(.*)")
    for line in raw_output.splitlines():
        match = port_pattern.search(line)
        if match:
            port = match.group(1)
            state = match.group(2)
            service = match.group(3)
            version_info = match.group(4).strip()

            if state == "open":
                analyzed_data["open_ports"].append(int(port))
                service_details = {"port": int(port), "service": service, "state": state}
                if version_info:
                    service_details["version"] = version_info
                analyzed_data["services"].append(service_details)

    # OS detection (basic)
    os_pattern = re.compile(r"OS details: (.*)")
    os_match = os_pattern.search(raw_output)
    if os_match:
        analyzed_data["os_detection"] = os_match.group(1).strip()
    
    # More detailed OS detection from Nmap's "Service and OS detection" section
    os_details_pattern = re.compile(r"Running: (.*?)\n")
    os_details_match = os_details_pattern.search(raw_output)
    if os_details_match:
        analyzed_data["os_detection"] = os_details_match.group(1).strip()


    return analyzed_data

# --- Endpoint e Lógica do Modo Autônomo ---
@app.route('/autonomous_scan', methods=['POST'])
def autonomous_scan_route():
    data = request.json
    if not data or 'target' not in data:
        return jsonify({"error": "Request inválido. JSON com a chave 'target' é esperado."}), 400

    target = data.get('target')
    model = 'llama' # Forçando o uso exclusivo do modelo LLaMA

    if not target:
        return jsonify({"error": "O campo 'target' é obrigatório."}), 400

    try:
        system_prompt = load_system_prompt()
        scan_history = []
        next_command = None # O primeiro comando será gerado pelo LLM

        # Initialize final_report before the loop
        final_report = {
            "model_used": model,
            "target": target,
            "mission_summary": [] # Will be updated with scan_history later
        }

        for i in range(MAX_AUTONOMOUS_ITERATIONS):
            print(f"--- Iteração Autônoma {i+1}/{MAX_AUTONOMOUS_ITERATIONS} covered by the LLM ---")

            if next_command is None:
                # Se for a primeira iteração, peça ao LLM para gerar o comando inicial
                initial_command_prompt = f"{system_prompt}\n\n--- ALVO ---\n{target}\n\n--- SUA TAREFA ---\nVocê está iniciando uma nova missão de reconhecimento. Com base no alvo fornecido, gere o comando Nmap inicial mais adequado para começar a investigação. Responda APENAS com o comando Nmap."
                next_command = get_llm_response(initial_command_prompt).strip().replace('```', '').replace('bash', "'")
                if not next_command.lower().startswith('nmap'):
                    return jsonify({"error": "O LLM não gerou um comando Nmap válido para iniciar a missão."}), 500

            raw_text_output = ""
            status = "success"
            try:
                raw_text_output = execute_nmap_scan(next_command)
            except (RuntimeError, ValueError) as e:
                print(f"ERRO no scan: {e}")
                raw_text_output = str(e)
                status = "error"
            
            image_b64 = generate_image_from_text(raw_text_output, next_command)
            analyzed_output = analyze_nmap_output(raw_text_output)
            
            scan_history.append({
                "step": i + 1,
                "command_executed": next_command,
                "status": status,
                "raw_output_for_llm": raw_text_output,
                "analyzed_output": analyzed_output, # Adiciona o output analisado
                "output_image_base64": image_b64
            })

            decision_prompt = f"{system_prompt}\n\n--- HISTÓRICO DA INVESTIGAÇÃO ATÉ AGORA ---\n{json.dumps([{'command': s.get('command_executed', ''), 'analyzed': s.get('analyzed_output', {})} for s in scan_history])}\n\n--- SUA TAREFA ---\nCom base no histórico, decida o próximo passo. Responda APENAS com a palavra 'COMPLETE' se a investigação for suficiente, ou APENAS com o próximo comando Nmap a ser executado."

            decision = get_llm_response(decision_prompt).strip().replace('```', '').replace('bash', "'")

            if decision.upper() == 'COMPLETE' or not decision.lower().startswith('nmap'):
                print("Agente decidiu completar a missão.")
                
                # Update final_report's mission_summary before calling refine_system_prompt
                final_report["mission_summary"] = scan_history
                
                # Propor refinamento do system prompt após a missão
                print("\n--- PROPOSTA DE REFINAMENTO DO SYSTEM PROMPT ---")
                current_system_prompt = load_system_prompt()
                proposed_new_prompt = refine_system_prompt(current_system_prompt, final_report)
                
                if proposed_new_prompt and proposed_new_prompt != current_system_prompt:
                    print("\n--- NOVO PROMPT APLICADO AUTOMATICAMENTE ---")
                    print(proposed_new_prompt)
                    print("\n--- FIM DO NOVO PROMPT ---")
                    save_system_prompt(proposed_new_prompt) # Automatically save the new prompt
                    print("System prompt atualizado automaticamente.")
                else:
                    print("Nenhuma proposta de refinamento significativa para o system prompt.")
                
                break
            else:
                next_command = decision
        
        # Ensure final_report's mission_summary is updated even if loop finishes without breaking
        final_report["mission_summary"] = scan_history
        
        save_mission_report(target, final_report)
        
        return jsonify(final_report)
    except Exception as e:
        print(f"ERRO FATAL NA ROTA AUTONOMOUS_SCAN: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Erro interno do servidor: {e}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
