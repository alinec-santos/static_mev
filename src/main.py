import os
import sys
import subprocess
import time
import json
from pathlib import Path

# =========================
# CONFIGURAÇÕES
# =========================
VENV_DIR = "venv"
SOLC_VERSION = "0.8.24"
CONTRACT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "contracts")
OUTPUT_FILE = "slither_results.json"

# Caminho onde o py-solc-x instala o solc
SOLC_PATH = os.path.expanduser(f"~/.solcx/solc-v{SOLC_VERSION}")

# Variável global para psutil (será definida depois da instalação)
psutil = None

# =========================
# FUNÇÕES AUXILIARES
# =========================
def run(cmd, check=True, capture_output=False):
    """Executa comando e retorna resultado"""
    print(">>", " ".join(cmd))
    return subprocess.run(cmd, check=check, capture_output=capture_output, text=True)

def venv_bin(tool):
    return os.path.join(VENV_DIR, "bin", tool)

def get_process_metrics(pid):
    """Obtém métricas de CPU e RAM de um processo"""
    global psutil
    
    if psutil is None:
        # Tenta importar psutil se ainda não foi importado
        try:
            import psutil as psutil_module
            psutil = psutil_module
        except ImportError:
            #print("  Aviso: psutil não disponível, pulando métricas de processo")
            return None
    
    try:
        process = psutil.Process(pid)
        cpu_times = process.cpu_times()
        memory_info = process.memory_info()
        
        return {
            'user_cpu_time': cpu_times.user,
            'system_cpu_time': cpu_times.system,
            'total_cpu_time': cpu_times.user + cpu_times.system,
            'ram_rss_mb': memory_info.rss / 1024 / 1024,  # MB
            'ram_vms_mb': memory_info.vms / 1024 / 1024   # MB
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

def find_solidity_files(root_dir):
    """Encontra todos os arquivos .sol recursivamente"""
    solidity_files = []
    root_path = Path(root_dir)
    
    if not root_path.exists():
        print(f"Diretório não encontrado: {root_dir}")
        return solidity_files
    
    for file_path in root_path.rglob("*.sol"):
        solidity_files.append(str(file_path))
    
    print(f"Encontrados {len(solidity_files)} arquivos .sol")
    return solidity_files

def analyze_contract_with_slither(contract_path, slither_bin, solc_path):
    """Analisa um contrato com Slither e coleta métricas"""
    result = {
        'contract': contract_path,
        'execution_status': None,
        'vulnerabilities_found': False,
        'vulnerability_count': 0,
        'error': None,
        'output': None,
        'metrics': {},
        'execution_time': 0,
        'cpu_time_estimated': 0  # Vamos estimar se não conseguir medir
    }
    
    start_time = time.time()
    
    try:
        # Executa slither e captura a saída
        cmd = [slither_bin, contract_path, "--solc", solc_path]
        print(f"\nAnalisando: {os.path.basename(contract_path)}")
        
        # Executa o processo
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        pid = process.pid
        
        # Aguarda conclusão
        stdout, stderr = process.communicate()
        execution_time = time.time() - start_time
        
        # Tenta coletar métricas após a execução
        metrics = None
        if pid:
            metrics = get_process_metrics(pid)
        
        # Atualiza resultados
        result['execution_time'] = execution_time
        result['metrics'] = metrics if metrics else {}
        result['output'] = stdout + stderr
        
        # Estima tempo de CPU se não conseguiu medir
        if metrics and metrics.get('total_cpu_time', 0) > 0:
            result['cpu_time_estimated'] = metrics['total_cpu_time']
        else:
            # Estimativa: assume que usou 1 core por 80% do tempo de execução
            result['cpu_time_estimated'] = execution_time * 0.8
        
        # Determina status baseado no código de retorno
        if process.returncode == 0:
            result['execution_status'] = 'SUCCESS'
            result['vulnerabilities_found'] = False
            print(f"  Status: Sucesso (sem vulnerabilidades)")
        elif process.returncode == 1:
            result['execution_status'] = 'SUCCESS_WITH_ISSUES'
            result['vulnerabilities_found'] = True
            print(f"  Status: Sucesso (vulnerabilidades encontradas)")
        else:
            result['execution_status'] = 'FAILED'
            result['error'] = f"Slither falhou com código {process.returncode}"
            print(f"  Status: Falha (código {process.returncode})")
        
        # Mostra métricas
        print(f"  Tempo execução: {execution_time:.2f}s")
        if metrics:
            print(f"  Tempo CPU: {metrics.get('total_cpu_time', 0):.2f}s")
            print(f"  RAM usada: {metrics.get('ram_rss_mb', 0):.1f}MB")
        else:
            print(f"  Tempo CPU estimado: {result['cpu_time_estimated']:.2f}s")
        
        # Verifica se há vulnerabilidades na saída
        if not result['vulnerabilities_found']:
            if 'INFO:Detectors:' in stdout or 'Reference:' in stdout:
                result['vulnerabilities_found'] = True
        
    except FileNotFoundError as e:
        result['execution_status'] = 'FAILED'
        result['error'] = f"Arquivo não encontrado: {e}"
        print(f"  Status: Falha (arquivo não encontrado)")
    except Exception as e:
        result['execution_status'] = 'FAILED'
        result['error'] = str(e)
        print(f"  Status: Falha (erro: {e})")
    
    return result

def install_dependencies():
    """Instala todas as dependências necessárias no venv"""
    print("\n2. Instalando dependências...")
    
    # Lista de dependências
    dependencies = [
        "web3",
        "py-solc-x",
        "slither-analyzer",
        "psutil"
    ]
    
    # Atualiza pip primeiro
    run([venv_bin("pip"), "install", "--upgrade", "pip"])
    
    # Instala todas as dependências de uma vez (mais eficiente)
    print(f"  Instalando {len(dependencies)} dependências...")
    run([venv_bin("pip"), "install"] + dependencies)
    
    print("  Todas as dependências instaladas com sucesso")
    
    # Agora podemos importar psutil
    global psutil
    try:
        import psutil as psutil_module
        psutil = psutil_module
        print("  psutil importado com sucesso")
    except ImportError:
        print("  AVISO: psutil não pôde ser importado mesmo após instalação")

def setup_environment():
    """Configura todo o ambiente antes de começar as análises"""
    print("=" * 60)
    print("CONFIGURAÇÃO DO AMBIENTE DE ANÁLISE")
    print("=" * 60)
    
    # =========================
    # 1. CRIAR VENV (se não existir)
    # =========================
    print("\n1. Configurando ambiente virtual...")
    if not os.path.exists(VENV_DIR):
        run([sys.executable, "-m", "venv", VENV_DIR])
        print(f"  ✓ Ambiente virtual criado em: {VENV_DIR}")
    else:
        print(f"  ✓ Ambiente virtual já existe em: {VENV_DIR}")
    
    # =========================
    # 2. INSTALAR DEPENDÊNCIAS NO VENV
    # =========================
    install_dependencies()
    
    # =========================
    # 3. INSTALAR SOLC
    # =========================
    print("\n3. Instalando solc...")
    try:
        # Importa solcx só depois que as dependências estão instaladas
        from solcx import install_solc
        install_solc(SOLC_VERSION)
        if not os.path.exists(SOLC_PATH):
            raise RuntimeError(f"solc não encontrado em {SOLC_PATH}")
        print(f"  ✓ solc {SOLC_VERSION} instalado em {SOLC_PATH}")
        
        # Testa o solc
        result = subprocess.run([SOLC_PATH, "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"  ✓ Solc testado: {result.stdout.split()[1]}")
    except ImportError:
        print("  ✗ Erro: py-solc-x não está instalado corretamente")
        sys.exit(1)
    except Exception as e:
        print(f"  ✗ Erro ao instalar solc: {e}")
        sys.exit(1)
    
    return venv_bin("slither")

# =========================
# EXECUÇÃO PRINCIPAL
# =========================
def main():
    # PRIMEIRO: Configurar todo o ambiente
    slither_bin = setup_environment()
    
    # SEGUNDO: Agora que tudo está instalado, podemos começar as análises
    
    # Inicializar estrutura de resultados
    overall_results = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'config': {
            'solc_version': SOLC_VERSION,
            'contract_dir': CONTRACT_DIR,
            'solc_path': SOLC_PATH
        },
        'summary': {
            'total_contracts': 0,
            'successful': 0,
            'failed': 0,
            'with_vulnerabilities': 0,
            'without_vulnerabilities': 0,
            'total_execution_time': 0,
            'total_cpu_time_measured': 0,
            'total_cpu_time_estimated': 0,
            'max_ram_usage_mb': 0
        },
        'contracts': []
    }
    
    print("\n" + "=" * 60)
    print("INICIANDO ANÁLISE DOS CONTRATOS")
    print("=" * 60)
    
    # =========================
    # 4. ENCONTRAR TODOS OS CONTRATOS
    # =========================
    print("\n4. Procurando contratos Solidity...")
    contract_files = find_solidity_files(CONTRACT_DIR)
    
    if not contract_files:
        print("Nenhum contrato .sol encontrado. Encerrando.")
        sys.exit(0)
    
    overall_results['summary']['total_contracts'] = len(contract_files)
    
    # =========================
    # 5. ANALISAR CADA CONTRATO
    # =========================
    print(f"\n5. Analisando {len(contract_files)} contratos...")
    
    total_cpu_measured = 0
    total_cpu_estimated = 0
    max_ram_usage = 0
    
    for i, contract_file in enumerate(contract_files, 1):
        print(f"\n[{i}/{len(contract_files)}] ", end="")
        
        # Analisa o contrato
        result = analyze_contract_with_slither(contract_file, slither_bin, SOLC_PATH)
        
        # Atualiza estatísticas gerais
        overall_results['contracts'].append(result)
        overall_results['summary']['total_execution_time'] += result['execution_time']
        
        if result['execution_status'] in ['SUCCESS', 'SUCCESS_WITH_ISSUES']:
            overall_results['summary']['successful'] += 1
            if result['vulnerabilities_found']:
                overall_results['summary']['with_vulnerabilities'] += 1
            else:
                overall_results['summary']['without_vulnerabilities'] += 1
        else:
            overall_results['summary']['failed'] += 1
        
        # Acumula métricas
        if result['metrics']:
            cpu_time = result['metrics'].get('total_cpu_time', 0)
            ram_usage = result['metrics'].get('ram_rss_mb', 0)
            
            total_cpu_measured += cpu_time
            max_ram_usage = max(max_ram_usage, ram_usage)
        
        total_cpu_estimated += result['cpu_time_estimated']
        
        # Progresso a cada 50 contratos
        if i % 50 == 0:
            print(f"\n{'='*50}")
            print(f"PROGRESSO: {i}/{len(contract_files)} contratos")
            print(f"Tempo total: {overall_results['summary']['total_execution_time']:.1f}s")
            print(f"CPU medida: {total_cpu_measured:.1f}s")
            print(f"{'='*50}")
    
    # =========================
    # 6. CALCULAR ESTATÍSTICAS FINAIS
    # =========================
    overall_results['summary']['total_cpu_time_measured'] = total_cpu_measured
    overall_results['summary']['total_cpu_time_estimated'] = total_cpu_estimated
    overall_results['summary']['max_ram_usage_mb'] = max_ram_usage
    
    # =========================
    # 7. SALVAR RESULTADOS
    # =========================
    print("\n6. Salvando resultados...")
    try:
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(overall_results, f, indent=2, default=str)
        print(f"  ✓ Resultados salvos em: {OUTPUT_FILE}")
    except Exception as e:
        print(f"  ✗ Erro ao salvar resultados: {e}")
    
    # =========================
    # 8. RESUMO FINAL
    # =========================
    print("\n" + "=" * 60)
    print("RESUMO FINAL DA EXECUÇÃO")
    print("=" * 60)
    summary = overall_results['summary']
    print(f"Total de contratos analisados: {summary['total_contracts']}")
    print(f"Análises bem-sucedidas: {summary['successful']}")
    print(f"Análises com falha: {summary['failed']}")
    print(f"Contratos com vulnerabilidades: {summary['with_vulnerabilities']}")
    print(f"Contratos sem vulnerabilidades: {summary['without_vulnerabilities']}")
    print(f"\nMÉTRICAS DE PERFORMANCE:")
    print(f"Tempo total de execução: {summary['total_execution_time']:.2f} segundos")
    
    if total_cpu_measured > 0:
        print(f"Tempo total de CPU (medido): {summary['total_cpu_time_measured']:.2f} segundos")
        efficiency = (summary['total_cpu_time_measured'] / summary['total_execution_time']) * 100
        print(f"Eficiência de CPU: {efficiency:.1f}%")
    
    print(f"Tempo total de CPU (estimado): {summary['total_cpu_time_estimated']:.2f} segundos")
    print(f"Uso máximo de RAM: {summary['max_ram_usage_mb']:.2f} MB")
    
    # Salva também um resumo em formato de texto
    with open("slither_summary.txt", "w") as f:
        f.write("RESUMO DA ANÁLISE SLITHER\n")
        f.write("=" * 50 + "\n")
        f.write(f"Data: {overall_results['timestamp']}\n")
        f.write(f"Total contratos: {summary['total_contracts']}\n")
        f.write(f"Sucesso: {summary['successful']}\n")
        f.write(f"Falha: {summary['failed']}\n")
        f.write(f"Com vulnerabilidades: {summary['with_vulnerabilities']}\n")
        f.write(f"Sem vulnerabilidades: {summary['without_vulnerabilities']}\n")
        f.write(f"Tempo total execução: {summary['total_execution_time']:.2f}s\n")
        f.write(f"Tempo total CPU (medido): {summary['total_cpu_time_measured']:.2f}s\n")
        f.write(f"Tempo total CPU (estimado): {summary['total_cpu_time_estimated']:.2f}s\n")
        f.write(f"RAM máxima: {summary['max_ram_usage_mb']:.2f} MB\n")
    
    print("\nScript finalizado com sucesso!")

if __name__ == "__main__":
    main()