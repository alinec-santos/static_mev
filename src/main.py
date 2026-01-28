import os
import sys
import subprocess
import time
import json
from pathlib import Path
import uuid
import re
from collections import defaultdict

# =========================
# CONFIGURAÇÕES
# =========================
VENV_DIR = "venv"
CONTRACT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "contracts")
OUTPUT_FILE = "slither_results.json"
SUMMARY_FILE = "vulnerability_summary.json"

SOLC_BASE_DIR = os.path.expanduser("~/.solcx")

INSTALLED_SOLC = set()

# =========================
# FUNÇÕES AUXILIARES
# =========================
def run(cmd, check=True, capture_output=False):
    print(">>", " ".join(cmd))
    return subprocess.run(cmd, check=check, capture_output=capture_output, text=True)

def venv_bin(tool):
    return os.path.join(VENV_DIR, "bin", tool)

def find_solidity_files(root_dir):
    solidity_files = []
    root_path = Path(root_dir)

    if not root_path.exists():
        print(f"Diretório não encontrado: {root_dir}")
        return solidity_files

    for file_path in root_path.rglob("*.sol"):
        solidity_files.append(str(file_path))

    print(f"Encontrados {len(solidity_files)} arquivos .sol")
    return solidity_files

# =========================
# PRAGMA + SOLC
# =========================
def extract_pragma_version(contract_path):
    try:
        with open(contract_path, "r", errors="ignore") as f:
            for _ in range(20):
                line = f.readline()
                if not line:
                    break
                if "pragma solidity" in line:
                    return line.strip()
    except:
        pass
    return None

def select_solc_version_from_pragma(pragma_line):
    if pragma_line is None:
        return "0.8.24"

    versions = re.findall(r"\d+\.\d+\.\d+", pragma_line)
    if not versions:
        return "0.8.24"

    if "^" not in pragma_line and ">=" not in pragma_line and "<" not in pragma_line:
        return versions[0]

    major_minor = versions[0].rsplit(".", 1)[0]
    if major_minor.startswith("0.7"):
        return "0.7.6"
    if major_minor.startswith("0.8"):
        return "0.8.24"

    return versions[0]

def ensure_solc_installed(version):
    if version in INSTALLED_SOLC:
        return get_solc_path(version)

    from solcx import install_solc

    print(f"  ⬇ Instalando solc {version} (se necessário)...")
    install_solc(version)

    solc_path = get_solc_path(version)

    if not os.path.exists(solc_path):
        raise RuntimeError(f"solc {version} não encontrado em {solc_path}")

    INSTALLED_SOLC.add(version)
    return solc_path

def get_solc_path(version):
    return os.path.join(SOLC_BASE_DIR, f"solc-v{version}")

# =========================
# SLITHER
# =========================
def analyze_contract_with_slither(contract_path):
    result = {
        'contract': contract_path,
        'execution_status': None,
        'vulnerabilities_found': False,
        'vulnerability_count': 0,
        'vulnerabilities': [],
        'error': None,
        'execution_time': 0,
        'solc_version': None
    }

    start_time = time.perf_counter()
    json_path = f"/tmp/slither_{uuid.uuid4().hex}.json"

    try:
        print(f"\nAnalisando: {os.path.basename(contract_path)}")

        pragma = extract_pragma_version(contract_path)
        solc_version = select_solc_version_from_pragma(pragma)
        solc_path = ensure_solc_installed(solc_version)

        result["solc_version"] = solc_version

        cmd = [
            venv_bin("slither"),
            contract_path,
            "--solc", solc_path,
            "--json", json_path
        ]

        completed = subprocess.run(cmd, capture_output=True, text=True)
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""

        result['execution_time'] = time.perf_counter() - start_time

        fatal_error_signals = [
            "Error: Source file requires different compiler version",
            "Invalid solc compilation",
            "Traceback (most recent call last)",
            "Solidity compilation failed",
        ]

        if any(err in stderr for err in fatal_error_signals):
            result['execution_status'] = "FAILED"
            result['error'] = stderr.strip() or stdout.strip()
            return result

        result['execution_status'] = "SUCCESS"

        if os.path.exists(json_path):
            with open(json_path) as f:
                data = json.load(f)

            detectors = data.get("results", {}).get("detectors", [])

            vulnerabilities = []
            for d in detectors:
                vulnerabilities.append({
                    "check": d.get("check"),
                    "impact": d.get("impact"),
                    "confidence": d.get("confidence"),
                    "description": d.get("description"),
                })

            result['vulnerabilities'] = vulnerabilities
            result['vulnerability_count'] = len(vulnerabilities)
            result['vulnerabilities_found'] = len(vulnerabilities) > 0
            return result

        vuln_count = stdout.count("Detector:")
        result['vulnerabilities_found'] = vuln_count > 0
        result['vulnerability_count'] = vuln_count
        return result

    except Exception as e:
        result['execution_status'] = "FAILED"
        result['error'] = str(e)
        result['execution_time'] = time.perf_counter() - start_time
        return result

    finally:
        if os.path.exists(json_path):
            os.remove(json_path)

# =========================
# SETUP
# =========================
def setup_environment():
    print("=" * 60)
    print("CONFIGURAÇÃO DO AMBIENTE DE ANÁLISE")
    print("=" * 60)

    if not os.path.exists(VENV_DIR):
        run([sys.executable, "-m", "venv", VENV_DIR])
    else:
        print("✓ venv já existe")

    run([venv_bin("pip"), "install", "--upgrade", "pip"])
    run([venv_bin("pip"), "install", "web3", "py-solc-x", "slither-analyzer", "setuptools"])

# =========================
# MAIN
# =========================
def main():
    setup_environment()

    vuln_counter = defaultdict(int)

    overall_results = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'summary': {
            'total_contracts': 0,
            'successful': 0,
            'failed': 0,
            'with_vulnerabilities': 0,
            'without_vulnerabilities': 0,
            'total_execution_time': 0
        },
        'contracts': []
    }

    print("\nINICIANDO ANÁLISE DOS CONTRATOS\n")

    contract_files = find_solidity_files(CONTRACT_DIR)

    if not contract_files:
        print("Nenhum contrato encontrado.")
        return

    overall_results['summary']['total_contracts'] = len(contract_files)

    for i, contract_file in enumerate(contract_files, 1):
        print(f"[{i}/{len(contract_files)}] ", end="")
        result = analyze_contract_with_slither(contract_file)

        overall_results['contracts'].append(result)
        overall_results['summary']['total_execution_time'] += result['execution_time']

        if result['execution_status'] == "SUCCESS":
            overall_results['summary']['successful'] += 1

            if result['vulnerabilities_found']:
                overall_results['summary']['with_vulnerabilities'] += 1

                for v in result['vulnerabilities']:
                    check = v.get("check", "unknown")
                    vuln_counter[check] += 1

            else:
                overall_results['summary']['without_vulnerabilities'] += 1
        else:
            overall_results['summary']['failed'] += 1

    print("\nSalvando resultados...")

    with open(OUTPUT_FILE, "w") as f:
        json.dump(overall_results, f, indent=2)

    vuln_summary_sorted = dict(sorted(vuln_counter.items(), key=lambda x: x[1], reverse=True))

    summary_data = {
        "total_distinct_vulnerabilities": len(vuln_summary_sorted),
        "vulnerability_counts": vuln_summary_sorted
    }

    with open(SUMMARY_FILE, "w") as f:
        json.dump(summary_data, f, indent=2)

    print("\nResumo final:")
    s = overall_results['summary']
    print(f"Total contratos: {s['total_contracts']}")
    print(f"Sucesso: {s['successful']}")
    print(f"Falha: {s['failed']}")
    print(f"Com vulnerabilidades: {s['with_vulnerabilities']}")
    print(f"Sem vulnerabilidades: {s['without_vulnerabilities']}")
    print(f"Tempo total: {s['total_execution_time']:.2f}s")

    print("\nTop vulnerabilidades:")
    for k, v in list(vuln_summary_sorted.items())[:10]:
        print(f"  {k}: {v}")

# =========================
if __name__ == "__main__":
    main()
