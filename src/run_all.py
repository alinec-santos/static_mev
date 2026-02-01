# /home/aline/static_mev/src/run_all.py
import subprocess
import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONTRACTS_DIR = os.path.join(BASE_DIR, "contracts")
OUTPUT_JSON = os.path.join(BASE_DIR, "src", "resultado_mev.json")

print(" Rodando Slither com detector customizado")
print(f" Contratos: {CONTRACTS_DIR}")
print(f" Detector: generic-slippage")
print(f" Saída: {OUTPUT_JSON}")

cmd = [
    "slither",
    CONTRACTS_DIR,
    "--detect", "generic-slippage",
    "--json", OUTPUT_JSON,
    "--filter-paths", "node_modules,test"
]

subprocess.run(cmd, check=True)

print(" Análise finalizada com sucesso!")
