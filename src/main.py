import os
import sys
import subprocess
from solcx import install_solc

# =========================
# CONFIGURAÇÕES
# =========================
VENV_DIR = "venv"
SOLC_VERSION = "0.8.24"
CONTRACT = "/home/aline/fuzzing/src/contracts/reentrancy/EtherStore.sol"

# Caminho onde o py-solc-x instala o solc
SOLC_PATH = os.path.expanduser(f"~/.solcx/solc-v{SOLC_VERSION}")

# =========================
# FUNÇÕES AUXILIARES
# =========================
def run(cmd, check=True):
    print(">>", " ".join(cmd))
    return subprocess.run(cmd, check=check)

def venv_bin(tool):
    return os.path.join(VENV_DIR, "bin", tool)

# =========================
# 1. CRIAR VENV (se não existir)
# =========================
if not os.path.exists(VENV_DIR):
    run([sys.executable, "-m", "venv", VENV_DIR])

# =========================
# 2. INSTALAR DEPENDÊNCIAS NO VENV
# =========================
run([venv_bin("pip"), "install", "--upgrade", "pip"])
run([
    venv_bin("pip"),
    "install",
    "web3",
    "py-solc-x",
    "slither-analyzer"
])

# =========================
# 3. INSTALAR SOLC
# =========================
install_solc(SOLC_VERSION)

if not os.path.exists(SOLC_PATH):
    raise RuntimeError(f" solc não encontrado em {SOLC_PATH}")

print(f" solc {SOLC_VERSION} encontrado em {SOLC_PATH}")

# (opcional) validar versão do solc
run([SOLC_PATH, "--version"])

# =========================
# 4. RODAR SLITHER
# =========================
print(" Executando Slither...")

result = subprocess.run([
    venv_bin("slither"),
    CONTRACT,
    "--solc",
    SOLC_PATH
])

# =========================
# 5. TRATAR RESULTADO
# =========================
if result.returncode == 0:
    print(" Slither executado — nenhum problema encontrado")
else:
    print(" Slither executado — vulnerabilidades encontradas (comportamento esperado)")

print(" Script finalizado com sucesso")
