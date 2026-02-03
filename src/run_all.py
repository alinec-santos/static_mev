import os
import subprocess
import json
import time
import uuid
import re
from pathlib import Path
from collections import defaultdict

# =========================
# CONFIGURAÇÕES
# =========================
BASE_DIR = Path(__file__).resolve().parent
CONTRACTS_DIR = BASE_DIR.parent / "contracts"

OUTPUT_FILE = BASE_DIR / "slither_results_detectorCustomizado.json"
SUMMARY_FILE = BASE_DIR / "vulnerability_summary_detectorCustomizado.json"

DETECTOR = "generic-slippage"
SOLC_BASE_DIR = Path.home() / ".solcx"

INSTALLED_SOLC = set()

# =========================
# UTIL
# =========================
def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)

def slither_bin():
    return BASE_DIR / "venv" / "bin" / "slither"

# =========================
# SOLC
# =========================
def extract_pragma(contract):
    try:
        with open(contract, "r", errors="ignore") as f:
            for _ in range(30):
                line = f.readline()
                if "pragma solidity" in line:
                    return line.strip()
    except:
        pass
    return None

def select_solc_version(pragma):
    if not pragma:
        return "0.8.24"

    versions = re.findall(r"\d+\.\d+\.\d+", pragma)
    if not versions:
        return "0.8.24"

    if "^" not in pragma and ">=" not in pragma:
        return versions[0]

    major_minor = versions[0].rsplit(".", 1)[0]
    if major_minor.startswith("0.5"):
        return "0.5.17"
    if major_minor.startswith("0.6"):
        return "0.6.12"
    if major_minor.startswith("0.7"):
        return "0.7.6"
    if major_minor.startswith("0.8"):
        return "0.8.24"

    return versions[0]

def ensure_solc(version):
    if version in INSTALLED_SOLC:
        return SOLC_BASE_DIR / f"solc-v{version}"

    from solcx import install_solc
    install_solc(version)

    solc_path = SOLC_BASE_DIR / f"solc-v{version}"
    if not solc_path.exists():
        raise RuntimeError(f"solc {version} não encontrado")

    INSTALLED_SOLC.add(version)
    return solc_path

# =========================
# SLITHER (ARQUIVO)
# =========================
def analyze_contract(contract_path: Path):
    result = {
        "contract": str(contract_path),
        "status": None,
        "solc_version": None,
        "vulnerabilities": [],
        "execution_time": 0,
        "error": None,
    }

    start = time.perf_counter()
    json_out = f"/tmp/slither_{uuid.uuid4().hex}.json"

    try:
        pragma = extract_pragma(contract_path)
        solc_version = select_solc_version(pragma)
        solc_path = ensure_solc(solc_version)

        result["solc_version"] = solc_version

        cmd = [
            str(slither_bin()),
            str(contract_path),
            "--detect", DETECTOR,
            "--solc", str(solc_path),
            "--json", json_out
        ]

        completed = run(cmd)
        stderr = completed.stderr or ""

        result["execution_time"] = time.perf_counter() - start

        if "Invalid solc compilation" in stderr or "Traceback" in stderr:
            result["status"] = "FAILED"
            result["error"] = stderr.strip()
            return result

        result["status"] = "SUCCESS"

        if os.path.exists(json_out):
            with open(json_out) as f:
                data = json.load(f)

            detectors = data.get("results", {}).get("detectors", [])
            for d in detectors:
                result["vulnerabilities"].append({
                    "check": d.get("check"),
                    "impact": d.get("impact"),
                    "confidence": d.get("confidence"),
                    "description": d.get("description"),
                })

        return result

    except Exception as e:
        result["status"] = "FAILED"
        result["error"] = str(e)
        result["execution_time"] = time.perf_counter() - start
        return result

    finally:
        if os.path.exists(json_out):
            os.remove(json_out)

# =========================
# MAIN
# =========================
def main():
    contracts = list(CONTRACTS_DIR.rglob("*.sol"))

    overall = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "total_contracts": len(contracts),
            "successful": 0,
            "failed": 0,
            "with_vulnerabilities": 0,
            "without_vulnerabilities": 0,
            "total_execution_time": 0,
        },
        "contracts": []
    }

    vuln_counter = defaultdict(int)

    print(f" Encontrados {len(contracts)} contratos\n")

    for i, contract in enumerate(contracts, 1):
        print(f"[{i}/{len(contracts)}] {contract}")
        res = analyze_contract(contract)
        overall["contracts"].append(res)
        overall["summary"]["total_execution_time"] += res["execution_time"]

        if res["status"] == "SUCCESS":
            overall["summary"]["successful"] += 1
            if res["vulnerabilities"]:
                overall["summary"]["with_vulnerabilities"] += 1
                for v in res["vulnerabilities"]:
                    vuln_counter[v["check"]] += 1
            else:
                overall["summary"]["without_vulnerabilities"] += 1
        else:
            overall["summary"]["failed"] += 1

    with open(OUTPUT_FILE, "w") as f:
        json.dump(overall, f, indent=2)

    summary = {
        "total_distinct_vulnerabilities": len(vuln_counter),
        "vulnerability_counts": dict(
            sorted(vuln_counter.items(), key=lambda x: x[1], reverse=True)
        )
    }

    with open(SUMMARY_FILE, "w") as f:
        json.dump(summary, f, indent=2)

    print("\n Análise finalizada")
    print(f" {OUTPUT_FILE}")
    print(f" {SUMMARY_FILE}")

# =========================
if __name__ == "__main__":
    main()
