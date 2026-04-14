"""
Ejecutor de PowerShell para pipe-security.
Corre comandos PS localmente con timeout y manejo de errores.
"""

import json
import subprocess
import tempfile
import os
from typing import Any


def run_ps(script: str, timeout: int = 30) -> Any:
    """
    Ejecuta un script PowerShell local y retorna el resultado parseado.
    El script debe terminar con | ConvertTo-Json -Depth 10 para retornar JSON.
    Si no hay ConvertTo-Json, retorna el output como string.
    """
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-Command", script,
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if result.returncode != 0 and not stdout:
            return {"error": stderr or "PowerShell returned non-zero exit code", "rc": result.returncode}

        if not stdout:
            return {"result": "ok", "output": ""}

        # Intentar parsear como JSON
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            # Retornar como texto si no es JSON válido
            return {"raw": stdout}

    except subprocess.TimeoutExpired:
        return {"error": f"Timeout ({timeout}s) ejecutando PowerShell"}
    except FileNotFoundError:
        return {"error": "powershell.exe no encontrado. ¿Estás en Windows?"}
    except Exception as e:
        return {"error": str(e)}


def run_ps_raw(script: str, timeout: int = 30) -> str:
    """Ejecuta PS y retorna el output crudo como string."""
    result = run_ps(script, timeout)
    if isinstance(result, dict) and "raw" in result:
        return result["raw"]
    return json.dumps(result, ensure_ascii=False)


def check_module(module_name: str) -> bool:
    """Verifica si un módulo de PowerShell está disponible."""
    result = run_ps(f"if (Get-Module -ListAvailable -Name '{module_name}') {{ 'yes' }} else {{ 'no' }}")
    if isinstance(result, dict) and "raw" in result:
        return result["raw"].strip().lower() == "yes"
    return False


def check_ad_module() -> bool:
    """Verifica si el módulo de Active Directory está disponible."""
    return check_module("ActiveDirectory")


def install_ad_module_instructions() -> str:
    return (
        "El módulo de Active Directory no está instalado.\n"
        "Para instalarlo ejecutá en PowerShell como Administrador:\n\n"
        "  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0\n\n"
        "O en sistemas más viejos:\n"
        "  Install-WindowsFeature RSAT-AD-PowerShell\n"
    )
