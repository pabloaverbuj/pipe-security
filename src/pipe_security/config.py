"""
Gestión de dominios y credenciales para pipe-security.
Las credenciales se almacenan en Windows Credential Manager (keyring).
La configuración de dominios se guarda en ~/.pipe-security/config.json.
"""

import json
from pathlib import Path
from typing import Optional

import keyring

APP_NAME = "pipe-security"
CONFIG_DIR = Path.home() / ".pipe-security"
CONFIG_FILE = CONFIG_DIR / "config.json"


class ConfigManager:

    def __init__(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        if not CONFIG_FILE.exists():
            self._write({"domains": [], "active_domain": None})

    def _read(self) -> dict:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)

    def _write(self, data: dict):
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    # ── Dominios ──────────────────────────────────────────────────────────────

    def add_domain(self, name: str, dc: str, domain_fqdn: str, user: str,
                   password: str, port: int = 389, ssl: bool = False):
        data = self._read()
        # Eliminar si ya existe con el mismo nombre
        data["domains"] = [d for d in data["domains"] if d["name"] != name]
        data["domains"].append({
            "name": name,
            "dc": dc,
            "domain_fqdn": domain_fqdn.upper(),
            "user": user,
            "port": port,
            "ssl": ssl,
        })
        # Guardar credencial en Credential Manager
        keyring.set_password(APP_NAME, f"domain:{name}", password)
        self._write(data)

    def list_domains(self) -> list:
        return self._read().get("domains", [])

    def get_domain(self, name: str) -> Optional[dict]:
        for d in self.list_domains():
            if d["name"] == name:
                result = dict(d)
                result["password"] = keyring.get_password(APP_NAME, f"domain:{name}") or ""
                return result
        return None

    def remove_domain(self, name: str):
        data = self._read()
        data["domains"] = [d for d in data["domains"] if d["name"] != name]
        if data.get("active_domain") == name:
            data["active_domain"] = data["domains"][0]["name"] if data["domains"] else None
        keyring.delete_password(APP_NAME, f"domain:{name}")
        self._write(data)

    # ── Dominio activo ────────────────────────────────────────────────────────

    def get_active_domain(self) -> Optional[str]:
        return self._read().get("active_domain")

    def set_active_domain(self, name: str):
        data = self._read()
        data["active_domain"] = name
        self._write(data)

    def get_active_domain_config(self) -> Optional[dict]:
        active = self.get_active_domain()
        if not active:
            return None
        return self.get_domain(active)
