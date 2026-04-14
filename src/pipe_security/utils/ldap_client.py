"""
Cliente LDAP para consultas a Active Directory.
Soporta autenticación NTLM (usuario/password) y Kerberos (dominio joined).
"""

from typing import Any, Optional
import ldap3
from ldap3 import Server, Connection, ALL, NTLM, SASL, KERBEROS, SUBTREE
from ldap3.core.exceptions import LDAPException


class LDAPClient:

    def __init__(self, domain_config: dict):
        self.dc = domain_config["dc"]
        self.domain_fqdn = domain_config["domain_fqdn"].upper()
        self.user = domain_config["user"]
        self.password = domain_config.get("password", "")
        self.port = domain_config.get("port", 389)
        self.ssl = domain_config.get("ssl", False)
        self._conn: Optional[Connection] = None
        self._base_dn = self._fqdn_to_dn(self.domain_fqdn)

    def _fqdn_to_dn(self, fqdn: str) -> str:
        return ",".join(f"DC={part}" for part in fqdn.split("."))

    def _connect(self) -> Connection:
        server = Server(
            self.dc,
            port=self.port,
            use_ssl=self.ssl,
            get_info=ALL,
            connect_timeout=10,
        )
        # Normalizar usuario para NTLM: DOMAIN\user o user@domain
        if "@" in self.user:
            ntlm_user = self.user
        else:
            short_domain = self.domain_fqdn.split(".")[0]
            ntlm_user = f"{short_domain}\\{self.user}"

        conn = Connection(
            server,
            user=ntlm_user,
            password=self.password,
            authentication=NTLM,
            auto_bind=True,
            receive_timeout=30,
        )
        return conn

    def _get_conn(self) -> Connection:
        if self._conn is None or not self._conn.bound:
            self._conn = self._connect()
        return self._conn

    def test_connection(self) -> dict:
        conn = self._get_conn()
        info = conn.server.info
        return {
            "domain": self.domain_fqdn,
            "dc": self.dc,
            "bound": conn.bound,
            "functional_level": str(info.other.get("domainFunctionality", ["N/A"])[0]) if info else "N/A",
        }

    def search(self, search_filter: str, attributes: list,
               search_base: str = None, size_limit: int = 1000) -> list:
        conn = self._get_conn()
        base = search_base or self._base_dn
        conn.search(
            search_base=base,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=attributes,
            size_limit=size_limit,
        )
        results = []
        for entry in conn.entries:
            row = {"dn": entry.entry_dn}
            for attr in attributes:
                if attr == "*":
                    continue
                try:
                    val = getattr(entry, attr, None)
                    if val is None:
                        row[attr] = None
                    elif val.value is None:
                        row[attr] = None
                    elif isinstance(val.value, list):
                        row[attr] = [str(v) for v in val.value]
                    else:
                        row[attr] = str(val.value)
                except Exception:
                    row[attr] = None
            results.append(row)
        return results

    def get_domain_info(self) -> dict:
        conn = self._get_conn()
        conn.search(
            search_base=self._base_dn,
            search_filter="(objectClass=domain)",
            search_scope=ldap3.BASE,
            attributes=["name", "distinguishedName", "whenCreated",
                        "domainFunctionality", "ms-DS-MachineAccountQuota"],
        )
        if conn.entries:
            e = conn.entries[0]
            return {
                "name": str(e.name.value) if e.name else self.domain_fqdn,
                "dn": e.entry_dn,
                "created": str(e.whenCreated.value) if e.whenCreated else None,
            }
        return {"name": self.domain_fqdn, "dn": self._base_dn}

    def close(self):
        if self._conn and self._conn.bound:
            self._conn.unbind()
            self._conn = None
