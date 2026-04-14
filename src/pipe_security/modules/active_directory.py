"""
Módulo de Active Directory para pipe-security.
Usa ldap3 con autenticación NTLM.
Todas las consultas son de solo lectura.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional
from ..utils.ldap_client import LDAPClient


# Constantes LDAP
ACCOUNT_DISABLED = 2
DONT_EXPIRE_PASSWORD = 65536
PASSWORD_NOT_REQUIRED = 32
TRUSTED_FOR_DELEGATION = 524288  # Unconstrained delegation
TRUSTED_TO_AUTH_FOR_DELEGATION = 16777216  # Constrained delegation
USE_DES_KEY_ONLY = 2097152
DONT_REQ_PREAUTH = 4194304  # AS-REP Roastable

# GUIDs de roles críticos de AD
DOMAIN_ADMIN_SID_SUFFIX = "512"
ENTERPRISE_ADMIN_SID_SUFFIX = "519"
SCHEMA_ADMIN_SID_SUFFIX = "518"
ACCOUNT_OPERATORS_SID_SUFFIX = "548"
BACKUP_OPERATORS_SID_SUFFIX = "551"

# Días para considerar cuenta inactiva
INACTIVE_DAYS = 90


def _now_minus_days(days: int) -> str:
    """Retorna timestamp LDAP para N días atrás."""
    dt = datetime.now(timezone.utc) - timedelta(days=days)
    # LDAP filetime: (days since 1601 + unix epoch offset) * 10^7
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    filetime = int((dt - epoch).total_seconds() * 10_000_000)
    return str(filetime)


def _uac_flag(uac_str: Optional[str], flag: int) -> bool:
    if not uac_str:
        return False
    try:
        return (int(uac_str) & flag) != 0
    except (ValueError, TypeError):
        return False


def ad_domain_overview(client: LDAPClient) -> dict:
    """Información general del dominio."""
    try:
        conn_info = client.test_connection()
        domain_info = client.get_domain_info()

        # Contar objetos clave
        users = client.search("(&(objectClass=user)(objectCategory=person))", ["cn"], size_limit=1)
        computers = client.search("(objectClass=computer)", ["cn"], size_limit=1)
        groups = client.search("(objectClass=group)", ["cn"], size_limit=1)
        dcs = client.search("(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                            ["cn", "dNSHostName", "operatingSystem"])

        return {
            "domain": conn_info["domain"],
            "dc": conn_info["dc"],
            "functional_level": conn_info["functional_level"],
            "domain_created": domain_info.get("created"),
            "domain_controllers": [
                {"name": d.get("cn"), "hostname": d.get("dNSHostName"), "os": d.get("operatingSystem")}
                for d in dcs
            ],
            "dc_count": len(dcs),
        }
    except Exception as e:
        return {"error": str(e)}


def ad_users_overview(client: LDAPClient) -> dict:
    """Resumen de usuarios del dominio."""
    try:
        attrs = ["sAMAccountName", "displayName", "userAccountControl",
                 "lastLogonTimestamp", "pwdLastSet", "whenCreated",
                 "memberOf", "mail", "description", "adminCount"]

        users = client.search(
            "(&(objectClass=user)(objectCategory=person))",
            attrs,
            size_limit=2000,
        )

        result = []
        stale_threshold = _now_minus_days(INACTIVE_DAYS)

        for u in users:
            uac = u.get("userAccountControl", "0")
            disabled = _uac_flag(uac, ACCOUNT_DISABLED)
            no_expire = _uac_flag(uac, DONT_EXPIRE_PASSWORD)
            no_pass_req = _uac_flag(uac, PASSWORD_NOT_REQUIRED)
            dont_preauth = _uac_flag(uac, DONT_REQ_PREAUTH)

            last_logon = u.get("lastLogonTimestamp")
            pwd_last_set = u.get("pwdLastSet")
            admin_count = u.get("adminCount") == "1"

            result.append({
                "username": u.get("sAMAccountName"),
                "display_name": u.get("displayName"),
                "email": u.get("mail"),
                "enabled": not disabled,
                "password_never_expires": no_expire,
                "password_not_required": no_pass_req,
                "asrep_roastable": dont_preauth and not disabled,
                "admin_count": admin_count,
                "last_logon": last_logon,
                "pwd_last_set": pwd_last_set,
                "description": u.get("description"),
            })

        enabled = [u for u in result if u["enabled"]]
        disabled = [u for u in result if not u["enabled"]]
        no_expire = [u for u in result if u["password_never_expires"] and u["enabled"]]
        asrep = [u for u in result if u["asrep_roastable"]]
        admins = [u for u in result if u["admin_count"]]

        return {
            "total": len(result),
            "enabled": len(enabled),
            "disabled": len(disabled),
            "password_never_expires": len(no_expire),
            "asrep_roastable_count": len(asrep),
            "admincount_users": len(admins),
            "users": result[:500],  # limitar output
        }
    except Exception as e:
        return {"error": str(e)}


def ad_privileged_groups(client: LDAPClient) -> dict:
    """Miembros de grupos privilegiados del dominio."""
    try:
        privileged_groups = [
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators",
            "Account Operators",
            "Backup Operators",
            "Print Operators",
            "Server Operators",
            "Group Policy Creator Owners",
        ]

        result = {}
        for group_name in privileged_groups:
            members = client.search(
                f"(&(objectClass=group)(cn={group_name}))",
                ["member", "cn"],
                size_limit=10,
            )
            if members:
                raw_members = members[0].get("member") or []
                if isinstance(raw_members, str):
                    raw_members = [raw_members]

                member_details = []
                for member_dn in raw_members[:50]:
                    # Buscar el usuario por DN
                    member_info = client.search(
                        f"(distinguishedName={member_dn})",
                        ["sAMAccountName", "objectClass", "userAccountControl", "displayName"],
                        size_limit=1,
                    )
                    if member_info:
                        m = member_info[0]
                        obj_class = m.get("objectClass") or []
                        member_details.append({
                            "username": m.get("sAMAccountName"),
                            "display_name": m.get("displayName"),
                            "type": "group" if "group" in obj_class else "user",
                            "enabled": not _uac_flag(m.get("userAccountControl", "0"), ACCOUNT_DISABLED),
                        })

                result[group_name] = {
                    "count": len(raw_members),
                    "members": member_details,
                }
            else:
                result[group_name] = {"count": 0, "members": []}

        return {
            "groups": result,
            "domain_admins_count": result.get("Domain Admins", {}).get("count", 0),
            "enterprise_admins_count": result.get("Enterprise Admins", {}).get("count", 0),
        }
    except Exception as e:
        return {"error": str(e)}


def ad_computers(client: LDAPClient) -> dict:
    """Equipos del dominio con sistema operativo y actividad."""
    try:
        attrs = ["cn", "dNSHostName", "operatingSystem", "operatingSystemVersion",
                 "lastLogonTimestamp", "whenCreated", "userAccountControl",
                 "userAccountControl", "description"]

        computers = client.search(
            "(objectClass=computer)",
            attrs,
            size_limit=1000,
        )

        result = []
        for c in computers:
            uac = c.get("userAccountControl", "0")
            disabled = _uac_flag(uac, ACCOUNT_DISABLED)
            delegation = _uac_flag(uac, TRUSTED_FOR_DELEGATION)

            os_name = c.get("operatingSystem", "Unknown")
            is_dc = _uac_flag(uac, 8192)  # SERVER_TRUST_ACCOUNT

            result.append({
                "name": c.get("cn"),
                "hostname": c.get("dNSHostName"),
                "os": os_name,
                "os_version": c.get("operatingSystemVersion"),
                "enabled": not disabled,
                "is_dc": is_dc,
                "unconstrained_delegation": delegation and not is_dc,
                "last_logon": c.get("lastLogonTimestamp"),
                "description": c.get("description"),
            })

        # Detectar OS legados
        legacy_os = [c for c in result if c["os"] and any(
            leg in c["os"] for leg in ["Windows XP", "Windows 7", "Windows 8", "2003", "2008", "Vista"]
        )]

        unconstrained = [c for c in result if c["unconstrained_delegation"] and not c["is_dc"]]

        return {
            "total": len(result),
            "enabled": len([c for c in result if c["enabled"]]),
            "domain_controllers": len([c for c in result if c["is_dc"]]),
            "legacy_os_count": len(legacy_os),
            "unconstrained_delegation_count": len(unconstrained),
            "legacy_os": legacy_os,
            "unconstrained_delegation": unconstrained,
            "computers": result,
        }
    except Exception as e:
        return {"error": str(e)}


def ad_password_policy(client: LDAPClient) -> dict:
    """Política de contraseñas del dominio."""
    try:
        results = client.search(
            "(objectClass=domain)",
            ["minPwdLength", "maxPwdAge", "minPwdAge", "pwdHistoryLength",
             "pwdProperties", "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow"],
            search_base=client._base_dn,
            size_limit=1,
        )

        if not results:
            return {"error": "No se pudo obtener la política de contraseñas"}

        d = results[0]

        def filetime_to_days(ft_str):
            if not ft_str or ft_str == "0":
                return 0
            try:
                ft = abs(int(ft_str))
                return ft // (10_000_000 * 86400)
            except Exception:
                return None

        max_age_days = filetime_to_days(d.get("maxPwdAge"))
        min_age_days = filetime_to_days(d.get("minPwdAge"))
        lockout_dur = filetime_to_days(d.get("lockoutDuration"))

        pwd_props = int(d.get("pwdProperties") or 0)
        complexity = bool(pwd_props & 1)

        return {
            "min_length": int(d.get("minPwdLength") or 0),
            "max_age_days": max_age_days,
            "min_age_days": min_age_days,
            "history_count": int(d.get("pwdHistoryLength") or 0),
            "complexity_enabled": complexity,
            "lockout_threshold": int(d.get("lockoutThreshold") or 0),
            "lockout_duration_minutes": (lockout_dur or 0) * 1440,
            "risks": {
                "short_password": int(d.get("minPwdLength") or 0) < 8,
                "no_expiry": max_age_days == 0,
                "no_complexity": not complexity,
                "no_lockout": int(d.get("lockoutThreshold") or 0) == 0,
                "no_history": int(d.get("pwdHistoryLength") or 0) < 5,
            }
        }
    except Exception as e:
        return {"error": str(e)}


def ad_stale_accounts(client: LDAPClient, inactive_days: int = 90) -> dict:
    """Cuentas habilitadas sin actividad en N días."""
    try:
        threshold = _now_minus_days(inactive_days)
        attrs = ["sAMAccountName", "displayName", "lastLogonTimestamp",
                 "userAccountControl", "adminCount", "mail"]

        users = client.search(
            f"(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
            f"(lastLogonTimestamp<={threshold}))",
            attrs,
            size_limit=500,
        )

        result = []
        for u in users:
            result.append({
                "username": u.get("sAMAccountName"),
                "display_name": u.get("displayName"),
                "email": u.get("mail"),
                "last_logon": u.get("lastLogonTimestamp"),
                "is_admin": u.get("adminCount") == "1",
            })

        return {
            "inactive_days_threshold": inactive_days,
            "total_stale": len(result),
            "stale_admins": len([u for u in result if u["is_admin"]]),
            "accounts": result,
        }
    except Exception as e:
        return {"error": str(e)}


def ad_kerberoastable(client: LDAPClient) -> dict:
    """Service accounts con SPN — vulnerables a Kerberoasting."""
    try:
        attrs = ["sAMAccountName", "displayName", "servicePrincipalName",
                 "userAccountControl", "adminCount", "pwdLastSet", "lastLogonTimestamp"]

        # Usuarios con SPN (no computers)
        accounts = client.search(
            "(&(objectClass=user)(objectCategory=person)(servicePrincipalName=*)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            attrs,
            size_limit=200,
        )

        result = []
        for a in accounts:
            spns = a.get("servicePrincipalName") or []
            if isinstance(spns, str):
                spns = [spns]
            result.append({
                "username": a.get("sAMAccountName"),
                "display_name": a.get("displayName"),
                "spns": spns,
                "is_admin": a.get("adminCount") == "1",
                "pwd_last_set": a.get("pwdLastSet"),
                "last_logon": a.get("lastLogonTimestamp"),
                "risk": "CRITICAL" if a.get("adminCount") == "1" else "HIGH",
            })

        return {
            "total_kerberoastable": len(result),
            "admin_accounts": len([a for a in result if a["is_admin"]]),
            "accounts": result,
            "description": "Estas cuentas pueden ser atacadas con Kerberoasting para obtener el hash de su contraseña offline.",
        }
    except Exception as e:
        return {"error": str(e)}


def ad_asrep_roastable(client: LDAPClient) -> dict:
    """Usuarios sin pre-autenticación Kerberos — AS-REP Roastable."""
    try:
        attrs = ["sAMAccountName", "displayName", "userAccountControl",
                 "adminCount", "lastLogonTimestamp"]

        accounts = client.search(
            "(&(objectClass=user)(objectCategory=person)"
            "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            attrs,
            size_limit=200,
        )

        result = []
        for a in accounts:
            result.append({
                "username": a.get("sAMAccountName"),
                "display_name": a.get("displayName"),
                "is_admin": a.get("adminCount") == "1",
                "last_logon": a.get("lastLogonTimestamp"),
                "risk": "CRITICAL" if a.get("adminCount") == "1" else "HIGH",
            })

        return {
            "total_asrep_roastable": len(result),
            "admin_accounts": len([a for a in result if a["is_admin"]]),
            "accounts": result,
            "description": "Estas cuentas no requieren pre-autenticación Kerberos. Un atacante puede solicitar un TGT y crackearlo offline sin credenciales.",
        }
    except Exception as e:
        return {"error": str(e)}


def ad_gpo_list(client: LDAPClient) -> dict:
    """Lista de GPOs del dominio."""
    try:
        attrs = ["displayName", "cn", "whenCreated", "whenChanged",
                 "gPCFileSysPath", "flags"]

        gpos = client.search(
            "(objectClass=groupPolicyContainer)",
            attrs,
            size_limit=200,
        )

        result = []
        for g in gpos:
            flags = int(g.get("flags") or 0)
            result.append({
                "name": g.get("displayName"),
                "guid": g.get("cn"),
                "created": g.get("whenCreated"),
                "modified": g.get("whenChanged"),
                "path": g.get("gPCFileSysPath"),
                "user_disabled": bool(flags & 1),
                "computer_disabled": bool(flags & 2),
                "all_disabled": flags == 3,
            })

        return {
            "total": len(result),
            "disabled": len([g for g in result if g["all_disabled"]]),
            "gpos": result,
        }
    except Exception as e:
        return {"error": str(e)}


def ad_unconstrained_delegation(client: LDAPClient) -> dict:
    """Cuentas y equipos con delegación Kerberos irrestricta (excepto DCs)."""
    try:
        attrs = ["sAMAccountName", "displayName", "objectClass",
                 "userAccountControl", "adminCount", "dNSHostName"]

        accounts = client.search(
            "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=8192))"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            attrs,
            size_limit=200,
        )

        result = []
        for a in accounts:
            obj_class = a.get("objectClass") or []
            result.append({
                "name": a.get("sAMAccountName"),
                "display_name": a.get("displayName"),
                "type": "computer" if "computer" in obj_class else "user",
                "hostname": a.get("dNSHostName"),
                "is_admin": a.get("adminCount") == "1",
            })

        return {
            "total": len(result),
            "accounts": result,
            "description": (
                "Cuentas con delegación irrestricta pueden impersonar a cualquier usuario "
                "que se autentique contra ellas. Vector clásico de ataque Pass-the-Ticket."
            ),
        }
    except Exception as e:
        return {"error": str(e)}
