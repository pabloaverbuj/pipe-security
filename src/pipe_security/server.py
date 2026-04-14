#!/usr/bin/env python3
"""
pipe-security MCP Server
Geo Labs Security Suite — Windows, Active Directory & Cloud

Herramientas disponibles:
  LOCAL (sin credenciales):
    local_machine_overview, local_users_audit, local_open_ports,
    local_smb_config, local_rdp_config, local_wdigest_check,
    local_windows_defender, local_pending_updates, local_firewall_status,
    local_password_policy, local_scheduled_tasks, local_laps_status

  ACTIVE DIRECTORY (requiere domain configurado):
    ad_domain_overview, ad_users_overview, ad_privileged_groups,
    ad_computers, ad_password_policy, ad_stale_accounts,
    ad_kerberoastable, ad_asrep_roastable, ad_gpo_list,
    ad_unconstrained_delegation

  GESTIÓN:
    domain_list, domain_switch, local_security_summary, ad_security_summary,
    local_security_findings, ad_security_findings
"""

import json
import asyncio
from typing import Any

import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server

from .config import ConfigManager
from .utils.ldap_client import LDAPClient
from .modules import local as local_mod
from .modules import active_directory as ad_mod

server = Server("pipe-security")
config = ConfigManager()


def ok(data: Any) -> str:
    return json.dumps(data, indent=2, default=str, ensure_ascii=False)


def get_ldap_client() -> LDAPClient:
    domain_cfg = config.get_active_domain_config()
    if not domain_cfg:
        raise RuntimeError(
            "No hay dominio activo configurado.\n"
            "Ejecutá: pipe-security domain add\n"
            "O en Claude: 'agregá el dominio X con DC 192.168.1.10'"
        )
    return LDAPClient(domain_cfg)


# ─── Definición de herramientas ────────────────────────────────────────────────

TOOLS: list[types.Tool] = [

    # ── Gestión de dominios ───────────────────────────────────────────────────
    types.Tool(
        name="domain_list",
        description="Lista los dominios de Active Directory configurados y muestra cuál está activo.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    types.Tool(
        name="domain_switch",
        description="Cambia el dominio activo para las consultas de Active Directory.",
        inputSchema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Nombre del dominio a activar"},
            },
            "required": ["name"],
        },
    ),
    types.Tool(
        name="domain_add",
        description=(
            "Registra un dominio de Active Directory para auditoría. "
            "Las credenciales se almacenan en Windows Credential Manager (no en disco en texto claro). "
            "El DC puede ser IP o hostname. Puerto default: 389 (LDAP), usar 636 para LDAPS. "
            "Ejemplo: domain='geonosis', dc='192.168.1.10', fqdn='geonosis.local', user='auditor', password='...' "
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "name":        {"type": "string", "description": "Nombre corto del dominio (ej: geonosis)"},
                "dc":          {"type": "string", "description": "IP o hostname del Domain Controller"},
                "domain_fqdn": {"type": "string", "description": "FQDN del dominio (ej: geonosis.local)"},
                "user":        {"type": "string", "description": "Usuario con permisos de lectura en AD (ej: auditor o DOMAIN\\auditor)"},
                "password":    {"type": "string", "description": "Contraseña del usuario"},
                "port":        {"type": "number", "description": "Puerto LDAP (default: 389, SSL: 636)", "default": 389},
                "ssl":         {"type": "boolean", "description": "Usar LDAPS (default: false)", "default": False},
            },
            "required": ["name", "dc", "domain_fqdn", "user", "password"],
        },
    ),
    types.Tool(
        name="domain_remove",
        description="Elimina un dominio registrado y borra sus credenciales del Credential Manager.",
        inputSchema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Nombre del dominio a eliminar"},
            },
            "required": ["name"],
        },
    ),

    # ── Escaneo local ─────────────────────────────────────────────────────────
    types.Tool(
        name="local_machine_overview",
        description="Información general del equipo: OS, dominio, usuario, RAM, uptime. No requiere credenciales.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    types.Tool(
        name="local_users_audit",
        description="Auditoría de usuarios locales: cuáles están habilitados, cuáles son admins, última sesión, si tienen contraseña.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    types.Tool(
        name="local_open_ports",
        description="Puertos TCP en escucha en el equipo. Identifica puertos riesgosos expuestos (RDP, SMB, WinRM, etc).",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    types.Tool(
        name="local_smb_config",
        description="Configuración SMB: detecta SMBv1 habilitado, firma SMB, carpetas compartidas con acceso Everyone.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    types.Tool(
        name="local_rdp_config",
        description="Configuración de RDP: si está habilitado, si requiere NLA, puerto usado.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    types.Tool(
        name="local_wdigest_check",
        description="Verifica WDigest (credenciales en texto claro en memoria), LSA Protection y Credential Guard.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    types.Tool(
        name="local_windows_defender",
        description="Estado de Windows Defender: protección en tiempo real, edad de firmas, tamper protection.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    types.Tool(
        name="local_pending_updates",
        description="Parches de seguridad pendientes de instalar. Requiere acceso a Windows Update API.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    types.Tool(
        name="local_firewall_status",
        description="Estado del Firewall de Windows en los tres perfiles (Domain, Private, Public).",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    types.Tool(
        name="local_password_policy",
        description="Política de contraseñas local: longitud mínima, expiración, historial, lockout.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    types.Tool(
        name="local_scheduled_tasks",
        description="Tareas programadas no-Microsoft activas. Detecta posibles mecanismos de persistencia.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    types.Tool(
        name="local_laps_status",
        description="Verifica si LAPS (Local Admin Password Solution) está instalado y configurado.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    types.Tool(
        name="local_security_summary",
        description="Resumen ejecutivo de seguridad del equipo local: corre todos los checks y presenta hallazgos críticos.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),

    # ── Active Directory ──────────────────────────────────────────────────────
    types.Tool(
        name="ad_domain_overview",
        description="Información general del dominio AD: nombre, nivel funcional, Domain Controllers, cantidad de objetos.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    types.Tool(
        name="ad_users_overview",
        description="Resumen de usuarios del dominio: habilitados, deshabilitados, sin expiración de contraseña, AS-REP roastables.",
        inputSchema={
            "type": "object",
            "properties": {
                "include_disabled": {"type": "boolean", "default": False,
                                     "description": "Incluir cuentas deshabilitadas (default: false)"},
            },
            "required": [],
        },
    ),
    types.Tool(
        name="ad_privileged_groups",
        description="Miembros de grupos privilegiados: Domain Admins, Enterprise Admins, Schema Admins, Backup Operators, etc.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    types.Tool(
        name="ad_computers",
        description="Equipos del dominio: SO, actividad, OS legados (XP/7/2003), delegación Kerberos irrestricta.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    types.Tool(
        name="ad_password_policy",
        description="Política de contraseñas del dominio: longitud, expiración, complejidad, lockout, historial.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    types.Tool(
        name="ad_stale_accounts",
        description="Cuentas habilitadas sin actividad en N días. Identifica cuentas zombie que deberían deshabilitarse.",
        inputSchema={
            "type": "object",
            "properties": {
                "inactive_days": {"type": "number", "default": 90,
                                  "description": "Días sin actividad para considerar inactiva (default: 90)"},
            },
            "required": [],
        },
    ),
    types.Tool(
        name="ad_kerberoastable",
        description="Service accounts con SPN vulnerables a Kerberoasting. Un atacante puede obtener su hash sin autenticación previa.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    types.Tool(
        name="ad_asrep_roastable",
        description="Usuarios sin pre-autenticación Kerberos (AS-REP Roastable). El hash puede crackearse offline sin credenciales.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    types.Tool(
        name="ad_gpo_list",
        description="Lista de Group Policy Objects del dominio: nombre, fecha de modificación, estado.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    types.Tool(
        name="ad_unconstrained_delegation",
        description="Cuentas y equipos con delegación Kerberos irrestricta (excluye DCs). Vector de ataque Pass-the-Ticket.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    types.Tool(
        name="ad_security_summary",
        description="Resumen ejecutivo de seguridad del dominio AD: corre todos los checks y presenta hallazgos priorizados.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    types.Tool(
        name="ad_security_assessment_full",
        description=(
            "Assessment completo y estandarizado del dominio Active Directory. "
            "Evalúa 6 dominios: Cuentas & MFA · Contraseñas & Políticas · "
            "Kerberos (Kerberoasting/AS-REP/Delegation) · Privilegios & Grupos · "
            "Equipos & Legado · GPOs & Hardening. "
            "Genera score 0-100 por dominio, score global ponderado, grade A-F, "
            "hallazgos con técnicas MITRE ATT&CK, escenarios de ataque y "
            "roadmap de remediación priorizado. "
            "Reutilizable en cualquier dominio AD — producto SaaS para assessments."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "include_breach_scenarios": {
                    "type": "boolean",
                    "description": "Incluir escenarios de ataque por hallazgo (default true)",
                    "default": True,
                },
                "include_passing_checks": {
                    "type": "boolean",
                    "description": "Incluir controles que pasaron bien (default false)",
                    "default": False,
                },
            },
            "required": [],
        },
    ),
    types.Tool(
        name="ad_ransomware_readiness",
        description=(
            "Evalúa la preparación del dominio AD contra ataques de ransomware. "
            "Verifica: accounts con altos privilegios sin protección, backup delegation, "
            "unconstrained delegation (vector previo al ransomware), accounts con SPN admin, "
            "política de contraseñas, cuentas de servicio sobreaprovisionadas, "
            "y GPO de protección (SMB signing, LSASS protection, WDigest). "
            "Retorna score anti-ransomware, MITRE ATT&CK stages y remediaciones GPO concretas."
        ),
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),

    # ── Findings con remediación ──────────────────────────────────────────────
    types.Tool(
        name="local_security_findings",
        description=(
            "Corre todos los controles de seguridad locales y devuelve una lista estructurada de vulnerabilidades "
            "con nombre, severidad, descripción del riesgo, recursos afectados, referencia MITRE/CVE y "
            "pasos de remediación concretos con comandos PowerShell listos para ejecutar."
        ),
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    types.Tool(
        name="ad_security_findings",
        description=(
            "Corre todos los controles de seguridad de Active Directory y devuelve una lista estructurada de "
            "vulnerabilidades con nombre, severidad, descripción del riesgo, cuentas/objetos afectados, "
            "referencia MITRE ATT&CK y pasos de remediación concretos."
        ),
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
]


# ─── Handlers ──────────────────────────────────────────────────────────────────

@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    try:
        result = await asyncio.get_event_loop().run_in_executor(None, dispatch, name, arguments)
        return [types.TextContent(type="text", text=ok(result))]
    except Exception as e:
        return [types.TextContent(type="text", text=ok({"error": str(e), "tool": name}))]


def dispatch(name: str, args: dict) -> Any:

    # ── Gestión de dominios ───────────────────────────────────────────────────

    if name == "domain_list":
        domains = config.list_domains()
        active = config.get_active_domain()
        return {
            "active_domain": active,
            "domains": [
                {**{k: v for k, v in d.items()}, "is_active": d["name"] == active}
                for d in domains
            ],
            "tip": "Usá domain_switch para cambiar de dominio activo." if len(domains) > 1 else
                   "Configurá dominios con: pipe-security domain add",
        }

    elif name == "domain_switch":
        domain_name = args.get("name", "")
        domains = [d["name"] for d in config.list_domains()]
        if domain_name not in domains:
            return {"error": f"Dominio '{domain_name}' no encontrado.", "available": domains}
        config.set_active_domain(domain_name)
        return {"success": True, "active_domain": domain_name}

    elif name == "domain_add":
        required = ["name", "dc", "domain_fqdn", "user", "password"]
        missing = [f for f in required if not args.get(f)]
        if missing:
            return {"error": f"Faltan campos requeridos: {', '.join(missing)}"}
        config.add_domain(
            name=args["name"],
            dc=args["dc"],
            domain_fqdn=args["domain_fqdn"],
            user=args["user"],
            password=args["password"],
            port=int(args.get("port", 389)),
            ssl=bool(args.get("ssl", False)),
        )
        # Auto-activar si es el primero
        if not config.get_active_domain():
            config.set_active_domain(args["name"])
        # Probar conexión
        try:
            client = get_ldap_client()
            conn_test = client.test_connection()
            status = "ok" if conn_test.get("bound") else "warn"
        except Exception as e:
            conn_test = {"error": str(e)}
            status = "error"
        return {
            "success": status in ("ok", "warn"),
            "domain": args["name"],
            "dc": args["dc"],
            "fqdn": args["domain_fqdn"],
            "port": int(args.get("port", 389)),
            "ssl": bool(args.get("ssl", False)),
            "connection_test": conn_test,
            "active": config.get_active_domain() == args["name"],
            "tip": (
                "Dominio registrado y conexión exitosa. Podés usar ad_domain_overview para empezar."
                if status == "ok" else
                "Dominio guardado pero la conexión falló. Verificá IP/credenciales y conectividad LDAP (puerto 389)."
            ),
        }

    elif name == "domain_remove":
        domain_name = args.get("name", "")
        domains = [d["name"] for d in config.list_domains()]
        if domain_name not in domains:
            return {"error": f"Dominio '{domain_name}' no encontrado.", "available": domains}
        config.remove_domain(domain_name)
        remaining = config.list_domains()
        return {
            "success": True,
            "removed": domain_name,
            "remaining_domains": [d["name"] for d in remaining],
            "active_domain": config.get_active_domain(),
        }

    # ── Local ─────────────────────────────────────────────────────────────────

    elif name == "local_machine_overview":
        return local_mod.local_machine_overview()

    elif name == "local_users_audit":
        return local_mod.local_users_audit()

    elif name == "local_open_ports":
        return local_mod.local_open_ports()

    elif name == "local_smb_config":
        return local_mod.local_smb_config()

    elif name == "local_rdp_config":
        return local_mod.local_rdp_config()

    elif name == "local_wdigest_check":
        return local_mod.local_wdigest_check()

    elif name == "local_windows_defender":
        return local_mod.local_windows_defender()

    elif name == "local_pending_updates":
        return local_mod.local_pending_updates()

    elif name == "local_firewall_status":
        return local_mod.local_firewall_status()

    elif name == "local_password_policy":
        return local_mod.local_password_policy()

    elif name == "local_scheduled_tasks":
        return local_mod.local_scheduled_tasks_suspicious()

    elif name == "local_laps_status":
        return local_mod.local_laps_status()

    elif name == "local_security_summary":
        return _local_summary()

    # ── Active Directory ──────────────────────────────────────────────────────

    elif name == "ad_domain_overview":
        client = get_ldap_client()
        return ad_mod.ad_domain_overview(client)

    elif name == "ad_users_overview":
        client = get_ldap_client()
        return ad_mod.ad_users_overview(client)

    elif name == "ad_privileged_groups":
        client = get_ldap_client()
        return ad_mod.ad_privileged_groups(client)

    elif name == "ad_computers":
        client = get_ldap_client()
        return ad_mod.ad_computers(client)

    elif name == "ad_password_policy":
        client = get_ldap_client()
        return ad_mod.ad_password_policy(client)

    elif name == "ad_stale_accounts":
        client = get_ldap_client()
        return ad_mod.ad_stale_accounts(client, int(args.get("inactive_days", 90)))

    elif name == "ad_kerberoastable":
        client = get_ldap_client()
        return ad_mod.ad_kerberoastable(client)

    elif name == "ad_asrep_roastable":
        client = get_ldap_client()
        return ad_mod.ad_asrep_roastable(client)

    elif name == "ad_gpo_list":
        client = get_ldap_client()
        return ad_mod.ad_gpo_list(client)

    elif name == "ad_unconstrained_delegation":
        client = get_ldap_client()
        return ad_mod.ad_unconstrained_delegation(client)

    elif name == "ad_security_summary":
        return _ad_summary()

    elif name == "local_security_findings":
        return _local_findings()

    elif name == "ad_security_findings":
        return _ad_findings()

    elif name == "ad_security_assessment_full":
        return _ad_assessment_full(
            include_breach=args.get("include_breach_scenarios", True),
            include_passing=args.get("include_passing_checks", False),
        )

    elif name == "ad_ransomware_readiness":
        return _ad_ransomware_readiness()

    else:
        return {"error": f"Herramienta desconocida: {name}"}


# ─── Summaries ────────────────────────────────────────────────────────────────

def _local_summary() -> dict:
    """Corre todos los checks locales y construye un resumen ejecutivo."""
    findings = []

    def check(label, fn, risk_fn):
        try:
            result = fn()
            risks = risk_fn(result)
            for r in risks:
                findings.append(r)
            return result
        except Exception as e:
            return {"error": str(e)}

    # SMB
    smb = local_mod.local_smb_config()
    if isinstance(smb, dict):
        if smb.get("risk_smb1"):
            findings.append({"severity": "CRITICAL", "area": "SMB", "finding": "SMBv1 habilitado — vulnerable a EternalBlue/WannaCry"})
        if smb.get("shares_with_everyone"):
            findings.append({"severity": "HIGH", "area": "SMB", "finding": f"{len(smb['shares_with_everyone'])} carpetas compartidas con acceso Everyone"})

    # WDigest
    wdigest = local_mod.local_wdigest_check()
    if isinstance(wdigest, dict):
        if wdigest.get("cleartext_in_memory"):
            findings.append({"severity": "CRITICAL", "area": "Credenciales", "finding": "WDigest habilitado — contraseñas en texto claro en memoria"})
        elif wdigest.get("risk_wdigest"):
            findings.append({"severity": "HIGH", "area": "Credenciales", "finding": "WDigest habilitado (LSA Protection activa mitiga el riesgo)"})

    # RDP
    rdp = local_mod.local_rdp_config()
    if isinstance(rdp, dict):
        if rdp.get("risk_no_nla"):
            findings.append({"severity": "HIGH", "area": "RDP", "finding": "RDP habilitado sin NLA — vulnerable a ataques pre-autenticación"})

    # Defender
    defender = local_mod.local_windows_defender()
    if isinstance(defender, dict) and not defender.get("error"):
        if defender.get("risk_realtime_disabled"):
            findings.append({"severity": "CRITICAL", "area": "Antivirus", "finding": "Windows Defender — protección en tiempo real deshabilitada"})
        if defender.get("risk_signature_outdated"):
            findings.append({"severity": "HIGH", "area": "Antivirus", "finding": f"Firmas de Defender desactualizadas ({defender.get('signature_age_days')} días)"})

    # Firewall
    fw = local_mod.local_firewall_status()
    if isinstance(fw, dict):
        if fw.get("risk_fw_disabled"):
            findings.append({"severity": "HIGH", "area": "Firewall", "finding": f"Firewall deshabilitado en {fw.get('disabled_count')} perfil(es)"})

    # Usuarios
    users = local_mod.local_users_audit()
    if isinstance(users, dict):
        admins = users.get("local_admins", 0)
        if admins > 2:
            findings.append({"severity": "MEDIUM", "area": "Usuarios", "finding": f"{admins} administradores locales — revisar si todos son necesarios"})

    # LAPS
    laps = local_mod.local_laps_status()
    if isinstance(laps, dict) and laps.get("risk_no_laps"):
        findings.append({"severity": "MEDIUM", "area": "LAPS", "finding": "LAPS no instalado — contraseña de admin local no gestionada"})

    # Scheduled tasks
    tasks = local_mod.local_scheduled_tasks_suspicious()
    if isinstance(tasks, dict) and tasks.get("suspicious"):
        findings.append({"severity": "MEDIUM", "area": "Persistencia",
                         "finding": f"{len(tasks['suspicious'])} tarea(s) programada(s) sospechosa(s) detectadas"})

    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    high = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] == "MEDIUM"]

    return {
        "summary": {
            "total_findings": len(findings),
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
        },
        "findings": findings,
        "verdict": (
            "RIESGO CRÍTICO — Acción inmediata requerida" if critical else
            "RIESGO ALTO — Remediar en las próximas 48hs" if high else
            "RIESGO MEDIO — Planificar remediación" if medium else
            "Sin hallazgos críticos — Continuar monitoreando"
        ),
    }


def _ad_summary() -> dict:
    """Corre todos los checks de AD y construye un resumen ejecutivo."""
    try:
        client = get_ldap_client()
    except Exception as e:
        return {"error": str(e)}

    findings = []

    # Password policy
    pp = ad_mod.ad_password_policy(client)
    if isinstance(pp, dict) and not pp.get("error"):
        risks = pp.get("risks", {})
        if risks.get("no_lockout"):
            findings.append({"severity": "HIGH", "area": "Password Policy", "finding": "Sin política de lockout — vulnerable a fuerza bruta"})
        if risks.get("short_password"):
            findings.append({"severity": "HIGH", "area": "Password Policy", "finding": f"Longitud mínima de contraseña: {pp.get('min_length')} caracteres (recomendado: 12+)"})
        if risks.get("no_complexity"):
            findings.append({"severity": "MEDIUM", "area": "Password Policy", "finding": "Complejidad de contraseñas no requerida"})
        if risks.get("no_expiry"):
            findings.append({"severity": "MEDIUM", "area": "Password Policy", "finding": "Las contraseñas no expiran nunca"})

    # Kerberoastable
    kerb = ad_mod.ad_kerberoastable(client)
    if isinstance(kerb, dict) and not kerb.get("error"):
        if kerb.get("total_kerberoastable", 0) > 0:
            sev = "CRITICAL" if kerb.get("admin_accounts", 0) > 0 else "HIGH"
            findings.append({"severity": sev, "area": "Kerberoasting",
                             "finding": f"{kerb['total_kerberoastable']} cuenta(s) Kerberoastable — {kerb.get('admin_accounts', 0)} son admins"})

    # AS-REP Roastable
    asrep = ad_mod.ad_asrep_roastable(client)
    if isinstance(asrep, dict) and not asrep.get("error"):
        if asrep.get("total_asrep_roastable", 0) > 0:
            sev = "CRITICAL" if asrep.get("admin_accounts", 0) > 0 else "HIGH"
            findings.append({"severity": sev, "area": "AS-REP Roasting",
                             "finding": f"{asrep['total_asrep_roastable']} cuenta(s) AS-REP Roastable"})

    # Unconstrained delegation
    deleg = ad_mod.ad_unconstrained_delegation(client)
    if isinstance(deleg, dict) and not deleg.get("error"):
        if deleg.get("total", 0) > 0:
            findings.append({"severity": "HIGH", "area": "Kerberos Delegation",
                             "finding": f"{deleg['total']} objeto(s) con delegación irrestricta (Pass-the-Ticket)"})

    # Stale accounts
    stale = ad_mod.ad_stale_accounts(client, 90)
    if isinstance(stale, dict) and not stale.get("error"):
        if stale.get("stale_admins", 0) > 0:
            findings.append({"severity": "HIGH", "area": "Cuentas Inactivas",
                             "finding": f"{stale['stale_admins']} admin(s) sin actividad en 90+ días"})
        if stale.get("total_stale", 0) > 10:
            findings.append({"severity": "MEDIUM", "area": "Cuentas Inactivas",
                             "finding": f"{stale['total_stale']} cuentas habilitadas sin actividad en 90+ días"})

    # Privileged groups
    priv = ad_mod.ad_privileged_groups(client)
    if isinstance(priv, dict) and not priv.get("error"):
        da_count = priv.get("domain_admins_count", 0)
        if da_count > 5:
            findings.append({"severity": "MEDIUM", "area": "Privilegios",
                             "finding": f"{da_count} Domain Admins — revisar si todos son necesarios"})

    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    high = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] == "MEDIUM"]

    domain_name = config.get_active_domain()

    return {
        "domain": domain_name,
        "summary": {
            "total_findings": len(findings),
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
        },
        "findings": findings,
        "verdict": (
            "RIESGO CRÍTICO — Dominio comprometible con técnicas estándar" if critical else
            "RIESGO ALTO — Vectores de ataque identificados" if high else
            "RIESGO MEDIO — Hardening recomendado" if medium else
            "Sin hallazgos críticos"
        ),
    }


# ─── Findings con remediación ─────────────────────────────────────────────────

def _finding(fid, name, severity, area, description, technique, affected, remediation_steps, powershell=None):
    """Construye un objeto finding estandarizado."""
    f = {
        "id": fid,
        "name": name,
        "severity": severity,
        "area": area,
        "description": description,
        "technique": technique,
        "affected": affected,
        "remediation": {
            "steps": remediation_steps,
        },
    }
    if powershell:
        f["remediation"]["powershell"] = powershell
    return f


def _local_findings() -> dict:
    """
    Ejecuta todos los controles locales y retorna hallazgos estructurados
    con descripción del riesgo, recursos afectados y remediación paso a paso.
    """
    findings = []
    errors = []

    # ── SMB ──────────────────────────────────────────────────────────────────
    try:
        smb = local_mod.local_smb_config()
        if isinstance(smb, dict):
            if smb.get("risk_smb1"):
                findings.append(_finding(
                    fid="LOCAL-001",
                    name="SMBv1 habilitado",
                    severity="CRITICAL",
                    area="Protocolo SMB",
                    description=(
                        "SMBv1 es un protocolo obsoleto con vulnerabilidades críticas sin parche, "
                        "incluyendo EternalBlue (MS17-010) utilizado por WannaCry y NotPetya. "
                        "Permite ejecución remota de código sin autenticación en sistemas sin parche."
                    ),
                    technique="CVE-2017-0144 / MITRE T1210 (Exploit Public-Facing Application)",
                    affected=["Servicio SMB del equipo local"],
                    remediation_steps=[
                        "Deshabilitar SMBv1 en el servidor SMB.",
                        "Verificar que ninguna aplicación legacy requiera SMBv1 (escáneres, impresoras antiguas).",
                        "Deshabilitar también el cliente SMBv1.",
                        "Reiniciar el servicio Server o el equipo para aplicar el cambio.",
                        "Verificar con: Get-SmbServerConfiguration | Select EnableSMB1Protocol",
                    ],
                    powershell=(
                        "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\n"
                        "Set-SmbClientConfiguration -EnableBandwidthThrottling $false -Force\n"
                        "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
                    ),
                ))
            if not smb.get("signing_required"):
                findings.append(_finding(
                    fid="LOCAL-002",
                    name="Firma SMB no requerida",
                    severity="HIGH",
                    area="Protocolo SMB",
                    description=(
                        "Sin firma SMB obligatoria, un atacante con acceso a la red puede realizar "
                        "ataques NTLM Relay: intercepta una autenticación y la reutiliza contra otro "
                        "servicio, obteniendo acceso sin conocer la contraseña."
                    ),
                    technique="MITRE T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)",
                    affected=["Servidor SMB local"],
                    remediation_steps=[
                        "Habilitar firma SMB obligatoria en el servidor.",
                        "Habilitar firma SMB obligatoria en el cliente (para proteger conexiones salientes).",
                        "Validar que todos los servidores del entorno también tengan firma habilitada.",
                        "Verificar con: Get-SmbServerConfiguration | Select RequireSecuritySignature",
                    ],
                    powershell=(
                        "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force\n"
                        "Set-SmbClientConfiguration -RequireSecuritySignature $true -Force"
                    ),
                ))
            shares_everyone = smb.get("shares_with_everyone", [])
            if shares_everyone:
                names = [s.get("name", "?") for s in shares_everyone]
                findings.append(_finding(
                    fid="LOCAL-003",
                    name="Carpetas compartidas accesibles por Everyone",
                    severity="HIGH",
                    area="Recursos Compartidos SMB",
                    description=(
                        "Uno o más recursos SMB tienen permisos para el grupo 'Everyone', "
                        "lo que permite acceso a cualquier usuario autenticado del dominio "
                        "(o incluso anónimo si Guest está habilitado). Vectoriza movimiento lateral "
                        "y exfiltración de datos."
                    ),
                    technique="MITRE T1039 (Data from Network Shared Drive)",
                    affected=names,
                    remediation_steps=[
                        "Revisar cada carpeta compartida listada en 'affected'.",
                        "Eliminar el permiso de Everyone y reemplazarlo por grupos específicos.",
                        "Aplicar el principio de mínimo privilegio: solo quienes necesitan acceso.",
                        "Auditar los archivos expuestos en esos recursos.",
                        "Habilitar auditoría de acceso a archivos en esos shares.",
                    ],
                    powershell=(
                        "# Para cada share, reemplazar Everyone por el grupo correcto:\n"
                        "Revoke-SmbShareAccess -Name 'NOMBRE_SHARE' -AccountName 'Everyone' -Force\n"
                        "Grant-SmbShareAccess -Name 'NOMBRE_SHARE' -AccountName 'DOMINIO\\GrupoAutorizado' -AccessRight Read -Force"
                    ),
                ))
    except Exception as e:
        errors.append(f"SMB: {e}")

    # ── WDigest ───────────────────────────────────────────────────────────────
    try:
        wdigest = local_mod.local_wdigest_check()
        if isinstance(wdigest, dict):
            if wdigest.get("cleartext_in_memory"):
                findings.append(_finding(
                    fid="LOCAL-004",
                    name="WDigest habilitado sin LSA Protection (credenciales en texto claro)",
                    severity="CRITICAL",
                    area="Protección de Credenciales",
                    description=(
                        "WDigest está habilitado y LSA Protection está desactivada. "
                        "Esto permite a herramientas como Mimikatz extraer contraseñas en texto claro "
                        "directamente de la memoria del proceso LSASS sin necesidad de crackear hashes."
                    ),
                    technique="MITRE T1003.001 (OS Credential Dumping: LSASS Memory)",
                    affected=["LSASS process memory"],
                    remediation_steps=[
                        "Deshabilitar WDigest para que no almacene credenciales en texto claro.",
                        "Habilitar LSA Protection (RunAsPPL) para proteger el proceso LSASS.",
                        "Considerar habilitar Credential Guard si el hardware lo soporta (Hyper-V).",
                        "Reiniciar el equipo para que los cambios tomen efecto.",
                        "Verificar con: Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
                    ],
                    powershell=(
                        "# Deshabilitar WDigest\n"
                        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' "
                        "-Name 'UseLogonCredential' -Value 0 -Type DWORD\n\n"
                        "# Habilitar LSA Protection\n"
                        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
                        "-Name 'RunAsPPL' -Value 1 -Type DWORD"
                    ),
                ))
            elif wdigest.get("risk_wdigest"):
                findings.append(_finding(
                    fid="LOCAL-004",
                    name="WDigest habilitado (mitigado por LSA Protection)",
                    severity="MEDIUM",
                    area="Protección de Credenciales",
                    description=(
                        "WDigest está habilitado pero LSA Protection está activa, lo que dificulta "
                        "la extracción de credenciales. Sin embargo, un atacante con privilegios de kernel "
                        "puede bypassear RunAsPPL. Se recomienda deshabilitar WDigest igualmente."
                    ),
                    technique="MITRE T1003.001 (OS Credential Dumping: LSASS Memory)",
                    affected=["Registro HKLM WDigest"],
                    remediation_steps=[
                        "Deshabilitar WDigest para eliminar el vector completamente.",
                        "Verificar que RunAsPPL siga activo después del cambio.",
                    ],
                    powershell=(
                        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' "
                        "-Name 'UseLogonCredential' -Value 0 -Type DWORD"
                    ),
                ))
            if not wdigest.get("lsa_protection"):
                findings.append(_finding(
                    fid="LOCAL-005",
                    name="LSA Protection (RunAsPPL) deshabilitada",
                    severity="HIGH",
                    area="Protección de Credenciales",
                    description=(
                        "Sin LSA Protection, el proceso LSASS no está protegido como proceso protegido (PPL). "
                        "Herramientas como Mimikatz pueden inyectarse en LSASS y extraer hashes NTLM, "
                        "tickets Kerberos y credenciales en caché sin necesitar drivers de kernel."
                    ),
                    technique="MITRE T1003.001 (OS Credential Dumping: LSASS Memory)",
                    affected=["LSASS.exe"],
                    remediation_steps=[
                        "Habilitar RunAsPPL en el registro.",
                        "Reiniciar el equipo para que LSASS inicie como proceso protegido.",
                        "Verificar en Event Viewer: Security → Event ID 12 (LSA started as protected process).",
                        "Nota: algunos drivers de terceros incompatibles pueden causar BSOD — testear en entorno controlado.",
                    ],
                    powershell=(
                        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
                        "-Name 'RunAsPPL' -Value 1 -Type DWORD\n"
                        "# Reiniciar para aplicar: Restart-Computer"
                    ),
                ))
    except Exception as e:
        errors.append(f"WDigest: {e}")

    # ── RDP ───────────────────────────────────────────────────────────────────
    try:
        rdp = local_mod.local_rdp_config()
        if isinstance(rdp, dict) and rdp.get("rdp_enabled"):
            if rdp.get("risk_no_nla"):
                findings.append(_finding(
                    fid="LOCAL-006",
                    name="RDP habilitado sin Network Level Authentication (NLA)",
                    severity="HIGH",
                    area="Escritorio Remoto (RDP)",
                    description=(
                        "RDP está activo sin NLA, lo que significa que la pantalla de login de Windows "
                        "es accesible sin autenticación previa. Esto expone el servicio a ataques de "
                        "fuerza bruta, BlueKeep (CVE-2019-0708) y explotación pre-autenticación. "
                        "Con NLA, el atacante debe autenticarse a nivel de red antes de ver el login."
                    ),
                    technique="CVE-2019-0708 (BlueKeep) / MITRE T1021.001 (Remote Services: Remote Desktop Protocol)",
                    affected=[f"RDP en puerto {rdp.get('port', 3389)}"],
                    remediation_steps=[
                        "Habilitar NLA (Network Level Authentication) en la configuración de RDP.",
                        "Si RDP no es necesario, deshabilitarlo completamente.",
                        "Restringir acceso RDP mediante Firewall solo a IPs autorizadas.",
                        "Considerar cambiar el puerto por defecto (3389) como medida adicional.",
                        "Habilitar autenticación MFA para RDP usando Windows Hello for Business o solución de terceros.",
                    ],
                    powershell=(
                        "# Habilitar NLA\n"
                        "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
                        "-Name 'UserAuthentication' -Value 1\n\n"
                        "# Deshabilitar RDP (si no es necesario)\n"
                        "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
                        "-Name 'fDenyTSConnections' -Value 1\n\n"
                        "# Bloquear puerto RDP en Firewall (reemplazar 192.168.1.0/24 con tu rango autorizado)\n"
                        "New-NetFirewallRule -DisplayName 'RDP - Solo LAN' -Direction Inbound -Protocol TCP "
                        "-LocalPort 3389 -RemoteAddress '192.168.1.0/24' -Action Allow"
                    ),
                ))
            if rdp.get("risk_default_port"):
                findings.append(_finding(
                    fid="LOCAL-007",
                    name="RDP en puerto por defecto (3389)",
                    severity="LOW",
                    area="Escritorio Remoto (RDP)",
                    description=(
                        "RDP está escuchando en el puerto 3389 (estándar). Los scanners automáticos "
                        "y botnets escanean este puerto masivamente. Cambiar el puerto reduce "
                        "el ruido de ataques automatizados (security by obscurity — no es suficiente solo esto)."
                    ),
                    technique="MITRE T1021.001 (Remote Services: RDP)",
                    affected=["Puerto TCP 3389"],
                    remediation_steps=[
                        "Cambiar el puerto RDP a un valor no estándar (ej: 45389).",
                        "Actualizar reglas de Firewall para el nuevo puerto.",
                        "Documentar el nuevo puerto para el equipo de IT.",
                        "Complementar con NLA y restricción por IP (mucho más efectivo).",
                    ],
                    powershell=(
                        "# Cambiar puerto RDP a 45389 (elegir un puerto libre)\n"
                        "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
                        "-Name 'PortNumber' -Value 45389 -Type DWORD\n"
                        "New-NetFirewallRule -DisplayName 'RDP Custom Port' -Direction Inbound -Protocol TCP -LocalPort 45389 -Action Allow\n"
                        "Remove-NetFirewallRule -DisplayName 'Remote Desktop*' -ErrorAction SilentlyContinue"
                    ),
                ))
    except Exception as e:
        errors.append(f"RDP: {e}")

    # ── Windows Defender ──────────────────────────────────────────────────────
    try:
        defender = local_mod.local_windows_defender()
        if isinstance(defender, dict) and not defender.get("error"):
            if defender.get("risk_realtime_disabled"):
                findings.append(_finding(
                    fid="LOCAL-008",
                    name="Windows Defender — Protección en tiempo real deshabilitada",
                    severity="CRITICAL",
                    area="Antivirus / EDR",
                    description=(
                        "La protección en tiempo real de Windows Defender está desactivada. "
                        "El equipo no detectará ni bloqueará malware, ransomware ni herramientas "
                        "de post-explotación (Mimikatz, Cobalt Strike, etc.) en tiempo real."
                    ),
                    technique="MITRE T1562.001 (Impair Defenses: Disable or Modify Tools)",
                    affected=["Windows Defender / Microsoft Defender Antivirus"],
                    remediation_steps=[
                        "Habilitar la protección en tiempo real.",
                        "Verificar que Tamper Protection esté activada para evitar que malware la deshabilite.",
                        "Si hay un AV de terceros instalado, verificar que esté activo y actualizado.",
                        "Revisar si la deshabilitación fue intencional o producto de un ataque.",
                    ],
                    powershell=(
                        "Set-MpPreference -DisableRealtimeMonitoring $false\n"
                        "# Habilitar Tamper Protection (requiere Intune o GUI de Security Center)\n"
                        "# Verificar estado:\n"
                        "Get-MpComputerStatus | Select RealTimeProtectionEnabled, IsTamperProtected"
                    ),
                ))
            if defender.get("risk_signature_outdated"):
                age = defender.get("signature_age_days", "?")
                findings.append(_finding(
                    fid="LOCAL-009",
                    name=f"Firmas de Windows Defender desactualizadas ({age} días)",
                    severity="HIGH",
                    area="Antivirus / EDR",
                    description=(
                        f"Las firmas de detección tienen {age} días de antigüedad. "
                        "Microsoft publica actualizaciones de firmas varias veces al día. "
                        "Con firmas viejas, el Defender no detectará amenazas recientes ni variantes "
                        "de malware conocido publicadas en los últimos días."
                    ),
                    technique="MITRE T1562.001 (Impair Defenses)",
                    affected=[f"Firmas versión: {defender.get('signature_version', 'N/A')}"],
                    remediation_steps=[
                        "Actualizar las firmas inmediatamente.",
                        "Verificar conectividad a Microsoft Update (portal.windowsupdate.com).",
                        "Si el equipo no tiene internet, configurar WSUS o Windows Update for Business.",
                        "Configurar actualización automática de firmas con la política: SignatureScheduleDay.",
                    ],
                    powershell=(
                        "Update-MpSignature\n"
                        "# Verificar versión post-actualización:\n"
                        "Get-MpComputerStatus | Select AntivirusSignatureVersion, AntivirusSignatureAge"
                    ),
                ))
    except Exception as e:
        errors.append(f"Defender: {e}")

    # ── Firewall ──────────────────────────────────────────────────────────────
    try:
        fw = local_mod.local_firewall_status()
        if isinstance(fw, dict) and fw.get("risk_fw_disabled"):
            disabled = [p["name"] for p in fw.get("profiles", []) if not p.get("enabled")]
            findings.append(_finding(
                fid="LOCAL-010",
                name=f"Firewall de Windows deshabilitado en perfil(es): {', '.join(disabled)}",
                severity="HIGH",
                area="Firewall",
                description=(
                    f"El Firewall de Windows está desactivado en los perfiles: {', '.join(disabled)}. "
                    "Sin firewall activo, cualquier servicio en escucha es accesible desde la red "
                    "sin restricción. Esto expone puertos como SMB (445), RDP (3389), WinRM (5985) "
                    "a toda la red o internet."
                ),
                technique="MITRE T1562.004 (Impair Defenses: Disable or Modify System Firewall)",
                affected=disabled,
                remediation_steps=[
                    "Habilitar el Firewall en todos los perfiles.",
                    "Configurar reglas específicas para los servicios necesarios en lugar de deshabilitar el firewall.",
                    "Verificar por qué fue deshabilitado (puede ser un malware o un cambio no autorizado).",
                    "Aplicar política de grupo para forzar el estado del firewall en todos los equipos.",
                ],
                powershell=(
                    "# Habilitar en todos los perfiles\n"
                    "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True\n"
                    "# Verificar estado:\n"
                    "Get-NetFirewallProfile | Select Name, Enabled"
                ),
            ))
    except Exception as e:
        errors.append(f"Firewall: {e}")

    # ── Password Policy ───────────────────────────────────────────────────────
    try:
        pp = local_mod.local_password_policy()
        if isinstance(pp, dict):
            if pp.get("risk_no_expiry"):
                findings.append(_finding(
                    fid="LOCAL-011",
                    name="Contraseñas locales sin expiración",
                    severity="MEDIUM",
                    area="Política de Contraseñas",
                    description=(
                        "Las contraseñas de cuentas locales no expiran nunca. "
                        "Una contraseña comprometida puede usarse indefinidamente sin ser detectada. "
                        "Las contraseñas deben rotar periódicamente para limitar la ventana de exposición."
                    ),
                    technique="MITRE T1078 (Valid Accounts)",
                    affected=["Política de contraseñas local (net accounts)"],
                    remediation_steps=[
                        "Configurar expiración máxima de contraseñas (recomendado: 90 días para cuentas locales).",
                        "Para administradores locales, usar LAPS (Local Admin Password Solution) en lugar de expiración manual.",
                        "Notificar a usuarios con antelación antes de que expiren sus contraseñas.",
                    ],
                    powershell="net accounts /maxpwage:90",
                ))
            if pp.get("risk_short_pass"):
                length = pp.get("min_length", 0)
                findings.append(_finding(
                    fid="LOCAL-012",
                    name=f"Longitud mínima de contraseña insuficiente ({length} caracteres)",
                    severity="MEDIUM",
                    area="Política de Contraseñas",
                    description=(
                        f"La longitud mínima de contraseña es {length} caracteres. "
                        "Contraseñas cortas son vulnerables a ataques de diccionario y fuerza bruta. "
                        "NIST SP 800-63B recomienda un mínimo de 8 caracteres para usuarios "
                        "y 15+ para cuentas privilegiadas."
                    ),
                    technique="MITRE T1110 (Brute Force)",
                    affected=["Política de contraseñas local"],
                    remediation_steps=[
                        "Aumentar la longitud mínima a 12 caracteres como mínimo.",
                        "Para cuentas de administrador, exigir 15+ caracteres.",
                        "Complementar con un gestor de contraseñas para facilitar contraseñas largas.",
                    ],
                    powershell="net accounts /minpwlen:12",
                ))
            if pp.get("risk_no_lockout"):
                findings.append(_finding(
                    fid="LOCAL-013",
                    name="Sin política de bloqueo de cuenta (lockout)",
                    severity="HIGH",
                    area="Política de Contraseñas",
                    description=(
                        "No hay umbral de bloqueo configurado, lo que permite intentos ilimitados "
                        "de contraseña sin bloquear la cuenta. Un atacante puede hacer fuerza bruta "
                        "de forma indefinida sin ser detectado ni bloqueado."
                    ),
                    technique="MITRE T1110.001 (Brute Force: Password Guessing)",
                    affected=["Política de bloqueo de cuentas locales"],
                    remediation_steps=[
                        "Configurar umbral de bloqueo (recomendado: 5 intentos fallidos).",
                        "Configurar duración de bloqueo (recomendado: 15 minutos).",
                        "Configurar contador de reinicio (recomendado: 15 minutos).",
                        "Monitorear eventos de lockout: Event ID 4740 en el Security Log.",
                    ],
                    powershell=(
                        "net accounts /lockoutthreshold:5\n"
                        "net accounts /lockoutduration:15\n"
                        "net accounts /lockoutwindow:15"
                    ),
                ))
    except Exception as e:
        errors.append(f"Password Policy: {e}")

    # ── Usuarios locales ──────────────────────────────────────────────────────
    try:
        users = local_mod.local_users_audit()
        if isinstance(users, dict):
            admins_count = users.get("local_admins", 0)
            user_list = users.get("users", [])
            # Usuarios habilitados sin contraseña
            no_pass = [u["name"] for u in user_list if u.get("enabled") and not u.get("password_required")]
            if no_pass:
                findings.append(_finding(
                    fid="LOCAL-014",
                    name="Cuentas locales habilitadas sin contraseña requerida",
                    severity="CRITICAL",
                    area="Cuentas Locales",
                    description=(
                        "Una o más cuentas locales habilitadas no requieren contraseña. "
                        "Cualquier persona con acceso físico o de red puede autenticarse como "
                        "esos usuarios sin credenciales."
                    ),
                    technique="MITRE T1078.003 (Valid Accounts: Local Accounts)",
                    affected=no_pass,
                    remediation_steps=[
                        "Asignar contraseñas fuertes a cada cuenta listada.",
                        "Deshabilitar cuentas que no sean necesarias.",
                        "Habilitar la política de contraseñas requeridas.",
                    ],
                    powershell=(
                        "# Para cada cuenta sin contraseña:\n"
                        "$password = ConvertTo-SecureString 'NuevaContraseñaSegura123!' -AsPlainText -Force\n"
                        "Set-LocalUser -Name 'NOMBRE_USUARIO' -Password $password -PasswordNeverExpires $false"
                    ),
                ))
            if admins_count > 2:
                admin_names = [u["name"] for u in user_list if u.get("is_local_admin") and u.get("enabled")]
                findings.append(_finding(
                    fid="LOCAL-015",
                    name=f"Exceso de administradores locales ({admins_count} cuentas)",
                    severity="MEDIUM",
                    area="Cuentas Locales",
                    description=(
                        f"Hay {admins_count} cuentas con privilegios de administrador local. "
                        "Cada cuenta admin adicional amplía la superficie de ataque: si cualquiera "
                        "de ellas es comprometida, el atacante obtiene control total del equipo. "
                        "El principio de mínimo privilegio indica que solo deben ser admins quienes lo necesiten."
                    ),
                    technique="MITRE T1078.003 (Valid Accounts: Local Accounts)",
                    affected=admin_names,
                    remediation_steps=[
                        "Revisar cada cuenta admin listada y determinar si el privilegio es necesario.",
                        "Eliminar del grupo Administrators a cuentas que no lo requieran.",
                        "Mantener máximo 2 admins locales: la cuenta predeterminada (deshabilitada) y una cuenta de servicio.",
                        "Implementar LAPS para gestionar la cuenta Administrator de forma centralizada.",
                    ],
                    powershell=(
                        "# Remover usuario del grupo Administrators:\n"
                        "Remove-LocalGroupMember -Group 'Administrators' -Member 'NOMBRE_USUARIO'"
                    ),
                ))
    except Exception as e:
        errors.append(f"Usuarios: {e}")

    # ── LAPS ──────────────────────────────────────────────────────────────────
    try:
        laps = local_mod.local_laps_status()
        if isinstance(laps, dict) and laps.get("risk_no_laps"):
            findings.append(_finding(
                fid="LOCAL-016",
                name="LAPS no configurado",
                severity="MEDIUM",
                area="Gestión de Contraseñas Locales",
                description=(
                    "Local Admin Password Solution (LAPS) no está instalado. "
                    "Sin LAPS, la cuenta Administrator local tiene la misma contraseña en todos "
                    "los equipos del dominio. Si un atacante la obtiene en un equipo, puede "
                    "reutilizarla para moverse lateralmente a todos los demás (Pass-the-Hash)."
                ),
                technique="MITRE T1550.002 (Use Alternate Authentication Material: Pass the Hash)",
                affected=["Cuenta Administrator local en todos los equipos del dominio"],
                remediation_steps=[
                    "Instalar Windows LAPS (integrado en Windows 11 22H2+ / Server 2022) o Legacy LAPS.",
                    "Extender el esquema de Active Directory para LAPS.",
                    "Crear y vincular la GPO de LAPS a las OUs de equipos.",
                    "Configurar qué grupos tienen permiso para leer las contraseñas LAPS.",
                    "Verificar con: Get-LapsADPassword -Identity NOMBRE_EQUIPO -AsPlainText",
                ],
                powershell=(
                    "# Instalar Windows LAPS (Windows 11 22H2+ / Server 2022+)\n"
                    "# Paso 1: Actualizar esquema AD (ejecutar en DC como Schema Admin)\n"
                    "Update-LapsADSchema\n\n"
                    "# Paso 2: Configurar permisos en OU\n"
                    "Set-LapsADComputerSelfPermission -Identity 'OU=Workstations,DC=empresa,DC=com'\n\n"
                    "# Paso 3: Crear GPO o CSP policy para Windows LAPS\n"
                    "# Ver documentación: https://aka.ms/laps"
                ),
            ))
    except Exception as e:
        errors.append(f"LAPS: {e}")

    # ── Tareas programadas sospechosas ────────────────────────────────────────
    try:
        tasks = local_mod.local_scheduled_tasks_suspicious()
        if isinstance(tasks, dict) and tasks.get("suspicious"):
            task_names = [t.get("name", "?") for t in tasks["suspicious"]]
            findings.append(_finding(
                fid="LOCAL-017",
                name=f"Tareas programadas sospechosas ({len(task_names)} detectadas)",
                severity="MEDIUM",
                area="Persistencia",
                description=(
                    f"Se detectaron {len(task_names)} tareas programadas que ejecutan binarios desde "
                    "rutas de usuario (AppData, Temp) o intérpretes de scripts (PowerShell, cmd, wscript). "
                    "Este es un mecanismo común de persistencia utilizado por malware y RATs."
                ),
                technique="MITRE T1053.005 (Scheduled Task/Job: Scheduled Task)",
                affected=task_names,
                remediation_steps=[
                    "Revisar cada tarea listada: verificar qué ejecuta, desde qué ruta y con qué usuario.",
                    "Si la tarea es desconocida, buscar el binario o script que ejecuta.",
                    "Deshabilitar o eliminar tareas que no tengan una justificación legítima.",
                    "Ejecutar un antivirus/EDR scan completo si se encuentra algo sospechoso.",
                    "Revisar el Event Log: Microsoft-Windows-TaskScheduler/Operational",
                ],
                powershell=(
                    "# Ver detalle de una tarea sospechosa:\n"
                    "Get-ScheduledTask -TaskName 'NOMBRE_TAREA' | Select *\n\n"
                    "# Deshabilitar una tarea sospechosa:\n"
                    "Disable-ScheduledTask -TaskName 'NOMBRE_TAREA'\n\n"
                    "# Eliminar una tarea sospechosa:\n"
                    "Unregister-ScheduledTask -TaskName 'NOMBRE_TAREA' -Confirm:$false"
                ),
            ))
    except Exception as e:
        errors.append(f"Scheduled Tasks: {e}")

    # ── Puertos riesgosos ─────────────────────────────────────────────────────
    try:
        ports = local_mod.local_open_ports()
        if isinstance(ports, dict):
            risky = ports.get("risky_ports", [])
            if risky:
                port_list = [f"{p['local_port']}/{p['process_name']}" for p in risky]
                findings.append(_finding(
                    fid="LOCAL-018",
                    name=f"Puertos de alto riesgo expuestos en todas las interfaces ({len(risky)} detectados)",
                    severity="HIGH",
                    area="Exposición de Red",
                    description=(
                        f"Los siguientes puertos de alto riesgo están escuchando en 0.0.0.0 o :: "
                        f"(todas las interfaces): {', '.join(port_list)}. "
                        "Esto los hace accesibles desde cualquier red conectada al equipo, "
                        "incluyendo redes no confiables."
                    ),
                    technique="MITRE T1049 (System Network Connections Discovery) / T1210 (Exploitation of Remote Services)",
                    affected=port_list,
                    remediation_steps=[
                        "Para cada servicio, evaluar si realmente necesita escuchar en todas las interfaces.",
                        "Configurar el servicio para escuchar solo en la interfaz necesaria (ej: 127.0.0.1 para servicios locales).",
                        "Agregar reglas de Firewall que restrinjan el acceso a esos puertos por IP de origen.",
                        "Deshabilitar servicios que no sean necesarios (ej: WinRM si no se usa gestión remota).",
                    ],
                    powershell=(
                        "# Bloquear acceso externo a WinRM (5985) - ejemplo:\n"
                        "New-NetFirewallRule -DisplayName 'Block WinRM External' -Direction Inbound "
                        "-Protocol TCP -LocalPort 5985 -RemoteAddress LocalSubnet -Action Allow\n"
                        "New-NetFirewallRule -DisplayName 'Block WinRM All' -Direction Inbound "
                        "-Protocol TCP -LocalPort 5985 -Action Block"
                    ),
                ))
    except Exception as e:
        errors.append(f"Puertos: {e}")

    # ── Actualizaciones pendientes ────────────────────────────────────────────
    try:
        updates = local_mod.local_pending_updates()
        if isinstance(updates, dict) and not updates.get("error"):
            critical_count = updates.get("critical", 0)
            total = updates.get("total_pending", 0)
            if critical_count > 0:
                findings.append(_finding(
                    fid="LOCAL-019",
                    name=f"{critical_count} parche(s) críticos/importantes pendientes de instalar",
                    severity="HIGH",
                    area="Gestión de Parches",
                    description=(
                        f"Hay {critical_count} actualizaciones clasificadas como Critical o Important "
                        f"sin instalar (de un total de {total} pendientes). "
                        "Los parches críticos generalmente corrigen vulnerabilidades con exploit público "
                        "conocido. Cada día sin instalarlos es una ventana de exposición activa."
                    ),
                    technique="MITRE T1190 (Exploit Public-Facing Application) / T1203 (Exploitation for Client Execution)",
                    affected=[f"{total} actualizaciones pendientes ({critical_count} críticas/importantes)"],
                    remediation_steps=[
                        "Instalar inmediatamente los parches clasificados como Critical.",
                        "Programar una ventana de mantenimiento para instalar los parches Important.",
                        "Habilitar Windows Update automático para parches de seguridad.",
                        "Considerar WSUS o Windows Update for Business para entornos corporativos.",
                        "Verificar con: Get-HotFix | Sort-Object InstalledOn -Descending | Select -First 10",
                    ],
                    powershell=(
                        "# Instalar todas las actualizaciones pendientes (requiere PSWindowsUpdate):\n"
                        "Install-Module PSWindowsUpdate -Force\n"
                        "Get-WindowsUpdate -Install -AcceptAll -AutoReboot"
                    ),
                ))
    except Exception as e:
        errors.append(f"Updates: {e}")

    # ── Resumen final ─────────────────────────────────────────────────────────
    by_severity = {
        "CRITICAL": [f for f in findings if f["severity"] == "CRITICAL"],
        "HIGH": [f for f in findings if f["severity"] == "HIGH"],
        "MEDIUM": [f for f in findings if f["severity"] == "MEDIUM"],
        "LOW": [f for f in findings if f["severity"] == "LOW"],
    }

    return {
        "scope": "local",
        "summary": {
            "total_findings": len(findings),
            "critical": len(by_severity["CRITICAL"]),
            "high": len(by_severity["HIGH"]),
            "medium": len(by_severity["MEDIUM"]),
            "low": len(by_severity["LOW"]),
        },
        "verdict": (
            "RIESGO CRÍTICO — Requiere acción inmediata" if by_severity["CRITICAL"] else
            "RIESGO ALTO — Remediar en las próximas 24-48hs" if by_severity["HIGH"] else
            "RIESGO MEDIO — Planificar remediación esta semana" if by_severity["MEDIUM"] else
            "RIESGO BAJO — Aplicar mejoras cuando sea posible" if by_severity["LOW"] else
            "Sin hallazgos — Configuración segura"
        ),
        "findings": findings,
        "errors": errors if errors else None,
    }


def _ad_findings() -> dict:
    """
    Ejecuta todos los controles de AD y retorna hallazgos estructurados
    con descripción del riesgo, objetos afectados y remediación paso a paso.
    """
    try:
        client = get_ldap_client()
    except Exception as e:
        return {"error": str(e)}

    findings = []
    errors = []
    domain_name = config.get_active_domain()

    # ── Kerberoasting ─────────────────────────────────────────────────────────
    try:
        kerb = ad_mod.ad_kerberoastable(client)
        if isinstance(kerb, dict) and not kerb.get("error") and kerb.get("total_kerberoastable", 0) > 0:
            accounts = [a.get("samaccountname", "?") for a in kerb.get("kerberoastable_accounts", [])]
            admin_count = kerb.get("admin_accounts", 0)
            sev = "CRITICAL" if admin_count > 0 else "HIGH"
            findings.append(_finding(
                fid="AD-001",
                name=f"Kerberoasting: {kerb['total_kerberoastable']} cuenta(s) con SPN vulnerable(s)",
                severity=sev,
                area="Kerberos / Autenticación",
                description=(
                    f"Se detectaron {kerb['total_kerberoastable']} cuentas con Service Principal Name (SPN) "
                    f"registrado, de las cuales {admin_count} tienen privilegios de administrador. "
                    "Un atacante autenticado en el dominio puede solicitar un ticket TGS para estos SPNs "
                    "y obtener el hash NTLM de la contraseña de la cuenta de servicio. "
                    "El hash puede crackearse offline con herramientas como Hashcat sin generar alertas en el DC."
                ),
                technique="MITRE T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting)",
                affected=accounts,
                remediation_steps=[
                    "Reemplazar las cuentas de servicio con contraseñas débiles por Managed Service Accounts (gMSA) — tienen contraseñas de 120 caracteres rotadas automáticamente.",
                    "Si no es posible usar gMSA, establecer contraseñas de 25+ caracteres aleatorios para las cuentas de servicio.",
                    "Auditar cuáles SPNs son necesarios: eliminar los que no estén en uso.",
                    "Habilitar AES encryption para las cuentas de servicio (deshabilitar RC4 que es más vulnerable a cracking).",
                    "Monitorear Event ID 4769 (TGS Request) en el DC para detectar solicitudes masivas de tickets.",
                ],
                powershell=(
                    "# Crear un Group Managed Service Account (gMSA) como reemplazo:\n"
                    "New-ADServiceAccount -Name 'svc-nuevo' -DNSHostName 'svc-nuevo.empresa.com' "
                    "-PrincipalsAllowedToRetrieveManagedPassword 'Domain Computers'\n\n"
                    "# Forzar AES en cuenta existente:\n"
                    "Set-ADUser -Identity 'svc-cuenta' -KerberosEncryptionType AES128,AES256\n\n"
                    "# Verificar cuentas Kerberoasteables:\n"
                    "Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName,PasswordLastSet"
                ),
            ))
    except Exception as e:
        errors.append(f"Kerberoasting: {e}")

    # ── AS-REP Roasting ───────────────────────────────────────────────────────
    try:
        asrep = ad_mod.ad_asrep_roastable(client)
        if isinstance(asrep, dict) and not asrep.get("error") and asrep.get("total_asrep_roastable", 0) > 0:
            accounts = [a.get("samaccountname", "?") for a in asrep.get("asrep_accounts", [])]
            admin_count = asrep.get("admin_accounts", 0)
            sev = "CRITICAL" if admin_count > 0 else "HIGH"
            findings.append(_finding(
                fid="AD-002",
                name=f"AS-REP Roasting: {asrep['total_asrep_roastable']} cuenta(s) sin preautenticación Kerberos",
                severity=sev,
                area="Kerberos / Autenticación",
                description=(
                    f"Se detectaron {asrep['total_asrep_roastable']} cuentas con la flag "
                    "'Do not require Kerberos preauthentication' habilitada. "
                    "Un atacante SIN credenciales puede solicitar un AS-REP para estas cuentas "
                    "y recibir un hash cifrado con la contraseña del usuario, que puede crackearse offline. "
                    f"{'CRÍTICO: ' + str(admin_count) + ' cuenta(s) afectada(s) tienen privilegios de administrador.' if admin_count > 0 else ''}"
                ),
                technique="MITRE T1558.004 (Steal or Forge Kerberos Tickets: AS-REP Roasting)",
                affected=accounts,
                remediation_steps=[
                    "Habilitar la preautenticación Kerberos en todas las cuentas listadas.",
                    "Verificar si alguna aplicación legítima requiere esta configuración — si no, deshabilitar.",
                    "Para cuentas que genuinamente necesiten esta flag, establecer contraseñas de 25+ caracteres.",
                    "Auditar periódicamente cuentas con esta flag usando el script PowerShell.",
                ],
                powershell=(
                    "# Habilitar preautenticación Kerberos (remover la flag insegura):\n"
                    "# Obtener el valor actual de userAccountControl:\n"
                    "Get-ADUser -Identity 'USUARIO' -Properties userAccountControl\n\n"
                    "# Remover la flag DONT_REQ_PREAUTH (0x400000 = 4194304):\n"
                    "$uac = (Get-ADUser -Identity 'USUARIO' -Properties userAccountControl).userAccountControl\n"
                    "Set-ADUser -Identity 'USUARIO' -Replace @{userAccountControl = ($uac -band -bnot 4194304)}\n\n"
                    "# Verificar todas las cuentas con esta flag:\n"
                    "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth"
                ),
            ))
    except Exception as e:
        errors.append(f"AS-REP Roasting: {e}")

    # ── Delegación sin restricciones ──────────────────────────────────────────
    try:
        deleg = ad_mod.ad_unconstrained_delegation(client)
        if isinstance(deleg, dict) and not deleg.get("error") and deleg.get("total", 0) > 0:
            objects = [o.get("name", "?") for o in deleg.get("objects", [])]
            findings.append(_finding(
                fid="AD-003",
                name=f"Delegación Kerberos sin restricciones en {deleg['total']} objeto(s)",
                severity="HIGH",
                area="Delegación Kerberos",
                description=(
                    f"Se detectaron {deleg['total']} objetos (equipos o cuentas) con delegación Kerberos "
                    "sin restricciones (Unconstrained Delegation). "
                    "Cuando un usuario se autentica en un servicio alojado en esos equipos, "
                    "el ticket TGT del usuario se almacena en memoria del equipo. "
                    "Si el equipo es comprometido, el atacante obtiene TGTs de todos los usuarios "
                    "que se autenticaron, incluyendo potencialmente el del Domain Admin (Pass-the-Ticket)."
                ),
                technique="MITRE T1550.003 (Use Alternate Authentication Material: Pass the Ticket)",
                affected=objects,
                remediation_steps=[
                    "Migrar a Constrained Delegation o Resource-Based Constrained Delegation (RBCD).",
                    "Deshabilitar la delegación sin restricciones en los objetos listados.",
                    "Si el servicio necesita delegar, configurar Constrained Delegation solo para los SPNs necesarios.",
                    "Agregar las cuentas sensibles (Domain Admins, etc.) al grupo 'Protected Users' para inmunizarlas ante delegación.",
                    "Monitorear autenticaciones a esos equipos: Event ID 4624 con tipo Kerberos.",
                ],
                powershell=(
                    "# Deshabilitar Unconstrained Delegation en un equipo:\n"
                    "Set-ADComputer -Identity 'NOMBRE_EQUIPO' -TrustedForDelegation $false\n\n"
                    "# Configurar Constrained Delegation en su lugar:\n"
                    "Set-ADComputer -Identity 'NOMBRE_EQUIPO' -TrustedToAuthForDelegation $false\n"
                    "Set-ADComputer -Identity 'NOMBRE_EQUIPO' -Add @{'msDS-AllowedToDelegateTo'='http/servidor.empresa.com'}\n\n"
                    "# Proteger Domain Admins con Protected Users:\n"
                    "Add-ADGroupMember -Identity 'Protected Users' -Members 'ADMIN_USER'"
                ),
            ))
    except Exception as e:
        errors.append(f"Delegación: {e}")

    # ── Password Policy ───────────────────────────────────────────────────────
    try:
        pp = ad_mod.ad_password_policy(client)
        if isinstance(pp, dict) and not pp.get("error"):
            risks = pp.get("risks", {})
            if risks.get("no_lockout"):
                findings.append(_finding(
                    fid="AD-004",
                    name="Política de lockout no configurada en el dominio",
                    severity="HIGH",
                    area="Política de Contraseñas AD",
                    description=(
                        "El Default Domain Policy no tiene umbral de bloqueo de cuentas configurado. "
                        "Un atacante puede realizar ataques de password spray o fuerza bruta "
                        "indefinidamente sin que las cuentas se bloqueen."
                    ),
                    technique="MITRE T1110.003 (Brute Force: Password Spraying)",
                    affected=["Default Domain Policy"],
                    remediation_steps=[
                        "Configurar Account Lockout Threshold en la Default Domain Policy (recomendado: 5 intentos).",
                        "Configurar Account Lockout Duration (recomendado: 15 minutos).",
                        "Configurar Reset Account Lockout Counter (recomendado: 15 minutos).",
                        "Para cuentas críticas, usar Fine-Grained Password Policies con umbrales más bajos.",
                        "Implementar Microsoft Entra Password Protection para bloquear contraseñas del diccionario filtrado de Microsoft.",
                    ],
                    powershell=(
                        "# Configurar via Default Domain Policy (requiere permisos en DC):\n"
                        "# Abrir GPMC.msc → Default Domain Policy → Computer Configuration\n"
                        "# → Windows Settings → Security Settings → Account Policies → Account Lockout Policy\n\n"
                        "# Alternativa via PowerShell (módulo AD):\n"
                        "Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 5 "
                        "-LockoutDuration 00:15:00 -LockoutObservationWindow 00:15:00"
                    ),
                ))
            if risks.get("short_password"):
                min_len = pp.get("min_length", 0)
                findings.append(_finding(
                    fid="AD-005",
                    name=f"Longitud mínima de contraseña de dominio insuficiente ({min_len} caracteres)",
                    severity="MEDIUM",
                    area="Política de Contraseñas AD",
                    description=(
                        f"La política de contraseñas del dominio exige solo {min_len} caracteres mínimos. "
                        "Contraseñas cortas son vulnerables a ataques de diccionario (rockyou.txt, etc.) "
                        "y a cracking de hashes NTLM obtenidos por Kerberoasting o volcados de NTDS.dit."
                    ),
                    technique="MITRE T1110.002 (Brute Force: Password Cracking)",
                    affected=["Default Domain Policy — Minimum Password Length"],
                    remediation_steps=[
                        "Aumentar la longitud mínima de contraseña a 12 caracteres para usuarios.",
                        "Configurar 15+ para cuentas de servicio y administradores.",
                        "Considerar habilitar 'passphrases' (frases largas) como alternativa a contraseñas complejas.",
                        "Implementar Azure AD Password Protection para bloquear contraseñas comunes.",
                    ],
                    powershell=(
                        "Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 12\n\n"
                        "# Fine-Grained Password Policy para admins (25+ chars):\n"
                        "New-ADFineGrainedPasswordPolicy -Name 'Admins-PSO' -Precedence 10 "
                        "-MinPasswordLength 25 -ComplexityEnabled $true -LockoutThreshold 3 "
                        "-LockoutDuration 00:30:00 -LockoutObservationWindow 00:30:00\n"
                        "Add-ADFineGrainedPasswordPolicySubject 'Admins-PSO' -Subjects 'Domain Admins'"
                    ),
                ))
            if risks.get("no_expiry"):
                findings.append(_finding(
                    fid="AD-006",
                    name="Contraseñas de dominio sin expiración",
                    severity="MEDIUM",
                    area="Política de Contraseñas AD",
                    description=(
                        "Las contraseñas de dominio no tienen fecha de expiración configurada. "
                        "Si una contraseña es comprometida (leak, phishing, etc.) puede ser utilizada "
                        "indefinidamente sin que el usuario se vea obligado a cambiarla."
                    ),
                    technique="MITRE T1078 (Valid Accounts)",
                    affected=["Default Domain Policy — Maximum Password Age"],
                    remediation_steps=[
                        "Configurar expiración máxima de contraseñas (recomendado: 90 días).",
                        "Para cuentas de servicio, usar GMSA (rotación automática) en lugar de expiración.",
                        "Notificar a usuarios con 14 días de anticipación antes de la expiración.",
                    ],
                    powershell="Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge 90.00:00:00",
                ))
    except Exception as e:
        errors.append(f"Password Policy: {e}")

    # ── Cuentas inactivas (stale) ─────────────────────────────────────────────
    try:
        stale = ad_mod.ad_stale_accounts(client, 90)
        if isinstance(stale, dict) and not stale.get("error"):
            stale_admin_count = stale.get("stale_admins", 0)
            total_stale = stale.get("total_stale", 0)
            if stale_admin_count > 0:
                stale_admin_names = [a.get("samaccountname", "?") for a in stale.get("stale_admin_accounts", [])]
                findings.append(_finding(
                    fid="AD-007",
                    name=f"Cuentas de administrador inactivas hace 90+ días ({stale_admin_count})",
                    severity="HIGH",
                    area="Gestión del Ciclo de Vida de Cuentas",
                    description=(
                        f"Se detectaron {stale_admin_count} cuentas con privilegios de administrador "
                        "sin actividad en los últimos 90 días. Estas cuentas pueden pertenecer a "
                        "empleados que ya no trabajan en la organización, y representan un vector "
                        "de acceso persistente si sus credenciales fueron comprometidas."
                    ),
                    technique="MITRE T1078.002 (Valid Accounts: Domain Accounts)",
                    affected=stale_admin_names,
                    remediation_steps=[
                        "Verificar con RRHH si las personas que usan estas cuentas siguen en la organización.",
                        "Deshabilitar inmediatamente las cuentas de ex-empleados.",
                        "Para cuentas de servicio inactivas, verificar si el servicio fue dado de baja.",
                        "Implementar un proceso de offboarding que incluya deshabilitación automática de cuentas AD.",
                        "Revisar los grupos a los que pertenecen antes de deshabilitar.",
                    ],
                    powershell=(
                        "# Deshabilitar cuenta inactiva:\n"
                        "Disable-ADAccount -Identity 'USUARIO'\n\n"
                        "# Mover a OU de cuentas deshabilitadas:\n"
                        "Move-ADObject -Identity (Get-ADUser 'USUARIO').DistinguishedName "
                        "-TargetPath 'OU=Disabled,DC=empresa,DC=com'\n\n"
                        "# Buscar todas las cuentas inactivas 90+ días:\n"
                        "$cutoff = (Get-Date).AddDays(-90)\n"
                        "Search-ADAccount -AccountInactive -TimeSpan (New-TimeSpan -Days 90) "
                        "-UsersOnly | Where {$_.Enabled} | Select Name, LastLogonDate"
                    ),
                ))
            if total_stale > 10:
                findings.append(_finding(
                    fid="AD-008",
                    name=f"{total_stale} cuentas de usuario inactivas hace 90+ días",
                    severity="MEDIUM",
                    area="Gestión del Ciclo de Vida de Cuentas",
                    description=(
                        f"Se detectaron {total_stale} cuentas habilitadas sin actividad en 90+ días. "
                        "Estas cuentas amplían la superficie de ataque: un atacante que comprometa "
                        "sus credenciales tendrá acceso al dominio sin que el usuario legítimo lo note."
                    ),
                    technique="MITRE T1078.002 (Valid Accounts: Domain Accounts)",
                    affected=[f"{total_stale} cuentas — ver ad_stale_accounts para el listado completo"],
                    remediation_steps=[
                        "Ejecutar ad_stale_accounts para obtener el listado completo.",
                        "Coordinar con RRHH para identificar ex-empleados.",
                        "Deshabilitar cuentas de ex-empleados y moverlas a una OU de archivados.",
                        "Implementar revisión trimestral automática de cuentas inactivas.",
                        "Configurar una GPO que deshabilite cuentas automáticamente tras 90 días de inactividad.",
                    ],
                    powershell=(
                        "# Deshabilitar masivamente cuentas inactivas 90+ días (revisar primero):\n"
                        "Search-ADAccount -AccountInactive -TimeSpan (New-TimeSpan -Days 90) "
                        "-UsersOnly | Where {$_.Enabled -and $_.DistinguishedName -notlike '*OU=ServiceAccounts*'} | "
                        "Disable-ADAccount -WhatIf  # Quitar -WhatIf para ejecutar realmente"
                    ),
                ))
    except Exception as e:
        errors.append(f"Stale accounts: {e}")

    # ── Exceso de Domain Admins ───────────────────────────────────────────────
    try:
        priv = ad_mod.ad_privileged_groups(client)
        if isinstance(priv, dict) and not priv.get("error"):
            da_count = priv.get("domain_admins_count", 0)
            if da_count > 5:
                da_members = [m.get("name", "?") for m in priv.get("domain_admins", [])]
                findings.append(_finding(
                    fid="AD-009",
                    name=f"Exceso de Domain Admins ({da_count} miembros)",
                    severity="MEDIUM",
                    area="Privilegios del Dominio",
                    description=(
                        f"El grupo Domain Admins tiene {da_count} miembros. "
                        "Cada Domain Admin es un objetivo de alto valor: si cualquiera de sus "
                        "cuentas es comprometida, el atacante obtiene control total del dominio. "
                        "El principio de mínimo privilegio indica que este grupo debería tener "
                        "el menor número posible de miembros (idealmente 2-3)."
                    ),
                    technique="MITRE T1078.002 (Valid Accounts: Domain Accounts)",
                    affected=da_members,
                    remediation_steps=[
                        "Revisar cada miembro del grupo Domain Admins.",
                        "Remover cuentas que no necesiten privilegios de Domain Admin permanentes.",
                        "Implementar Privileged Access Management (PAM): asignar privilegios de DA solo cuando sea necesario y por tiempo limitado.",
                        "Usar cuentas dedicadas para tareas administrativas (separadas de las cuentas de uso diario).",
                        "Considerar Microsoft Entra PIM (Privileged Identity Management) para acceso JIT (Just-In-Time).",
                    ],
                    powershell=(
                        "# Ver todos los miembros de Domain Admins:\n"
                        "Get-ADGroupMember -Identity 'Domain Admins' -Recursive | Select Name, SamAccountName\n\n"
                        "# Remover usuario de Domain Admins:\n"
                        "Remove-ADGroupMember -Identity 'Domain Admins' -Members 'USUARIO' -Confirm:$false"
                    ),
                ))
    except Exception as e:
        errors.append(f"Privileged groups: {e}")

    # ── Equipos con OS legacy ─────────────────────────────────────────────────
    try:
        computers = ad_mod.ad_computers(client)
        if isinstance(computers, dict) and not computers.get("error"):
            legacy_os_list = [
                c for c in computers.get("computers", [])
                if any(old in str(c.get("operatingsystem", ""))
                       for old in ["Windows XP", "Windows 7", "Windows 8", "Server 2003", "Server 2008", "Server 2012"])
            ]
            if legacy_os_list:
                legacy_names = [f"{c.get('name','?')} ({c.get('operatingsystem','?')})" for c in legacy_os_list]
                findings.append(_finding(
                    fid="AD-010",
                    name=f"{len(legacy_os_list)} equipo(s) con sistema operativo fuera de soporte",
                    severity="HIGH",
                    area="Equipos del Dominio",
                    description=(
                        f"Se detectaron {len(legacy_os_list)} equipos con sistemas operativos que ya no "
                        "reciben actualizaciones de seguridad de Microsoft. Estos sistemas tienen "
                        "vulnerabilidades críticas sin parche (EternalBlue, BlueKeep, etc.) que no "
                        "serán corregidas. Un único equipo legacy comprometido puede ser usado como "
                        "pivote para moverse lateralmente en todo el dominio."
                    ),
                    technique="MITRE T1190 (Exploit Public-Facing Application) / T1210 (Exploitation of Remote Services)",
                    affected=legacy_names,
                    remediation_steps=[
                        "Planificar la migración urgente a Windows 10/11 o Windows Server 2019/2022.",
                        "Mientras tanto, aislar los equipos legacy en una VLAN separada sin acceso lateral.",
                        "Deshabilitar SMBv1 en todos los equipos legacy (si el SO lo permite).",
                        "Aplicar todos los parches disponibles (aunque el SO esté EOL, algunos parches críticos como EternalBlue tienen parche).",
                        "Desconectar equipos legacy de internet si no es estrictamente necesario.",
                    ],
                    powershell=(
                        "# Listar equipos legacy en el dominio:\n"
                        "Get-ADComputer -Filter * -Properties OperatingSystem | "
                        "Where-Object {$_.OperatingSystem -match 'XP|2003|2008|Vista|Windows 7'} | "
                        "Select Name, OperatingSystem, LastLogonDate | Sort OperatingSystem"
                    ),
                ))
    except Exception as e:
        errors.append(f"Computers: {e}")

    # ── Resumen final ─────────────────────────────────────────────────────────
    by_severity = {
        "CRITICAL": [f for f in findings if f["severity"] == "CRITICAL"],
        "HIGH": [f for f in findings if f["severity"] == "HIGH"],
        "MEDIUM": [f for f in findings if f["severity"] == "MEDIUM"],
        "LOW": [f for f in findings if f["severity"] == "LOW"],
    }

    return {
        "scope": "active_directory",
        "domain": domain_name,
        "summary": {
            "total_findings": len(findings),
            "critical": len(by_severity["CRITICAL"]),
            "high": len(by_severity["HIGH"]),
            "medium": len(by_severity["MEDIUM"]),
            "low": len(by_severity["LOW"]),
        },
        "verdict": (
            "RIESGO CRÍTICO — Dominio comprometible con técnicas estándar" if by_severity["CRITICAL"] else
            "RIESGO ALTO — Vectores de ataque identificados" if by_severity["HIGH"] else
            "RIESGO MEDIO — Hardening del dominio recomendado" if by_severity["MEDIUM"] else
            "RIESGO BAJO — Ajustes menores pendientes" if by_severity["LOW"] else
            "Sin hallazgos — Configuración segura"
        ),
        "findings": findings,
        "errors": errors if errors else None,
    }


# ─── AD Full Assessment ───────────────────────────────────────────────────────

def _ad_assessment_full(include_breach: bool = True, include_passing: bool = False) -> dict:
    """
    Assessment estandarizado AD — reutilizable en cualquier dominio.
    6 dominios con pesos, score 0-100, grade A-F, MITRE ATT&CK.
    """
    try:
        client = get_ldap_client()
    except Exception as e:
        return {"error": str(e)}

    from datetime import datetime, timezone

    DOMAINS = {
        "accounts":   {"name": "Cuentas & Identidad",         "weight": 0.25},
        "passwords":  {"name": "Contraseñas & Políticas",      "weight": 0.20},
        "kerberos":   {"name": "Kerberos & Delegación",        "weight": 0.20},
        "privileges": {"name": "Privilegios & Grupos",         "weight": 0.15},
        "endpoints":  {"name": "Equipos & Legado",             "weight": 0.10},
        "gpos":       {"name": "GPOs & Hardening",             "weight": 0.10},
    }

    all_findings = []
    domain_points = {k: {"earned": 0, "max": 0} for k in DOMAINS}

    def finding(fid, domain, severity, status, title, detail,
                attack_vector=None, breach_scenario=None, mitre=None,
                remediation=None, priority="SHORT_TERM"):
        f = {
            "id": fid, "domain": domain, "severity": severity,
            "status": status, "title": title, "detail": detail,
        }
        if attack_vector:
            f["attack_vector"] = attack_vector
        if breach_scenario and include_breach:
            f["breach_scenario"] = breach_scenario
        if mitre:
            f["mitre_technique"] = mitre
        if remediation:
            f["remediation"] = {"priority": priority, "steps": remediation}
        return f

    def score(domain, earned, maximum):
        domain_points[domain]["earned"] += earned
        domain_points[domain]["max"] += maximum

    # ── CUENTAS ────────────────────────────────────────────────────────────────
    try:
        users_data = ad_mod.ad_users_overview(client)
        total_users = users_data.get("total", 0)
        enabled = users_data.get("enabled", 0)
        no_expire_count = users_data.get("password_never_expires", 0)
        asrep_count = users_data.get("asrep_roastable_count", 0)
        stale_data = ad_mod.ad_stale_accounts(client, 90)
        stale_count = stale_data.get("total_stale", 0)
        stale_admins = stale_data.get("stale_admins", 0)

        # ACC-001: Cuentas inactivas habilitadas
        pct_stale = (stale_count / max(enabled, 1)) * 100
        if stale_count == 0:
            all_findings.append(finding("ACC-001", "accounts", "LOW", "PASS",
                "Sin cuentas inactivas habilitadas", "0 cuentas sin actividad en 90+ días"))
            score("accounts", 20, 20)
        elif pct_stale <= 10:
            all_findings.append(finding("ACC-001", "accounts", "MEDIUM", "WARN",
                f"Cuentas inactivas: {stale_count} ({pct_stale:.0f}%)",
                f"{stale_count} cuentas habilitadas sin actividad en 90+ días",
                attack_vector="Cuentas zombie = vectores de acceso con credenciales válidas sin dueño activo",
                breach_scenario="Atacante obtiene credenciales de usuario inactivo (dump, phishing previo). La cuenta sigue activa porque nadie la monitorea. Usa las credenciales para movimiento lateral sin alertar al usuario.",
                mitre="T1078 — Valid Accounts",
                remediation=["Deshabilitar o eliminar cuentas sin actividad en 90+ días",
                             "Implementar proceso automático: Get-ADUser -Filter {Enabled -eq $true} | Where-Object {$_.LastLogonDate -lt (Get-Date).AddDays(-90)}",
                             "Usar Tiered Admin Model para separar cuentas de admin y usuario"],
                priority="SHORT_TERM"))
            score("accounts", 10, 20)
        else:
            all_findings.append(finding("ACC-001", "accounts", "HIGH", "FAIL",
                f"Exceso de cuentas inactivas: {stale_count} ({pct_stale:.0f}%)",
                f"{stale_count} cuentas habilitadas sin actividad en 90+ días — superficie de ataque elevada",
                attack_vector="Password spray / credential stuffing contra cuentas sin dueño activo",
                breach_scenario=f"Con {stale_count} cuentas activas sin dueño, un atacante tiene múltiples objetivos para password spray. Ningún usuario va a reportar el acceso no autorizado porque la cuenta 'no se usa'.",
                mitre="T1078 — Valid Accounts",
                remediation=["Ejecutar revisión inmediata de cuentas inactivas",
                             "Deshabilitar en bloque: Get-ADUser -Filter {Enabled -eq $true} | Where-Object {$_.LastLogonDate -lt (Get-Date).AddDays(-90)} | Disable-ADAccount",
                             "Implementar AD Access Review mensual"],
                priority="IMMEDIATE"))
            score("accounts", 0, 20)

        # ACC-002: Cuentas admin inactivas
        if stale_admins > 0:
            all_findings.append(finding("ACC-002", "accounts", "CRITICAL", "FAIL",
                f"{stale_admins} cuenta(s) admin inactiva(s) habilitada(s)",
                f"Cuentas con adminCount=1 sin actividad en 90+ días siguen habilitadas",
                attack_vector="Cuenta admin abandonada = acceso privilegiado sin detección",
                breach_scenario="Atacante obtiene hash de cuenta admin inactiva via NTLM relay o dump. Nadie monitorea la cuenta porque 'no se usa'. El atacante puede explorar el dominio con privilegios elevados durante semanas.",
                mitre="T1078.002 — Valid Accounts: Domain Accounts",
                remediation=["URGENTE: Identificar y deshabilitar cuentas admin sin actividad",
                             "Get-ADUser -Filter {adminCount -eq 1 -and Enabled -eq $true} | Where-Object {$_.LastLogonDate -lt (Get-Date).AddDays(-90)}",
                             "Revocar adminCount y pertenencia a grupos privilegiados antes de deshabilitar"],
                priority="IMMEDIATE"))
            score("accounts", 0, 15)
        else:
            all_findings.append(finding("ACC-002", "accounts", "HIGH", "PASS",
                "Sin cuentas admin inactivas", "Todas las cuentas con adminCount tienen actividad reciente"))
            score("accounts", 15, 15)

        # ACC-003: AS-REP Roastable
        if asrep_count == 0:
            all_findings.append(finding("ACC-003", "accounts", "LOW", "PASS",
                "Sin cuentas AS-REP Roastable",
                "Ningún usuario tiene pre-autenticación Kerberos deshabilitada"))
            score("accounts", 15, 15)
        else:
            all_findings.append(finding("ACC-003", "accounts", "HIGH", "FAIL",
                f"{asrep_count} cuenta(s) AS-REP Roastable",
                "Cuentas sin pre-autenticación Kerberos — hash crackeable offline sin credenciales",
                attack_vector="Sin credenciales: solicitar TGT AS-REP → crack offline con hashcat/john",
                breach_scenario=f"Un atacante sin credenciales puede solicitar el hash Kerberos de estas {asrep_count} cuentas directamente al DC. Con hashcat y una GPU moderna, contraseñas de menos de 10 chars se crackean en horas.",
                mitre="T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting",
                remediation=["Habilitar pre-autenticación en todas las cuentas listadas",
                             "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Set-ADAccountControl -DoesNotRequirePreAuth $false",
                             "Si algún servicio lo requiere, usar contraseñas de 25+ chars y rotar cada 30 días"],
                priority="IMMEDIATE"))
            score("accounts", 0, 15)

    except Exception as e:
        all_findings.append(finding("ACC-ERR", "accounts", "MEDIUM", "UNKNOWN",
            "Error auditando cuentas", str(e)))

    # ── CONTRASEÑAS ────────────────────────────────────────────────────────────
    try:
        pp = ad_mod.ad_password_policy(client)
        risks = pp.get("risks", {})
        min_len = pp.get("min_length", 0)
        history = pp.get("history_count", 0)
        lockout = pp.get("lockout_threshold", 0)
        max_age = pp.get("max_age_days", 0)
        complexity = pp.get("complexity_enabled", False)

        # PWD-001: Longitud mínima
        if min_len >= 12:
            all_findings.append(finding("PWD-001", "passwords", "LOW", "PASS",
                f"Longitud mínima adecuada: {min_len} caracteres", "Cumple el mínimo recomendado de 12+"))
            score("passwords", 20, 20)
        elif min_len >= 8:
            all_findings.append(finding("PWD-001", "passwords", "MEDIUM", "WARN",
                f"Longitud mínima insuficiente: {min_len} caracteres",
                "Recomendado: 12+ caracteres (NIST SP 800-63B)",
                attack_vector="Contraseñas cortas crackeables offline con NTLM hashes",
                mitre="T1110.002 — Password Cracking",
                remediation=["Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 12",
                             "Comunicar el cambio a usuarios con anticipación"],
                priority="SHORT_TERM"))
            score("passwords", 10, 20)
        else:
            all_findings.append(finding("PWD-001", "passwords", "HIGH", "FAIL",
                f"Longitud mínima crítica: {min_len} caracteres",
                f"Longitud de {min_len} permite contraseñas trivialmente crackeables",
                attack_vector="NTLM hash dump + hashcat → crack de contraseñas cortas en minutos",
                breach_scenario=f"Con mínimo de {min_len} chars, la mayoría de usuarios elige contraseñas simples. Post-dump de NTLM hashes (via mimikatz), hashcat en GPU moderna crackea contraseñas de 7 chars en segundos.",
                mitre="T1110.002 — Password Cracking",
                remediation=["URGENTE: Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 12",
                             "Forzar reset de contraseñas existentes tras el cambio"],
                priority="IMMEDIATE"))
            score("passwords", 0, 20)

        # PWD-002: Lockout
        if lockout > 0 and lockout <= 10:
            all_findings.append(finding("PWD-002", "passwords", "LOW", "PASS",
                f"Política de lockout configurada: {lockout} intentos",
                "Protege contra fuerza bruta online"))
            score("passwords", 20, 20)
        elif lockout == 0:
            all_findings.append(finding("PWD-002", "passwords", "CRITICAL", "FAIL",
                "Sin política de lockout — fuerza bruta ilimitada posible",
                "lockoutThreshold=0 permite intentos de contraseña sin límite",
                attack_vector="Password spray sin límite de intentos — explotar cuentas sin MFA",
                breach_scenario="Sin lockout, un atacante puede probar miles de contraseñas contra cualquier cuenta. Combinado con el ataque de spray (una contraseña por cuenta), puede comprometer cuentas sin bloquear nada.",
                mitre="T1110.003 — Password Spraying",
                remediation=["Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 5 -LockoutDuration 00:15:00 -LockoutObservationWindow 00:15:00",
                             "Fine-Grained Password Policies para cuentas admin: umbral 3 intentos"],
                priority="IMMEDIATE"))
            score("passwords", 0, 20)
        else:
            all_findings.append(finding("PWD-002", "passwords", "MEDIUM", "WARN",
                f"Lockout alto: {lockout} intentos",
                "Más de 10 intentos permite ataques de spray más efectivos",
                remediation=["Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 5"],
                priority="SHORT_TERM"))
            score("passwords", 10, 20)

        # PWD-003: Complejidad
        if complexity:
            all_findings.append(finding("PWD-003", "passwords", "LOW", "PASS",
                "Complejidad de contraseñas habilitada", "Requiere mayúsculas, minúsculas, números/símbolos"))
            score("passwords", 10, 10)
        else:
            all_findings.append(finding("PWD-003", "passwords", "MEDIUM", "FAIL",
                "Complejidad de contraseñas deshabilitada",
                "Usuarios pueden usar contraseñas simples como 'password' o 'empresa2024'",
                attack_vector="Diccionario / credential stuffing con contraseñas simples",
                mitre="T1110.001 — Password Guessing",
                remediation=["Set-ADDefaultDomainPasswordPolicy -ComplexityEnabled $true"],
                priority="SHORT_TERM"))
            score("passwords", 0, 10)

        # PWD-004: Historial
        if history >= 10:
            all_findings.append(finding("PWD-004", "passwords", "LOW", "PASS",
                f"Historial de contraseñas adecuado: {history}",
                "Evita reutilización de contraseñas recientes"))
            score("passwords", 10, 10)
        else:
            all_findings.append(finding("PWD-004", "passwords", "MEDIUM", "WARN",
                f"Historial de contraseñas bajo: {history}",
                "Recomendado: 12+ contraseñas en historial",
                remediation=["Set-ADDefaultDomainPasswordPolicy -PasswordHistoryCount 12"],
                priority="SHORT_TERM"))
            score("passwords", 5, 10)

    except Exception as e:
        all_findings.append(finding("PWD-ERR", "passwords", "MEDIUM", "UNKNOWN",
            "Error auditando política de contraseñas", str(e)))

    # ── KERBEROS ───────────────────────────────────────────────────────────────
    try:
        kerb_data = ad_mod.ad_kerberoastable(client)
        kerb_count = kerb_data.get("total_kerberoastable", 0)
        kerb_admins = kerb_data.get("admin_accounts", 0)
        deleg_data = ad_mod.ad_unconstrained_delegation(client)
        deleg_count = deleg_data.get("total", 0)

        # KRB-001: Kerberoastable
        if kerb_count == 0:
            all_findings.append(finding("KRB-001", "kerberos", "LOW", "PASS",
                "Sin cuentas Kerberoastable",
                "No hay service accounts con SPN en cuentas de usuario"))
            score("kerberos", 30, 30)
        elif kerb_admins > 0:
            accounts = [a.get("username") for a in kerb_data.get("accounts", []) if a.get("is_admin")]
            all_findings.append(finding("KRB-001", "kerberos", "CRITICAL", "FAIL",
                f"Kerberoasting: {kerb_count} cuenta(s) — {kerb_admins} SON ADMIN",
                f"Service accounts con SPN y adminCount=1: {', '.join(accounts[:5])}",
                attack_vector="Request ST para SPN → hash TGS crackeable offline → cuenta admin comprometida",
                breach_scenario=f"Un atacante autenticado en el dominio solicita un ticket de servicio para las {kerb_admins} cuentas admin con SPN. El hash del ticket se crackea offline. Si la contraseña es débil, el atacante obtiene credenciales de admin en minutos.",
                mitre="T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting",
                remediation=["URGENTE: Cambiar contraseñas de service accounts admin a 25+ chars aleatorios",
                             "Usar Group Managed Service Accounts (gMSA) — contraseña gestionada automáticamente por AD",
                             "Remover adminCount=1 / membresía en grupos privilegiados de service accounts",
                             "New-ADServiceAccount para crear gMSA: Install-ADServiceAccount; Set-ADUser -Identity svc_account -ServicePrincipalNames @{Remove='...'}"],
                priority="IMMEDIATE"))
            score("kerberos", 0, 30)
        else:
            all_findings.append(finding("KRB-001", "kerberos", "HIGH", "WARN",
                f"Kerberoasting: {kerb_count} cuenta(s) sin privilegios admin",
                f"Service accounts con SPN — riesgo si tienen contraseñas débiles",
                attack_vector="TGS hash crackeable → movimiento lateral a sistemas donde el servicio tiene acceso",
                mitre="T1558.003 — Kerberoasting",
                remediation=["Migrar a gMSA (Group Managed Service Accounts)",
                             "Si no es posible, asegurar contraseñas de 25+ chars y rotar cada 90 días",
                             "Auditar a qué recursos tienen acceso estas cuentas y minimizar permisos"],
                priority="SHORT_TERM"))
            score("kerberos", 10, 30)

        # KRB-002: Unconstrained Delegation
        if deleg_count == 0:
            all_findings.append(finding("KRB-002", "kerberos", "LOW", "PASS",
                "Sin delegación Kerberos irrestricta (fuera de DCs)",
                "No hay equipos/cuentas con TrustedForDelegation (excepto DCs, que es esperado)"))
            score("kerberos", 30, 30)
        else:
            accounts = [a.get("name") for a in deleg_data.get("accounts", [])]
            all_findings.append(finding("KRB-002", "kerberos", "CRITICAL", "FAIL",
                f"Delegación irrestricta en {deleg_count} objeto(s): {', '.join(accounts[:5])}",
                "Equipos/cuentas con TRUSTED_FOR_DELEGATION pueden impersonar a cualquier usuario que se autentique contra ellos",
                attack_vector="Printer Bug / SpoolSample → forzar auth DC → capturar TGT de DC → DCSync",
                breach_scenario=f"Un atacante con acceso al equipo {accounts[0] if accounts else '?'} puede activar el Printer Bug para que el DC se autentique contra él. Captura el TGT del DC y lo usa para DCSync — extrayendo todos los hashes del dominio (incluyendo krbtgt).",
                mitre="T1558 — Steal or Forge Kerberos Tickets (Pass-the-Ticket)",
                remediation=["Cambiar a Constrained Delegation o Resource-Based Constrained Delegation",
                             f"Set-ADComputer -Identity '{accounts[0] if accounts else 'NOMBRE'}' -TrustedForDelegation $false",
                             "Si el servicio lo requiere, usar Constrained Delegation con protocolo específico",
                             "Proteger cuentas sensibles marcándolas como 'Account is sensitive and cannot be delegated'"],
                priority="IMMEDIATE"))
            score("kerberos", 0, 30)

        # KRB-003: AS-REP ya evaluado en accounts, aquí damos puntos de kerberos
        asrep_f = next((f for f in all_findings if f["id"] == "ACC-003"), None)
        if asrep_f and asrep_f["status"] == "PASS":
            score("kerberos", 10, 10)
        else:
            score("kerberos", 0, 10)

    except Exception as e:
        all_findings.append(finding("KRB-ERR", "kerberos", "MEDIUM", "UNKNOWN",
            "Error auditando Kerberos", str(e)))

    # ── PRIVILEGIOS ────────────────────────────────────────────────────────────
    try:
        priv_data = ad_mod.ad_privileged_groups(client)
        groups = priv_data.get("groups", {})
        da_count = priv_data.get("domain_admins_count", 0)
        ea_count = priv_data.get("enterprise_admins_count", 0)

        # PRIV-001: Domain Admins
        if da_count == 0:
            all_findings.append(finding("PRIV-001", "privileges", "HIGH", "WARN",
                "Domain Admins: 0 miembros (posible vacío o grupo anidado)",
                "Verificar que no haya grupos anidados con DA implícito"))
            score("privileges", 15, 30)
        elif da_count <= 3:
            all_findings.append(finding("PRIV-001", "privileges", "LOW", "PASS",
                f"Domain Admins: {da_count} miembro(s) — cantidad adecuada",
                "Principio de mínimo privilegio respetado"))
            score("privileges", 30, 30)
        elif da_count <= 5:
            all_findings.append(finding("PRIV-001", "privileges", "MEDIUM", "WARN",
                f"Domain Admins: {da_count} miembros — revisar necesidad",
                "Cada DA es un vector de compromiso total del dominio",
                remediation=["Revisar cada miembro y remover los que no necesitan DA permanente",
                             "Implementar Just-in-Time via PAM/PIM o grupos de AD con tiempo",
                             "Objetivo: máximo 3 DAs permanentes"],
                priority="SHORT_TERM"))
            score("privileges", 15, 30)
        else:
            da_names = [m.get("username") for m in groups.get("Domain Admins", {}).get("members", [])]
            all_findings.append(finding("PRIV-001", "privileges", "HIGH", "FAIL",
                f"Exceso de Domain Admins: {da_count} miembros",
                f"DAs: {', '.join(da_names[:8])}",
                attack_vector=f"Con {da_count} DAs, la probabilidad de comprometer al menos uno es alta",
                breach_scenario=f"Con {da_count} Domain Admins, el atacante tiene múltiples objetivos. Comprometer cualquiera de ellos significa control total del dominio. Cada DA adicional aumenta la superficie exponencialmente.",
                mitre="T1078.002 — Valid Accounts: Domain Accounts",
                remediation=["Reducir DA a máximo 3-4 cuentas de emergencia",
                             "Para tareas administrativas cotidianas: usar roles delegados (User Admin, Workstation Admin, etc.)",
                             "Considerar Privileged Access Workstations (PAW) para los DAs restantes"],
                priority="SHORT_TERM"))
            score("privileges", 0, 30)

        # PRIV-002: Enterprise Admins
        if ea_count == 0:
            all_findings.append(finding("PRIV-002", "privileges", "LOW", "PASS",
                "Enterprise Admins: vacío (correcto para operación normal)",
                "EA solo debería tener miembros durante cambios de schema o forest-level"))
            score("privileges", 20, 20)
        elif ea_count <= 2:
            all_findings.append(finding("PRIV-002", "privileges", "MEDIUM", "WARN",
                f"Enterprise Admins: {ea_count} miembro(s) permanente(s)",
                "EA no debería tener miembros permanentes — solo para operaciones puntuales",
                remediation=["Remover miembros de Enterprise Admins y agregar solo cuando sea necesario",
                             "Proceso: agregar → ejecutar tarea → remover (máximo 1 hora)"],
                priority="SHORT_TERM"))
            score("privileges", 10, 20)
        else:
            all_findings.append(finding("PRIV-002", "privileges", "CRITICAL", "FAIL",
                f"Enterprise Admins con {ea_count} miembros permanentes",
                "EA tiene privilegios sobre todo el forest — debe estar vacío en operación normal",
                attack_vector="Compromiso de cuenta EA = control de todo el forest AD (multi-dominio)",
                mitre="T1078.002 — Valid Accounts: Domain Accounts",
                remediation=["Remover todos los miembros de EA inmediatamente",
                             "Documentar proceso para agregar/remover temporalmente cuando sea necesario"],
                priority="IMMEDIATE"))
            score("privileges", 0, 20)

        # PRIV-003: Backup Operators
        bo = groups.get("Backup Operators", {})
        bo_count = bo.get("count", 0)
        if bo_count == 0:
            score("privileges", 10, 10)
        else:
            all_findings.append(finding("PRIV-003", "privileges", "HIGH", "WARN",
                f"Backup Operators: {bo_count} miembro(s)",
                "Backup Operators pueden leer archivos del sistema incluyendo NTDS.dit y SAM",
                attack_vector="Miembro de BO → backup de NTDS.dit → extracción de todos los hashes del dominio",
                mitre="T1003.003 — OS Credential Dumping: NTDS",
                remediation=["Revisar y minimizar membresía en Backup Operators",
                             "Separar backup de DC del grupo BO usando solución de backup dedicada con cuenta específica"],
                priority="SHORT_TERM"))
            score("privileges", 5, 10)

    except Exception as e:
        all_findings.append(finding("PRIV-ERR", "privileges", "MEDIUM", "UNKNOWN",
            "Error auditando privilegios", str(e)))

    # ── EQUIPOS ────────────────────────────────────────────────────────────────
    try:
        comp_data = ad_mod.ad_computers(client)
        total_comp = comp_data.get("total", 0)
        legacy_count = comp_data.get("legacy_os_count", 0)
        legacy_list = [c.get("name") for c in comp_data.get("legacy_os", [])]

        if legacy_count == 0:
            all_findings.append(finding("END-001", "endpoints", "LOW", "PASS",
                "Sin sistemas operativos legados",
                "No se detectaron Windows XP/7/2003/2008 en el dominio"))
            score("endpoints", 60, 60)
        elif legacy_count <= 2:
            all_findings.append(finding("END-001", "endpoints", "HIGH", "WARN",
                f"{legacy_count} equipo(s) con OS legado: {', '.join(legacy_list[:5])}",
                "Sistemas sin soporte oficial = sin parches de seguridad",
                attack_vector="EternalBlue (MS17-010) u otras vulnerabilidades sin parche en sistemas legacy",
                breach_scenario="Un equipo Windows 7 sin parches en la red puede ser explotado con EternalBlue sin credenciales. Desde ahí, el atacante pivota lateralmente usando Pass-the-Hash.",
                mitre="T1210 — Exploitation of Remote Services",
                remediation=["Reemplazar o aislar en VLAN segmentada los equipos legacy",
                             "Si no es posible reemplazar: firewall de host, desactivar servicios innecesarios, monitoreo intensivo"],
                priority="SHORT_TERM"))
            score("endpoints", 20, 60)
        else:
            all_findings.append(finding("END-001", "endpoints", "CRITICAL", "FAIL",
                f"Alta cantidad de OS legados: {legacy_count}/{total_comp} equipos",
                f"Sistemas: {', '.join(legacy_list[:8])}",
                attack_vector="Múltiples vectores de explotación sin parche activos en la red",
                breach_scenario=f"Con {legacy_count} sistemas sin parches en la red, cualquier exploit público contra Windows XP/7/2003/2008 es aplicable sin autenticación. WannaCry, NotPetya, EternalBlue siguen siendo efectivos contra estos sistemas.",
                mitre="T1210 — Exploitation of Remote Services",
                remediation=["Plan de migración urgente para todos los sistemas legacy",
                             "Mientras tanto: segmentar en VLAN sin acceso a recursos críticos",
                             "Activar Windows Firewall con reglas restrictivas",
                             "Considerar desconectar los más críticos de la red"],
                priority="IMMEDIATE"))
            score("endpoints", 0, 60)

        # END-002: Equipos con unconstrained delegation (ya evaluado en kerberos)
        unc_comp = [c for c in comp_data.get("computers", []) if c.get("unconstrained_delegation")]
        if not unc_comp:
            score("endpoints", 20, 20)
        else:
            score("endpoints", 0, 20)
            # El finding ya está en KRB-002

    except Exception as e:
        all_findings.append(finding("END-ERR", "endpoints", "MEDIUM", "UNKNOWN",
            "Error auditando equipos", str(e)))

    # ── GPOs ───────────────────────────────────────────────────────────────────
    try:
        gpo_data = ad_mod.ad_gpo_list(client)
        total_gpos = gpo_data.get("total", 0)
        disabled_gpos = gpo_data.get("disabled", 0)
        gpo_list = gpo_data.get("gpos", [])

        # GPO-001: GPOs deshabilitadas (potencial evasión)
        if total_gpos == 0:
            all_findings.append(finding("GPO-001", "gpos", "HIGH", "WARN",
                "Sin GPOs detectadas",
                "No se detectaron Group Policy Objects — sin hardening centralizado",
                attack_vector="Sin GPOs de seguridad, cada equipo depende de configuración local inconsistente",
                remediation=["Implementar GPOs de baseline de seguridad (Microsoft Security Compliance Toolkit)"],
                priority="MEDIUM_TERM"))
            score("gpos", 0, 40)
        elif disabled_gpos > total_gpos * 0.3:
            all_findings.append(finding("GPO-001", "gpos", "MEDIUM", "WARN",
                f"{disabled_gpos}/{total_gpos} GPOs deshabilitadas ({(disabled_gpos/total_gpos*100):.0f}%)",
                "Alto porcentaje de GPOs inactivas — posible acumulación o evasión deliberada de controles",
                remediation=["Auditar GPOs deshabilitadas y eliminar las obsoletas",
                             "Documentar las deshabilitadas temporalmente con fecha de reactivación"],
                priority="SHORT_TERM"))
            score("gpos", 20, 40)
        else:
            all_findings.append(finding("GPO-001", "gpos", "LOW", "PASS",
                f"{total_gpos} GPOs activas, {disabled_gpos} deshabilitadas",
                "Distribución de GPOs aparentemente normal"))
            score("gpos", 40, 40)

        # GPO-002: Hardening conocido detectado por nombre de GPO
        hardening_keywords = ["security", "hardening", "baseline", "cis", "stig",
                               "smb", "lsass", "credential", "defender", "firewall",
                               "bitlocker", "applocker", "wef", "audit"]
        gpo_names_lower = [g.get("name", "").lower() for g in gpo_list if g.get("name")]
        has_hardening = any(any(kw in n for kw in hardening_keywords) for n in gpo_names_lower)
        security_gpos = [g["name"] for g in gpo_list if g.get("name") and
                         any(kw in g["name"].lower() for kw in hardening_keywords)]

        if has_hardening:
            all_findings.append(finding("GPO-002", "gpos", "LOW", "PASS",
                f"GPOs de hardening/seguridad detectadas: {len(security_gpos)}",
                f"Políticas de seguridad encontradas: {', '.join(security_gpos[:5])}"))
            score("gpos", 30, 30)
        else:
            all_findings.append(finding("GPO-002", "gpos", "HIGH", "FAIL",
                "Sin GPOs de hardening/seguridad detectadas",
                "No se detectaron GPOs con nombres relacionados a seguridad — el hardening puede ser inexistente",
                attack_vector="Sin controles centralizados: SMBv1 puede estar activo, LSASS sin protección, WDigest habilitado",
                breach_scenario="Sin GPOs de seguridad, cada workstation tiene configuración de fábrica: SMBv1 potencialmente activo, LSASS vulnerable a mimikatz, no hay restricción de software. Un compromiso se propaga sin fricción.",
                mitre="T1562 — Impair Defenses",
                remediation=["Descargar Microsoft Security Compliance Toolkit (SCT)",
                             "Aplicar baselines: Windows 11/10 Security Baseline, MS Defender Antivirus Baseline",
                             "Como mínimo, crear GPOs para: SMBv1 deshabilitado, LSASS protegido, Credential Guard, Auditoría habilitada",
                             "Considerar CIS Benchmarks como referencia adicional"],
                priority="SHORT_TERM"))
            score("gpos", 0, 30)

    except Exception as e:
        all_findings.append(finding("GPO-ERR", "gpos", "MEDIUM", "UNKNOWN",
            "Error auditando GPOs", str(e)))

    # ── SCORING FINAL ──────────────────────────────────────────────────────────
    domain_results = {}
    overall_weighted = 0.0
    for dk, dv in DOMAINS.items():
        pts = domain_points[dk]
        raw_score = round((pts["earned"] / max(pts["max"], 1)) * 100, 1)
        weighted = round(raw_score * dv["weight"], 2)
        overall_weighted += weighted

        def grade(s):
            if s >= 85: return "A"
            if s >= 70: return "B"
            if s >= 55: return "C"
            if s >= 40: return "D"
            return "F"

        domain_results[dk] = {
            "name": dv["name"],
            "weight": f"{int(dv['weight']*100)}%",
            "score": raw_score,
            "weighted_score": weighted,
            "grade": grade(raw_score),
        }

    overall_score = round(overall_weighted, 1)
    overall_grade = (lambda s: "A" if s>=85 else "B" if s>=70 else "C" if s>=55 else "D" if s>=40 else "F")(overall_score)

    visible = all_findings if include_passing else [f for f in all_findings if f["status"] != "PASS"]

    critical = [f for f in all_findings if f["status"] in ("FAIL","WARN") and f["severity"] == "CRITICAL"]
    high     = [f for f in all_findings if f["status"] in ("FAIL","WARN") and f["severity"] == "HIGH"]
    medium   = [f for f in all_findings if f["status"] in ("FAIL","WARN") and f["severity"] == "MEDIUM"]

    immediate   = sorted([f for f in all_findings if f.get("remediation", {}).get("priority") == "IMMEDIATE"],
                         key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2}.get(x["severity"],3))
    short_term  = [f for f in all_findings if f.get("remediation", {}).get("priority") == "SHORT_TERM"]
    medium_term = [f for f in all_findings if f.get("remediation", {}).get("priority") in ("MEDIUM_TERM", None)]

    def roadmap_item(f):
        return {"id": f["id"], "domain": f["domain"], "severity": f["severity"],
                "title": f["title"], "steps": f.get("remediation", {}).get("steps", [])}

    return {
        "assessment_framework": "pipe-security AD Assessment v1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "domain_audited": config.get_active_domain(),
        "overall": {
            "score": overall_score,
            "grade": overall_grade,
            "interpretation": {
                "A": "Postura AD excelente (85-100)",
                "B": "Buena postura con mejoras menores (70-84)",
                "C": "Postura aceptable con brechas importantes (55-69)",
                "D": "Postura insuficiente con riesgos altos (40-54)",
                "F": "Postura crítica — acción inmediata requerida (0-39)",
            }[overall_grade],
        },
        "domains": domain_results,
        "findings": {
            "total": len(visible),
            "by_severity": {
                "critical": len([f for f in visible if f["severity"] == "CRITICAL"]),
                "high": len([f for f in visible if f["severity"] == "HIGH"]),
                "medium": len([f for f in visible if f["severity"] == "MEDIUM"]),
                "unknown": len([f for f in visible if f["status"] == "UNKNOWN"]),
            },
            "detail": visible,
        },
        "remediation_roadmap": {
            "phase_1_immediate": [roadmap_item(f) for f in immediate],
            "phase_2_short_term_30d": [roadmap_item(f) for f in short_term],
            "phase_3_medium_term_90d": [roadmap_item(f) for f in medium_term],
        },
        "benchmark": {
            "industry_average_score": 55,
            "recommended_minimum": 70,
            "gap_to_minimum": max(0, round(70 - overall_score, 1)),
            "gap_to_industry_avg": round(overall_score - 55, 1),
        },
        "attack_surface": {
            "domain_takeover_risk": any(f["id"] in ("KRB-002","PRIV-002") and f["status"]=="FAIL" for f in all_findings),
            "kerberoast_risk": any(f["id"]=="KRB-001" and f["status"]!="PASS" for f in all_findings),
            "spray_risk": any(f["id"]=="PWD-002" and f["status"]=="FAIL" for f in all_findings),
            "legacy_os_risk": any(f["id"]=="END-001" and f["status"] in ("FAIL","WARN") for f in all_findings),
            "stale_admin_risk": any(f["id"]=="ACC-002" and f["status"]=="FAIL" for f in all_findings),
        },
    }


# ─── AD Ransomware Readiness ───────────────────────────────────────────────────

def _ad_ransomware_readiness() -> dict:
    """
    Evalúa la preparación del dominio AD contra ransomware.
    Cubre las etapas de la kill chain: initial access → privilege escalation →
    lateral movement → impact (encryption/exfiltration).
    """
    try:
        client = get_ldap_client()
    except Exception as e:
        return {"error": str(e)}

    from datetime import datetime, timezone

    findings = []
    score_earned = 0
    score_max = 0

    def add_check(check_id, stage, severity, status, title, detail,
                  mitre=None, kill_chain_stage=None, gpo_fix=None, ps_fix=None):
        f = {
            "id": check_id,
            "stage": stage,
            "severity": severity,
            "status": status,
            "title": title,
            "detail": detail,
        }
        if mitre:
            f["mitre"] = mitre
        if kill_chain_stage:
            f["kill_chain_stage"] = kill_chain_stage
        if gpo_fix:
            f["gpo_remediation"] = gpo_fix
        if ps_fix:
            f["powershell_fix"] = ps_fix
        findings.append(f)

    def pts(earned, maximum):
        nonlocal score_earned, score_max
        score_earned += earned
        score_max += maximum

    # ── STAGE 1: Initial Access / Credential Theft ─────────────────────────────

    # Check: policy de lockout (spray blocker)
    try:
        pp = ad_mod.ad_password_policy(client)
        lockout = pp.get("lockout_threshold", 0)
        min_len = pp.get("min_length", 0)

        if lockout > 0:
            add_check("RW-001", "credential_theft", "HIGH", "PASS",
                "Política de lockout activa — bloquea password spray inicial",
                f"Lockout tras {lockout} intentos — primera línea contra spray",
                mitre="T1110.003",
                kill_chain_stage="Initial Access")
            pts(15, 15)
        else:
            add_check("RW-001", "credential_theft", "CRITICAL", "FAIL",
                "Sin lockout — password spray ilimitado posible",
                "Operadores de ransomware usan spray masivo para obtener credenciales iniciales",
                mitre="T1110.003 — Password Spraying",
                kill_chain_stage="Initial Access",
                ps_fix="Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 5 -LockoutDuration 00:30:00 -LockoutObservationWindow 00:30:00")
            pts(0, 15)

        if min_len >= 12:
            pts(5, 5)
        else:
            add_check("RW-002", "credential_theft", "HIGH", "FAIL",
                f"Contraseñas cortas ({min_len} chars) — crackeables post-dump",
                "Ransomware obtiene hashes NTLM y los crackea offline para escalar privilegios",
                mitre="T1110.002 — Password Cracking",
                kill_chain_stage="Credential Access",
                ps_fix="Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14")
            pts(0, 5)
    except Exception as e:
        add_check("RW-001", "credential_theft", "MEDIUM", "UNKNOWN",
            "No se pudo auditar política de contraseñas", str(e))

    # ── STAGE 2: Privilege Escalation ──────────────────────────────────────────

    # Kerberoastable admins
    try:
        kerb = ad_mod.ad_kerberoastable(client)
        kerb_admins = kerb.get("admin_accounts", 0)
        if kerb_admins == 0:
            add_check("RW-003", "privilege_escalation", "HIGH", "PASS",
                "Sin service accounts admin Kerberoastables",
                "No hay cuentas privilegiadas atacables via Kerberoasting",
                kill_chain_stage="Privilege Escalation")
            pts(20, 20)
        else:
            admins = [a["username"] for a in kerb.get("accounts", []) if a.get("is_admin")]
            add_check("RW-003", "privilege_escalation", "CRITICAL", "FAIL",
                f"{kerb_admins} cuenta(s) admin Kerberoastable(s): {', '.join(admins[:3])}",
                "Ransomware usa Kerberoasting para escalar a DA sin comprometer credenciales interactivas",
                mitre="T1558.003 — Kerberoasting",
                kill_chain_stage="Privilege Escalation",
                ps_fix="# Convertir a gMSA:\nNew-ADServiceAccount -Name 'gMSA_svc' -DNSHostName 'dc.domain.local'\nInstall-ADServiceAccount -Identity 'gMSA_svc'")
            pts(0, 20)
    except Exception as e:
        add_check("RW-003", "privilege_escalation", "MEDIUM", "UNKNOWN",
            "No se pudo auditar Kerberoasting", str(e))

    # Unconstrained delegation
    try:
        deleg = ad_mod.ad_unconstrained_delegation(client)
        if deleg.get("total", 0) == 0:
            add_check("RW-004", "privilege_escalation", "HIGH", "PASS",
                "Sin delegación Kerberos irrestricta",
                "Sin vectores de Pass-the-Ticket para escalada a DC",
                kill_chain_stage="Privilege Escalation")
            pts(20, 20)
        else:
            hosts = [a["name"] for a in deleg.get("accounts", [])]
            add_check("RW-004", "privilege_escalation", "CRITICAL", "FAIL",
                f"Delegación irrestricta en {deleg['total']} objeto(s): {', '.join(hosts[:3])}",
                "Vector clásico pre-ransomware: Printer Bug → captura TGT DC → DCSync → hash krbtgt → Golden Ticket",
                mitre="T1558 — Steal or Forge Kerberos Tickets",
                kill_chain_stage="Privilege Escalation",
                ps_fix=f"Set-ADComputer -Identity '{hosts[0] if hosts else 'NOMBRE'}' -TrustedForDelegation $false")
            pts(0, 20)
    except Exception as e:
        add_check("RW-004", "privilege_escalation", "MEDIUM", "UNKNOWN",
            "No se pudo auditar delegación", str(e))

    # Exceso de DAs
    try:
        priv = ad_mod.ad_privileged_groups(client)
        da_count = priv.get("domain_admins_count", 0)
        if da_count <= 3:
            add_check("RW-005", "privilege_escalation", "MEDIUM", "PASS",
                f"Domain Admins controlados: {da_count}",
                "Superficie de ataque privilegiada limitada",
                kill_chain_stage="Privilege Escalation")
            pts(10, 10)
        else:
            add_check("RW-005", "privilege_escalation", "HIGH", "FAIL",
                f"Exceso de Domain Admins: {da_count} — superficie amplia para escalar",
                "Más DAs = más objetivos de alto valor para ransomware",
                mitre="T1078.002",
                kill_chain_stage="Privilege Escalation",
                ps_fix="# Revisar y remover DAs innecesarios:\nGet-ADGroupMember -Identity 'Domain Admins' | Where-Object {$_.objectClass -eq 'user'}")
            pts(0, 10)
    except Exception as e:
        pass

    # ── STAGE 3: Lateral Movement ──────────────────────────────────────────────

    # Cuentas inactivas = pivoting sin detección
    try:
        stale = ad_mod.ad_stale_accounts(client, 90)
        stale_total = stale.get("total_stale", 0)
        stale_admins = stale.get("stale_admins", 0)

        if stale_admins > 0:
            add_check("RW-006", "lateral_movement", "CRITICAL", "FAIL",
                f"{stale_admins} admin(s) inactivo(s) — pivoting silencioso posible",
                "Cuentas admin sin actividad son usadas por ransomware para movimiento lateral sin alertar al usuario real",
                mitre="T1078 — Valid Accounts",
                kill_chain_stage="Lateral Movement",
                ps_fix="# Deshabilitar admins inactivos:\nGet-ADUser -Filter {adminCount -eq 1} | Where-Object {$_.LastLogonDate -lt (Get-Date).AddDays(-90)} | Disable-ADAccount")
            pts(0, 15)
        elif stale_total > 20:
            add_check("RW-006", "lateral_movement", "HIGH", "FAIL",
                f"{stale_total} cuentas inactivas habilitadas — superficie lateral amplia",
                "Cuentas zombie facilitan movimiento lateral sin detección",
                mitre="T1078",
                kill_chain_stage="Lateral Movement",
                ps_fix="Get-ADUser -Filter {Enabled -eq $true} | Where-Object {$_.LastLogonDate -lt (Get-Date).AddDays(-90)} | Disable-ADAccount")
            pts(0, 15)
        else:
            add_check("RW-006", "lateral_movement", "HIGH", "PASS",
                "Cuentas inactivas bajo control",
                "Pocos vectores de movimiento lateral via cuentas zombie",
                kill_chain_stage="Lateral Movement")
            pts(15, 15)
    except Exception as e:
        add_check("RW-006", "lateral_movement", "MEDIUM", "UNKNOWN",
            "No se pudo auditar cuentas inactivas", str(e))

    # ── STAGE 4: Impact (pre-encryption checks) ────────────────────────────────

    # Backup Operators (acceso a NTDS)
    try:
        priv2 = ad_mod.ad_privileged_groups(client)
        bo = priv2.get("groups", {}).get("Backup Operators", {})
        bo_count = bo.get("count", 0)
        if bo_count == 0:
            add_check("RW-007", "pre_impact", "HIGH", "PASS",
                "Backup Operators vacío",
                "Sin acceso a NTDS.dit via Backup Operators — hash dump dificultado",
                kill_chain_stage="Collection / Impact")
            pts(10, 10)
        else:
            members = [m.get("username") for m in bo.get("members", [])]
            add_check("RW-007", "pre_impact", "HIGH", "FAIL",
                f"Backup Operators con {bo_count} miembro(s): {', '.join(members[:3])}",
                "Backup Operators puede hacer backup de NTDS.dit y extraer todos los hashes del dominio",
                mitre="T1003.003 — NTDS Credential Dumping",
                kill_chain_stage="Collection",
                ps_fix="Remove-ADGroupMember -Identity 'Backup Operators' -Members 'usuario' -Confirm:$false")
            pts(0, 10)
    except Exception as e:
        pass

    # GPO anti-ransomware detectadas
    try:
        gpos = ad_mod.ad_gpo_list(client)
        gpo_names = [g.get("name", "").lower() for g in gpos.get("gpos", [])]
        ransomware_keywords = ["smb", "signing", "lsass", "credential", "restrict",
                                "applocker", "software restriction", "wef", "audit",
                                "bitlocker", "antivirus", "defender"]
        rw_gpos = [g["name"] for g in gpos.get("gpos", [])
                   if any(kw in (g.get("name") or "").lower() for kw in ransomware_keywords)]
        if rw_gpos:
            add_check("RW-008", "hardening", "MEDIUM", "PASS",
                f"GPOs de hardening anti-ransomware detectadas: {len(rw_gpos)}",
                f"Políticas: {', '.join(rw_gpos[:5])}",
                kill_chain_stage="Defense Evasion")
            pts(15, 15)
        else:
            add_check("RW-008", "hardening", "HIGH", "FAIL",
                "Sin GPOs de hardening anti-ransomware",
                "No se detectaron políticas de grupo que mitiguen propagación de ransomware",
                mitre="T1562 — Impair Defenses",
                kill_chain_stage="Lateral Movement / Impact",
                gpo_fix={
                    "smb_signing": {
                        "gpo_path": "Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options",
                        "setting": "Microsoft network server: Digitally sign communications (always) = Enabled",
                        "impact": "Bloquea NTLM Relay y SMB relay attacks"
                    },
                    "lsass_protection": {
                        "gpo_path": "Computer Configuration → Administrative Templates → System → Local Security Authority",
                        "setting": "RunAsPPL = 1",
                        "registry": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa → RunAsPPL = 1",
                        "impact": "Bloquea mimikatz y extracción de hashes de LSASS"
                    },
                    "wdigest": {
                        "registry": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest → UseLogonCredential = 0",
                        "impact": "Evita contraseñas en texto claro en memoria"
                    },
                    "smb1_disable": {
                        "ps": "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
                        "impact": "Bloquea EternalBlue / WannaCry propagation"
                    },
                    "software_restriction": {
                        "gpo_path": "Computer Configuration → Windows Settings → Security Settings → Software Restriction Policies",
                        "impact": "Bloquea ejecución de ransomware desde %TEMP%, %APPDATA%"
                    },
                })
            pts(0, 15)
    except Exception as e:
        add_check("RW-008", "hardening", "MEDIUM", "UNKNOWN",
            "No se pudo auditar GPOs", str(e))

    # ── Score final ────────────────────────────────────────────────────────────
    final_score = round((score_earned / max(score_max, 1)) * 100, 1)

    def rw_grade(s):
        if s >= 80: return ("A", "Preparación excelente contra ransomware")
        if s >= 65: return ("B", "Buena preparación con mejoras necesarias")
        if s >= 50: return ("C", "Preparación media — vectores explotables presentes")
        if s >= 35: return ("D", "Preparación insuficiente — riesgo real de ransomware")
        return ("F", "Sin preparación — compromiso por ransomware altamente probable")

    grade, interpretation = rw_grade(final_score)

    stages = {}
    for f in findings:
        stage = f.get("stage", "other")
        if stage not in stages:
            stages[stage] = {"pass": 0, "fail": 0, "warn": 0}
        stages[stage][f["status"].lower() if f["status"] in ("PASS","FAIL","WARN") else "warn"] += 1

    critical_fails = [f for f in findings if f["status"] == "FAIL" and f["severity"] == "CRITICAL"]
    high_fails = [f for f in findings if f["status"] == "FAIL" and f["severity"] == "HIGH"]

    return {
        "framework": "pipe-security AD Ransomware Readiness v1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "domain": config.get_active_domain(),
        "score": final_score,
        "grade": grade,
        "interpretation": interpretation,
        "kill_chain_coverage": stages,
        "summary": {
            "total_checks": len(findings),
            "pass": sum(1 for f in findings if f["status"] == "PASS"),
            "fail": sum(1 for f in findings if f["status"] == "FAIL"),
            "warn": sum(1 for f in findings if f["status"] == "WARN"),
            "critical_fails": len(critical_fails),
            "high_fails": len(high_fails),
        },
        "critical_risks": [
            {"id": f["id"], "title": f["title"], "stage": f.get("stage"),
             "mitre": f.get("mitre"), "fix": f.get("ps_fix") or f.get("gpo_fix")}
            for f in critical_fails
        ],
        "findings": findings,
        "gpo_hardening_recommendations": {
            "priority_1_immediate": [
                "SMB Signing obligatorio (bloquea NTLM Relay)",
                "Deshabilitar SMBv1 (bloquea EternalBlue/WannaCry)",
                "LSASS RunAsPPL = 1 (bloquea mimikatz)",
                "WDigest UseLogonCredential = 0 (sin passwords en memoria)",
            ],
            "priority_2_short_term": [
                "Software Restriction Policies o AppLocker (bloquea ejecución desde TEMP/APPDATA)",
                "Windows Event Forwarding (WEF) a SIEM centralizado",
                "Audit Policy: Process Creation, Logon Events, Object Access",
                "Credential Guard via Device Guard GPO",
            ],
            "priority_3_medium_term": [
                "Microsoft Defender Attack Surface Reduction (ASR) rules",
                "BitLocker para todos los endpoints (protección datos en caso de robo físico)",
                "Tiered Administration Model (separar Tier 0 DC, Tier 1 Server, Tier 2 Workstation)",
                "PAW — Privileged Access Workstations para cuentas DA",
            ],
        },
    }


# ─── Entrypoint ───────────────────────────────────────────────────────────────

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
