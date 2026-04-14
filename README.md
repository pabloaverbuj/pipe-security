<div align="center">

# 🔐 pipe-security

**Auditoría de Active Directory directamente desde Claude Desktop**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![MCP](https://img.shields.io/badge/Claude-MCP%20Server-D97706?logo=anthropic&logoColor=white)](https://modelcontextprotocol.io)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org)
[![Gratis](https://img.shields.io/badge/Precio-100%25%20Gratis-brightgreen)]()

*Sin suscripciones · Sin APIs de pago · Sin datos a terceros · Código abierto*

</div>

---

## ¿Qué hace?

Convierte a Claude en un auditor de Active Directory. Desde el chat podés pedir assessments completos, detectar vectores de ataque y obtener remediaciones concretas — sin instalar herramientas adicionales, sin consolas de administración.

```
"hacé un assessment completo de seguridad del dominio"
"¿hay cuentas Kerberoasteables con privilegios elevados?"
"analizá el riesgo de ransomware y dame las GPOs de mitigación"
"listá todos los Domain Admins inactivos hace más de 90 días"
```

---

## 🛡️ Qué detecta

| Categoría | Checks |
|---|---|
| **Identidades** | Cuentas inactivas, admins sin uso, AS-REP Roastable |
| **Kerberos** | Kerberoastable (T1558.003), AS-REP (T1558.004), delegación irrestricta |
| **Privilegios** | Domain Admins, Enterprise Admins, Backup Operators |
| **Contraseñas** | Longitud mínima, complejidad, lockout, historial, password spray |
| **GPOs** | Cantidad, hardening detectado, SMB Signing, LSASS PPL |
| **Endpoints** | Windows legado (XP/2003/2008), delegación irrestricta por equipo |
| **Ransomware** | Kill chain completo: Initial Access → Credential Theft → Impact |
| **Local** | SMBv1, WDigest, RDP, Defender, LAPS, firewall |

Cada hallazgo incluye **técnica MITRE ATT&CK**, **severidad** y **remediación paso a paso**.

---

## ⚡ Instalación — 1 comando

Abrí **PowerShell como Administrador** y ejecutá:

```powershell
irm https://raw.githubusercontent.com/pabloaverbuj/pipe-security/main/install.ps1 | iex
```

El script hace todo automáticamente:

- ✅ Instala Python 3.11 si no está presente
- ✅ Crea un entorno virtual aislado
- ✅ Instala pipe-security y dependencias
- ✅ Configura Claude Desktop
- ✅ Detecta el dominio AD automáticamente
- ✅ Crea la cuenta auditora `auditoria.mcp` (pide credenciales de Domain Admin via popup)
- ✅ Registra el dominio en pipe-security listo para usar

**Reiniciá Claude Desktop** — listo para auditar.

> **Sin acceso a un dominio AD todavía?** El script instala igual y podés agregar el dominio después desde Claude.

---

## 💬 Primeros pasos

Una vez instalado, abrí Claude Desktop y probá:

```
"hacé un ad_security_assessment_full"
```

```
"hacé un ad_ransomware_readiness"
```

```
"mostrá los grupos privilegiados del dominio"
```

---

## 🛠️ Herramientas disponibles

### Gestión de dominios
| Tool | Descripción |
|---|---|
| `domain_add` | Registrar dominio (IP DC + credenciales) |
| `domain_remove` | Eliminar un dominio registrado |
| `domain_list` | Ver dominios configurados y activo |
| `domain_switch` | Cambiar dominio activo |

### Assessment completo
| Tool | Descripción |
|---|---|
| `ad_security_assessment_full` | Score 0-100, grade A-F, 6 dominios con MITRE |
| `ad_ransomware_readiness` | Kill chain completo + GPO fixes prioritizados |
| `ad_security_summary` | Resumen ejecutivo rápido |
| `ad_security_findings` | Hallazgos con remediación detallada |

### Auditoría granular
| Tool | Descripción |
|---|---|
| `ad_domain_overview` | DCs, nivel funcional, cantidad de objetos |
| `ad_users_overview` | Habilitados, sin expiración, AS-REP roastable |
| `ad_privileged_groups` | Domain Admins, Enterprise Admins, Backup Operators |
| `ad_password_policy` | Longitud, complejidad, lockout, historial |
| `ad_kerberoastable` | Service accounts con SPN vulnerables |
| `ad_asrep_roastable` | Cuentas sin pre-autenticación Kerberos |
| `ad_stale_accounts` | Cuentas inactivas por N días |
| `ad_computers` | OS legacy, delegación irrestricta |
| `ad_gpo_list` | Group Policy Objects del dominio |
| `ad_unconstrained_delegation` | Delegación Kerberos irrestricta |

### Equipo local
| Tool | Descripción |
|---|---|
| `local_security_summary` | Resumen de seguridad del equipo |
| `local_security_findings` | Hallazgos con remediación PowerShell |
| `local_smb_config` | SMBv1, SMB signing, shares Everyone |
| `local_wdigest_check` | WDigest, LSA Protection, Credential Guard |
| `local_rdp_config` | RDP habilitado, NLA, puerto |
| `local_windows_defender` | Estado, firmas, tamper protection |
| `local_firewall_status` | Estado por perfil (Domain/Private/Public) |
| `local_laps_status` | LAPS instalado y configurado |

---

## 🏢 Multidominio

Auditá múltiples clientes desde la misma instalación:

```
"agregá el dominio CLIENTE-A con DC 10.0.1.5, fqdn clientea.local, usuario auditor, password ..."
"cambiá al dominio CLIENTE-B"
"hacé el assessment"
```

Las credenciales se guardan en **Windows Credential Manager** — nunca en disco en texto claro.

---

## 📋 Requisitos

| Requisito | Detalle |
|---|---|
| Claude Desktop | [claude.ai/download](https://claude.ai/download) — plan gratuito suficiente |
| Python 3.10+ | Se instala automáticamente si no está |
| Acceso LDAP (puerto 389) | VPN o red local al DC |
| Windows 10/11 | El MCP corre en el equipo del auditor |

---

## 🔒 Seguridad y privacidad

- **Solo lectura** — LDAP read-only, no modifica nada en AD
- **Credenciales en Credential Manager** — mismo almacén que Chrome/Edge/Windows
- **Sin telemetría** — no envía datos a ningún servidor externo
- **Código abierto** — auditá todo en este repositorio

---

## ❓ FAQ

**¿Necesito ser Domain Admin para usar el MCP?**
No. La cuenta auditora usa permisos de Domain Users (solo lectura). El script de instalación pide credenciales de DA solo para crear esa cuenta — una vez.

**¿Funciona con Azure AD / Entra ID?**
No — este MCP audita AD on-premises via LDAP. Para Microsoft 365 usá [`m365-security`](https://github.com/pabloaverbuj/m365-security-mcp).

**¿Funciona por VPN?**
Sí, siempre que el puerto 389 (LDAP) sea accesible al DC.

**¿Qué versiones de AD soporta?**
Windows Server 2008 R2 o superior (nivel funcional ≥ 4).

---

## 🗑️ Desinstalar

```powershell
irm https://raw.githubusercontent.com/pabloaverbuj/pipe-security/main/install.ps1 | iex -Uninstall
```

---

<div align="center">

MIT License — uso libre incluyendo comercial (consultorías, assessments para clientes)

</div>
