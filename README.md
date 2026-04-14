# pipe-security — AD Security Auditor para Claude Desktop

Herramienta **gratuita** de auditoría de Active Directory que corre directamente en Claude Desktop.  
Sin suscripciones, sin APIs de pago, sin enviar datos a terceros.

---

## ¿Qué hace?

Desde una conversación con Claude podés pedirle:

- Assessment completo de seguridad AD con **score A-F y técnicas MITRE ATT&CK**
- Análisis de **Kerberoasting, AS-REP Roasting, delegación irrestricta**
- Política de contraseñas y **riesgo de password spray**
- **Domain Admins, Enterprise Admins, Backup Operators** — quién tiene qué
- Cuentas inactivas, service accounts sobreaprovisionadas
- GPOs y detección de hardening
- **Readiness anti-ransomware** con kill chain stages
- Auditoría del equipo local (SMB, RDP, Defender, LAPS)

Todo sin salir de Claude Desktop. Todo gratis.

---

## Requisitos

| Requisito | Costo | Link |
|---|---|---|
| Claude Desktop | Gratis | [claude.ai/download](https://claude.ai/download) |
| Python 3.10+ | Gratis | Se instala automáticamente |
| Acceso a la red del dominio | — | VPN o red local |
| Cuenta AD de solo lectura | — | Script incluido |

> El plan **gratuito de Claude** (~20-50 mensajes/día) es suficiente para un assessment completo.

---

## Instalación — 2 pasos

### Paso 1: Instalar el MCP (en el equipo del auditor)

Abrí **PowerShell como Administrador** y ejecutá:

```powershell
irm https://raw.githubusercontent.com/pabloaverbuj/pipe-security/main/install.ps1 | iex
```

Esto:
- Instala Python si no está presente
- Crea un entorno virtual aislado
- Instala pipe-security y sus dependencias
- Configura Claude Desktop automáticamente

**Reiniciá Claude Desktop** cuando termine.

---

### Paso 2: Crear cuenta de auditoría en AD (en un DC, como Domain Admin)

```powershell
# Descargar y ejecutar en el DC
irm https://raw.githubusercontent.com/pabloaverbuj/pipe-security/main/setup-ad-auditor.ps1 | iex
```

Esto crea el usuario `auditoria.mcp` con:
- Solo lectura en el dominio (usa los permisos de Domain Users)
- Contraseña segura generada automáticamente
- Sin posibilidad de modificar objetos AD

El script te muestra el usuario y contraseña para usar en el siguiente paso.

---

## Primer uso

Una vez instalado y con Claude Desktop reiniciado, abrí Claude y decí:

```
"agregá el dominio MIEMPRESA con DC 192.168.1.10, fqdn miempresa.local,
 usuario auditoria.mcp, password LaPasswordDelScript"
```

Luego pedí el assessment:

```
"hacé un ad_security_assessment_full"
```

```
"hacé un ad_ransomware_readiness"
```

---

## Herramientas disponibles

### Gestión de dominios
| Tool | Descripción |
|---|---|
| `domain_add` | Registrar un dominio (IP DC + credenciales) |
| `domain_remove` | Eliminar un dominio registrado |
| `domain_list` | Ver dominios configurados |
| `domain_switch` | Cambiar dominio activo |

### Assessment AD
| Tool | Descripción |
|---|---|
| `ad_security_assessment_full` | Assessment completo — score 0-100, grade A-F, MITRE |
| `ad_ransomware_readiness` | Kill chain anti-ransomware, GPO fixes |
| `ad_security_summary` | Resumen ejecutivo rápido |
| `ad_security_findings` | Hallazgos con remediación paso a paso |

### Auditoría granular
| Tool | Descripción |
|---|---|
| `ad_domain_overview` | Info general: DCs, nivel funcional, objetos |
| `ad_users_overview` | Usuarios: habilitados, sin expiración, AS-REP |
| `ad_privileged_groups` | Domain Admins, Enterprise Admins, Backup Operators |
| `ad_password_policy` | Longitud, complejidad, lockout, historial |
| `ad_kerberoastable` | Service accounts con SPN vulnerables |
| `ad_asrep_roastable` | Usuarios sin pre-autenticación Kerberos |
| `ad_stale_accounts` | Cuentas inactivas en N días |
| `ad_computers` | Equipos: OS legacy, delegación irrestricta |
| `ad_gpo_list` | Group Policy Objects del dominio |
| `ad_unconstrained_delegation` | Delegación Kerberos irrestricta |

### Equipo local
| Tool | Descripción |
|---|---|
| `local_security_summary` | Resumen de seguridad del equipo |
| `local_security_findings` | Hallazgos locales con remediación PS |
| `local_smb_config` | SMBv1, SMB signing, shares Everyone |
| `local_wdigest_check` | WDigest, LSA Protection, Credential Guard |
| `local_rdp_config` | RDP habilitado, NLA, puerto |
| `local_windows_defender` | Estado, firmas, tamper protection |
| `local_firewall_status` | Estado por perfil (Domain/Private/Public) |
| `local_laps_status` | LAPS instalado y configurado |

---

## Multidominio

Podés auditar múltiples clientes/dominios desde la misma instalación:

```
"agregá el dominio CLIENTE-A con DC 10.0.1.5, fqdn clientea.local, usuario auditor, password ..."
"agregá el dominio CLIENTE-B con DC 192.168.50.10, fqdn clienteb.com, usuario pipe.audit, password ..."
"cambiá al dominio CLIENTE-A"
"hacé el assessment"
```

Las credenciales se guardan en **Windows Credential Manager** — nunca en disco en texto claro.

---

## Seguridad y privacidad

- **Las credenciales** se guardan en Windows Credential Manager (mismo lugar que usa Chrome/Edge)
- **Todas las consultas son de solo lectura** — LDAP Read-Only, no modifica nada en AD
- **Sin telemetría** — el MCP no envía datos a ningún servidor externo
- **Los datos van de tu red a Claude** (Anthropic) — igual que cualquier conversación de Claude Desktop
- **Código abierto** — podés auditar todo el código en este repositorio

---

## Preguntas frecuentes

**¿Necesito ser Domain Admin para instalar el MCP?**  
No. Solo necesitás una cuenta de dominio con permisos de lectura (Domain Users es suficiente).

**¿El script setup-ad-auditor.ps1 requiere permisos elevados?**  
Sí, necesita correr como Domain Admin para crear el usuario. Solo hay que correrlo una vez.

**¿Funciona con dominios en la nube (Azure AD / Entra ID)?**  
No — este MCP audita AD on-premises via LDAP. Para Azure AD/M365 usá el MCP `m365-security`.

**¿Puedo correrlo desde una VPN?**  
Sí, siempre que el puerto 389 (LDAP) sea accesible al DC desde tu equipo.

**¿Qué versiones de AD soporta?**  
Windows Server 2008 R2 o superior (nivel funcional ≥ 4).

---

## Desinstalar

```powershell
irm https://raw.githubusercontent.com/pabloaverbuj/pipe-security/main/install.ps1 | iex -Uninstall
```

O manualmente:
1. Borrar la entrada `pipe-security` de `%APPDATA%\Claude\claude_desktop_config.json`
2. Borrar `%LOCALAPPDATA%\pipe-security\`

---

## Licencia

MIT — uso libre incluyendo uso comercial (consultorías, assessments para clientes).

---

*Desarrollado por Geo Labs Security*
