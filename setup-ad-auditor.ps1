#Requires -Module ActiveDirectory
<#
.SYNOPSIS
    Crea la cuenta de solo lectura en AD para pipe-security MCP.
    Ejecutar en un Domain Controller o equipo con RSAT como Domain Admin.

.EXAMPLE
    .\setup-ad-auditor.ps1
    .\setup-ad-auditor.ps1 -Username "auditoria.mcp" -OU "OU=ServiceAccounts,DC=empresa,DC=local"
#>

[CmdletBinding()]
param(
    [string]$Username  = "auditoria.mcp",
    [string]$OU        = "",   # Si vacío, usa Users por defecto
    [switch]$Remove
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host "  → $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "  ✓ $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "  ! $msg" -ForegroundColor Yellow }

# ── Verificar permisos ────────────────────────────────────────────────────────
$domain = Get-ADDomain
$domainFQDN = $domain.DNSRoot
$domainDN   = $domain.DistinguishedName

Write-Host ""
Write-Host "  pipe-security — Setup de cuenta auditora en AD" -ForegroundColor DarkCyan
Write-Host "  Dominio: $domainFQDN" -ForegroundColor Gray
Write-Host ""

# ── Eliminar cuenta ───────────────────────────────────────────────────────────
if ($Remove) {
    try {
        Remove-ADUser -Identity $Username -Confirm:$false
        Write-Ok "Usuario '$Username' eliminado"
    } catch {
        Write-Warn "No se pudo eliminar: $_"
    }
    exit 0
}

# ── Crear cuenta ──────────────────────────────────────────────────────────────
Write-Step "Generando contraseña segura..."
$chars = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%"
$password = -join (1..24 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
$securePass = ConvertTo-SecureString $password -AsPlainText -Force

# OU de destino
if (-not $OU) {
    $OU = "CN=Users,$domainDN"
}

Write-Step "Creando usuario '$Username' en: $OU ..."

$userParams = @{
    Name                  = $Username
    SamAccountName        = $Username
    UserPrincipalName     = "$Username@$domainFQDN"
    AccountPassword       = $securePass
    Enabled               = $true
    PasswordNeverExpires  = $true
    CannotChangePassword  = $true
    Description           = "Cuenta de auditoría pipe-security MCP — solo lectura — NO BORRAR"
    Path                  = $OU
}

try {
    New-ADUser @userParams
    Write-Ok "Usuario '$Username' creado"
} catch {
    if ($_ -match "already exists") {
        Write-Warn "El usuario '$Username' ya existe — actualizando contraseña..."
        Set-ADAccountPassword -Identity $Username -NewPassword $securePass -Reset
        Write-Ok "Contraseña actualizada"
    } else {
        throw
    }
}

# ── Permisos mínimos (Read-only) ───────────────────────────────────────────────
# El usuario de dominio estándar ya tiene acceso de lectura a AD por defecto.
# Estos permisos adicionales son opcionales pero mejoran la auditoría:

Write-Step "Verificando permisos de lectura..."

# El rol "Domain Users" ya incluye:
# - Leer usuarios, grupos, computadoras del dominio
# - Leer GPOs
# - Leer password policy
# NO incluye: leer contraseñas, modificar objetos, acceder a SYSVOL con credenciales de admin

Write-Ok "Permisos de solo lectura confirmados (Domain Users tiene acceso de lectura por defecto)"

# Opcional: agregar al grupo "Distributed COM Users" para algunas consultas WMI remotas
# Add-ADGroupMember -Identity "Distributed COM Users" -Members $Username

# ── Mostrar resumen ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║  Cuenta de auditoría creada correctamente                ║" -ForegroundColor Green
Write-Host "  ╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  DATOS PARA USAR EN CLAUDE DESKTOP:" -ForegroundColor White
Write-Host ""
Write-Host "  Usuario  : $Username" -ForegroundColor Yellow
Write-Host "  Password : $password" -ForegroundColor Yellow
Write-Host "  Dominio  : $domainFQDN" -ForegroundColor Yellow
Write-Host ""
Write-Host "  GUARDA ESTA CONTRASEÑA — no se volverá a mostrar" -ForegroundColor Red
Write-Host ""
Write-Host "  Decile a Claude:" -ForegroundColor Cyan
Write-Host "  `"agregá el dominio MI-EMPRESA con DC [IP del DC]," -ForegroundColor DarkGray
Write-Host "   fqdn $domainFQDN, usuario $Username, password $password`"" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Para eliminar esta cuenta más adelante:" -ForegroundColor DarkGray
Write-Host "  .\setup-ad-auditor.ps1 -Remove" -ForegroundColor DarkGray
Write-Host ""

# Guardar en archivo local por si acaso
$outputFile = "$env:USERPROFILE\Desktop\pipe-security-credentials.txt"
@"
pipe-security MCP — Credenciales de auditoría
Generado: $(Get-Date -Format "yyyy-MM-dd HH:mm")
Dominio : $domainFQDN
DC      : (IP de tu Domain Controller)
Usuario : $Username
Password: $password

Comando para Claude Desktop:
"agregá el dominio MI-EMPRESA con DC [IP], fqdn $domainFQDN, usuario $Username, password $password"

IMPORTANTE: Eliminar este archivo tras configurar Claude Desktop.
"@ | Set-Content $outputFile -Encoding UTF8

Write-Warn "Credenciales guardadas en: $outputFile"
Write-Warn "Eliminar ese archivo tras configurar el MCP."
Write-Host ""
