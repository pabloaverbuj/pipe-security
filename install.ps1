#Requires -Version 5.1
<#
.SYNOPSIS
    Instalador de pipe-security MCP para Claude Desktop.
    Herramienta gratuita de auditoría de Active Directory via Claude Desktop.

.DESCRIPTION
    Un solo comando instala todo:
    - pipe-security MCP en Claude Desktop
    - Detecta el dominio AD automáticamente
    - Crea la cuenta auditora (sin RSAT, via ADSI)
    - Configura el dominio en pipe-security listo para usar

.EXAMPLE
    # Instalación con un comando (como Admin):
    irm https://raw.githubusercontent.com/pabloaverbuj/pipe-security/main/install.ps1 | iex

.NOTES
    Autor: Geo Labs Security
    Versión: 2.0
    Licencia: MIT — uso libre incluyendo comercial
#>

[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$Silent
)

$ErrorActionPreference = "Stop"
$INSTALL_DIR  = "$env:LOCALAPPDATA\pipe-security"
$PYTHON_MIN   = [Version]"3.10"
$REPO_URL     = "https://github.com/pabloaverbuj/pipe-security"
$AUDIT_USER   = "auditoria.mcp"

# ── Helpers ───────────────────────────────────────────────────────────────────

function Write-Step($msg)  { Write-Host "  -> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)    { Write-Host "  OK $msg" -ForegroundColor Green }
function Write-Warn($msg)  { Write-Host "  !  $msg" -ForegroundColor Yellow }
function Write-Err($msg)   { Write-Host "  X  $msg" -ForegroundColor Red }

function Show-Banner {
    Write-Host ""
    Write-Host "  +================================================+" -ForegroundColor DarkCyan
    Write-Host "  |   pipe-security MCP -- AD Auditor             |" -ForegroundColor DarkCyan
    Write-Host "  |   Auditoria de Active Directory               |" -ForegroundColor DarkCyan
    Write-Host "  |   Instalador v2.0 -- Uso Libre (MIT)          |" -ForegroundColor DarkCyan
    Write-Host "  +================================================+" -ForegroundColor DarkCyan
    Write-Host ""
}

function Get-PythonExe {
    $pyCmd  = Get-Command python  -ErrorAction SilentlyContinue
    $py3Cmd = Get-Command python3 -ErrorAction SilentlyContinue
    $candidates = @(
        $(if ($pyCmd)  { $pyCmd.Source  }),
        $(if ($py3Cmd) { $py3Cmd.Source }),
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
        "C:\Python311\python.exe",
        "C:\Python312\python.exe"
    ) | Where-Object { $_ -and (Test-Path $_ -ErrorAction SilentlyContinue) }

    foreach ($py in $candidates) {
        try {
            $ver = & $py -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
            if ($ver -and [Version]$ver -ge $PYTHON_MIN) { return $py }
        } catch {}
    }
    return $null
}

function Install-Python {
    Write-Step "Python 3.11+ no encontrado -- instalando via winget..."
    try {
        winget install --id Python.Python.3.11 --silent --accept-package-agreements --accept-source-agreements
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("PATH","User")
        $py = Get-PythonExe
        if ($py) { return $py }
    } catch {}

    Write-Step "winget fallo -- descargando Python 3.11 directamente..."
    $installer = "$env:TEMP\python-3.11.9-amd64.exe"
    Invoke-WebRequest "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe" -OutFile $installer
    Start-Process $installer -ArgumentList "/quiet InstallAllUsers=0 PrependPath=1" -Wait
    Remove-Item $installer -Force
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("PATH","User")
    return Get-PythonExe
}

function Get-ClaudeConfig {
    $paths = @(
        "$env:APPDATA\Claude\claude_desktop_config.json",
        "$env:LOCALAPPDATA\AnthropicClaude\claude_desktop_config.json"
    )
    foreach ($p in $paths) { if (Test-Path $p) { return $p } }
    $defaultPath = "$env:APPDATA\Claude\claude_desktop_config.json"
    New-Item -Path (Split-Path $defaultPath) -ItemType Directory -Force | Out-Null
    if (-not (Test-Path $defaultPath)) {
        '{"mcpServers":{}}' | Set-Content $defaultPath -Encoding UTF8
    }
    return $defaultPath
}

# ── Deteccion de dominio (sin modulos extra) ──────────────────────────────────

function Get-DomainInfo {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    if (-not $cs -or -not $cs.PartOfDomain) { return $null }

    $fqdn    = $env:USERDNSDOMAIN
    $netbios = $env:USERDOMAIN
    $dcName  = ($env:LOGONSERVER).TrimStart('\')

    # Resolver IP del DC
    $dcIP = $null
    try {
        $addresses = [System.Net.Dns]::GetHostAddresses($dcName) |
                     Where-Object { $_.AddressFamily -eq 'InterNetwork' }
        $dcIP = ($addresses | Select-Object -First 1).IPAddressToString
    } catch {}

    # Fallback: intentar con el FQDN del dominio
    if (-not $dcIP) {
        try {
            $addresses = [System.Net.Dns]::GetHostAddresses($fqdn) |
                         Where-Object { $_.AddressFamily -eq 'InterNetwork' }
            $dcIP = ($addresses | Select-Object -First 1).IPAddressToString
        } catch {}
    }

    return @{
        fqdn    = $fqdn
        netbios = $netbios
        dcName  = $dcName
        dcIP    = $dcIP
        dn      = "DC=" + ($fqdn -replace "\.", ",DC=")
    }
}

# ── Crear cuenta auditora con credenciales de Domain Admin ───────────────────

function New-AuditAccount($domain, $auditPassword) {
    $dn   = $domain.dn
    $fqdn = $domain.fqdn

    # Pedir credenciales de Domain Admin via popup nativo de Windows
    Write-Host ""
    Write-Host "  Se necesitan credenciales de Domain Admin para crear la cuenta auditora." -ForegroundColor Yellow
    Write-Host "  (La cuenta auditora solo tendra permisos de lectura)" -ForegroundColor DarkGray
    Write-Host ""

    try {
        $cred = Get-Credential -Message "Ingresa credenciales de Domain Admin para $fqdn" `
                               -UserName "$($domain.netbios)\Administrador"
    } catch {
        Write-Warn "Credenciales canceladas -- saltando creacion de cuenta"
        return $false
    }

    if (-not $cred) {
        Write-Warn "Credenciales canceladas -- saltando creacion de cuenta"
        return $false
    }

    $daUser = $cred.UserName
    $daPass = $cred.GetNetworkCredential().Password
    $ldapPath = "LDAP://CN=Users,$dn"

    try {
        $container = New-Object System.DirectoryServices.DirectoryEntry($ldapPath, $daUser, $daPass)

        # Verificar que la conexion funciono
        if (-not $container.Name) {
            Write-Warn "No se pudo conectar al AD -- verificar credenciales o conectividad al DC"
            return $false
        }

        # Verificar si el usuario ya existe
        $existingPath = "LDAP://CN=$AUDIT_USER,CN=Users,$dn"
        try {
            $existing = New-Object System.DirectoryServices.DirectoryEntry($existingPath, $daUser, $daPass)
            if ($existing.sAMAccountName) {
                Write-Warn "Usuario '$AUDIT_USER' ya existe -- actualizando contrasena..."
                $existing.Invoke("SetPassword", $auditPassword)
                $existing.CommitChanges()
                Write-Ok "Contrasena actualizada"
                return $true
            }
        } catch {}

        # Crear usuario
        $user = $container.Children.Add("CN=$AUDIT_USER", "user")
        $user.Properties["sAMAccountName"].Value = $AUDIT_USER
        $user.Properties["userPrincipalName"].Value = "$AUDIT_USER@$fqdn"
        $user.Properties["description"].Value = "Cuenta auditoria pipe-security MCP -- solo lectura -- NO BORRAR"
        $user.CommitChanges()

        # Establecer contrasena y habilitar
        $user.Invoke("SetPassword", $auditPassword)
        # 66048 = 512 (normal account) + 65536 (password never expires)
        $user.Properties["userAccountControl"].Value = 66048
        $user.CommitChanges()

        Write-Ok "Usuario '$AUDIT_USER' creado en AD"
        return $true

    } catch {
        $msg = $_.Exception.Message
        if ($msg -match "Access is denied|0x80070005|Logon failure") {
            Write-Warn "Credenciales incorrectas o sin permisos de Domain Admin"
        } elseif ($msg -match "already exists|00002071") {
            Write-Warn "El usuario ya existe -- intenta correr el script de nuevo"
        } else {
            Write-Warn "Error: $msg"
        }
        return $false
    }
}

# ── Registrar dominio en pipe-security ────────────────────────────────────────

function Register-Domain($venvPython, $domain, $password) {
    $name   = $domain.netbios
    $dcIP   = $domain.dcIP
    $fqdn   = $domain.fqdn

    $script = @"
from pipe_security.config import ConfigManager
c = ConfigManager()
c.add_domain('$name', '$dcIP', '$fqdn', '$AUDIT_USER', '$password')
if not c.get_active_domain():
    c.set_active_domain('$name')
print('ok')
"@
    $result = & $venvPython -c $script 2>&1
    return ($result -eq "ok")
}

# ── Generar contrasena segura ─────────────────────────────────────────────────

function New-SecurePassword {
    $chars = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%"
    return -join (1..24 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
}

# ── Desinstalacion ────────────────────────────────────────────────────────────

function Uninstall-PipeSecurity {
    Write-Host "`n  Desinstalando pipe-security..." -ForegroundColor Yellow
    $cfgPath = Get-ClaudeConfig
    if (Test-Path $cfgPath) {
        $cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
        if ($cfg.mcpServers.PSObject.Properties.Name -contains "pipe-security") {
            $cfg.mcpServers.PSObject.Properties.Remove("pipe-security")
            $cfg | ConvertTo-Json -Depth 10 | Set-Content $cfgPath -Encoding UTF8
            Write-Ok "Removido de claude_desktop_config.json"
        }
    }
    if (Test-Path $INSTALL_DIR) {
        Remove-Item $INSTALL_DIR -Recurse -Force
        Write-Ok "Directorio $INSTALL_DIR eliminado"
    }
    Write-Host "`n  pipe-security desinstalado correctamente." -ForegroundColor Green
    Write-Warn "Reinicia Claude Desktop para que los cambios surtan efecto."
}

# ── Instalacion ───────────────────────────────────────────────────────────────

function Install-PipeSecurity {
    Show-Banner

    # 1. Claude Desktop
    Write-Step "Verificando Claude Desktop..."
    $claudeConfig = Get-ClaudeConfig
    Write-Ok "Config de Claude: $claudeConfig"

    # 2. Python
    Write-Step "Verificando Python 3.10+..."
    $python = Get-PythonExe
    if (-not $python) {
        Write-Warn "Python 3.10+ no encontrado"
        if (-not $Silent) {
            $resp = Read-Host "  Instalar Python 3.11 automaticamente? (S/n)"
            if ($resp -match "^[Nn]") {
                Write-Err "Python requerido. Descargalo de https://python.org/downloads"
                exit 1
            }
        }
        $python = Install-Python
        if (-not $python) {
            Write-Err "No se pudo instalar Python. Instalalo manualmente desde https://python.org"
            exit 1
        }
    }
    $pyVer = & $python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"
    Write-Ok "Python $pyVer en: $python"

    # 3. Crear venv
    Write-Step "Creando entorno virtual en $INSTALL_DIR ..."
    if (Test-Path $INSTALL_DIR) { Remove-Item $INSTALL_DIR -Recurse -Force }
    & $python -m venv $INSTALL_DIR
    $venvPython = "$INSTALL_DIR\Scripts\python.exe"
    $venvPip    = "$INSTALL_DIR\Scripts\pip.exe"
    Write-Ok "Entorno virtual creado"

    # 4. Instalar pipe-security
    Write-Step "Instalando pipe-security..."
    & $venvPip install --quiet --upgrade pip
    try {
        & $venvPip install --quiet "pipe-security @ git+$REPO_URL.git"
        Write-Ok "pipe-security instalado desde GitHub"
    } catch {
        Write-Warn "Instalacion desde GitHub fallo -- instalando dependencias base..."
        $deps = @("mcp>=1.0.0", "ldap3>=2.9.1", "keyring>=24.0.0", "click>=8.1.0", "rich>=13.0.0")
        foreach ($dep in $deps) { & $venvPip install --quiet $dep }
        Write-Warn "Descarga el codigo de $REPO_URL y ejecuta: pip install -e ."
    }

    # 5. Verificar modulo
    Write-Step "Verificando instalacion..."
    $testResult = & $venvPython -c "import pipe_security; print('ok')" 2>&1
    if ($testResult -ne "ok") {
        Write-Err "El modulo no cargo correctamente: $testResult"
        exit 1
    }
    Write-Ok "Modulo pipe_security verificado"

    # 6. Configurar Claude Desktop
    Write-Step "Configurando Claude Desktop..."
    $cfg = Get-Content $claudeConfig -Raw | ConvertFrom-Json
    if (-not $cfg.PSObject.Properties.Name.Contains("mcpServers")) {
        $cfg | Add-Member -NotePropertyName "mcpServers" -NotePropertyValue ([PSCustomObject]@{})
    }
    $serverConfig = [PSCustomObject]@{
        command = ($venvPython -replace "\\", "/")
        args    = @("-m", "pipe_security.server")
    }
    $cfg.mcpServers | Add-Member -NotePropertyName "pipe-security" -NotePropertyValue $serverConfig -Force
    $cfg | ConvertTo-Json -Depth 10 | Set-Content $claudeConfig -Encoding UTF8
    Write-Ok "Claude Desktop configurado"

    # 7. Detectar dominio AD
    Write-Host ""
    Write-Host "  -- Configuracion de dominio AD --" -ForegroundColor White
    $domain = Get-DomainInfo

    $domainConfigured = $false

    if (-not $domain) {
        Write-Warn "Este equipo no esta unido a un dominio AD"
        Write-Host ""
        Write-Host "  Para agregar un dominio manualmente, decile a Claude:" -ForegroundColor Cyan
        Write-Host '  "agrega el dominio NOMBRE con DC 192.168.1.10, fqdn empresa.local,' -ForegroundColor DarkGray
        Write-Host '   usuario auditoria.mcp, password TuPassword"' -ForegroundColor DarkGray

    } elseif (-not $domain.dcIP) {
        Write-Warn "Dominio detectado ($($domain.fqdn)) pero no se pudo resolver la IP del DC"
        Write-Host "  Agrega el dominio manualmente desde Claude Desktop." -ForegroundColor Yellow

    } else {
        Write-Ok "Dominio detectado: $($domain.fqdn) | DC: $($domain.dcName) ($($domain.dcIP))"
        Write-Host ""

        # Generar contrasena para la cuenta auditora
        $auditPassword = New-SecurePassword

        # Intentar crear cuenta auditora en AD
        Write-Step "Creando cuenta auditora '$AUDIT_USER' en AD..."
        $accountCreated = New-AuditAccount $domain $auditPassword

        if ($accountCreated) {
            # Registrar dominio en pipe-security automaticamente
            Write-Step "Registrando dominio en pipe-security..."
            $registered = Register-Domain $venvPython $domain $auditPassword
            if ($registered) {
                Write-Ok "Dominio '$($domain.netbios)' configurado automaticamente"
                $domainConfigured = $true
            } else {
                Write-Warn "No se pudo registrar el dominio automaticamente"
            }
        } else {
            Write-Host ""
            Write-Host "  La cuenta auditora no se creo -- agrega el dominio manualmente desde Claude:" -ForegroundColor Yellow
            Write-Host "  `"agrega el dominio $($domain.netbios) con DC $($domain.dcIP), fqdn $($domain.fqdn)," -ForegroundColor DarkGray
            Write-Host "   usuario [tu-usuario-ad], password [tu-password]`"" -ForegroundColor DarkGray
        }
    }

    # 8. Resumen final
    Write-Host ""
    Write-Host "  +============================================================+" -ForegroundColor Green
    Write-Host "  |   pipe-security instalado correctamente                   |" -ForegroundColor Green
    Write-Host "  +============================================================+" -ForegroundColor Green
    Write-Host ""

    if ($domainConfigured) {
        Write-Host "  TODO LISTO. Solo queda:" -ForegroundColor White
        Write-Host ""
        Write-Host "  1. Reinicia Claude Desktop" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  2. Pide el assessment:" -ForegroundColor Cyan
        Write-Host '     "hace un ad_security_assessment_full"' -ForegroundColor DarkGray
        Write-Host '     "hace un ad_ransomware_readiness"' -ForegroundColor DarkGray
    } else {
        Write-Host "  PROXIMOS PASOS:" -ForegroundColor White
        Write-Host ""
        Write-Host "  1. Reinicia Claude Desktop" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  2. Agrega tu dominio desde Claude (ver instrucciones arriba)" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  3. Pide el assessment:" -ForegroundColor Cyan
        Write-Host '     "hace un ad_security_assessment_full"' -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "  Documentacion: $REPO_URL" -ForegroundColor DarkGray
    Write-Host "  Licencia: MIT -- uso libre incluyendo comercial" -ForegroundColor DarkGray
    Write-Host ""
}

# ── Entry point ───────────────────────────────────────────────────────────────

if ($Uninstall) {
    Uninstall-PipeSecurity
} else {
    Install-PipeSecurity
}
