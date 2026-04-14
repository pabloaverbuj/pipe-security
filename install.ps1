#Requires -Version 5.1
<#
.SYNOPSIS
    Instalador de pipe-security MCP para Claude Desktop.
    Herramienta gratuita de auditoría de Active Directory via Claude Desktop.

.DESCRIPTION
    Instala pipe-security MCP en Claude Desktop para auditar dominios AD.
    Requiere: Claude Desktop (gratis), conexión a la red del dominio.

.EXAMPLE
    # Instalación con un comando (como Admin):
    irm https://raw.githubusercontent.com/pabloaverbuj/pipe-security/main/install.ps1 | iex

.NOTES
    Autor: Geo Labs Security
    Versión: 1.0
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
$PACKAGE_NAME = "pipe-security"

# ── Helpers ───────────────────────────────────────────────────────────────────

function Write-Step($msg)  { Write-Host "  → $msg" -ForegroundColor Cyan }
function Write-Ok($msg)    { Write-Host "  ✓ $msg" -ForegroundColor Green }
function Write-Warn($msg)  { Write-Host "  ! $msg" -ForegroundColor Yellow }
function Write-Err($msg)   { Write-Host "  ✗ $msg" -ForegroundColor Red }

function Show-Banner {
    Write-Host ""
    Write-Host "  ╔════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
    Write-Host "  ║       pipe-security MCP — AD Auditor           ║" -ForegroundColor DarkCyan
    Write-Host "  ║       Auditoría de Active Directory            ║" -ForegroundColor DarkCyan
    Write-Host "  ║       Instalador v1.0 — Uso Libre (MIT)        ║" -ForegroundColor DarkCyan
    Write-Host "  ╚════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
    Write-Host ""
}

function Get-PythonExe {
    # Busca Python 3.10+ instalado en el sistema
    $candidates = @(
        (Get-Command python -ErrorAction SilentlyContinue)?.Source,
        (Get-Command python3 -ErrorAction SilentlyContinue)?.Source,
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
            if ($ver -and [Version]$ver -ge $PYTHON_MIN) {
                return $py
            }
        } catch {}
    }
    return $null
}

function Install-Python {
    Write-Step "Python 3.11+ no encontrado — instalando via winget..."
    try {
        winget install --id Python.Python.3.11 --silent --accept-package-agreements --accept-source-agreements
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("PATH", "User")
        $py = Get-PythonExe
        if ($py) { return $py }
    } catch {}

    # Fallback: descarga directa
    Write-Step "winget falló — descargando Python 3.11 directamente..."
    $installer = "$env:TEMP\python-3.11.9-amd64.exe"
    Invoke-WebRequest "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe" -OutFile $installer
    Start-Process $installer -ArgumentList "/quiet InstallAllUsers=0 PrependPath=1" -Wait
    Remove-Item $installer -Force

    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("PATH", "User")
    return Get-PythonExe
}

function Get-ClaudeConfig {
    $paths = @(
        "$env:APPDATA\Claude\claude_desktop_config.json",
        "$env:LOCALAPPDATA\AnthropicClaude\claude_desktop_config.json"
    )
    foreach ($p in $paths) {
        if (Test-Path $p) { return $p }
    }
    # Crear el archivo si no existe pero Claude está instalado
    $claudeExe = Get-Command claude -ErrorAction SilentlyContinue
    if (-not $claudeExe) {
        $claudeExe = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" `
            -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match "Claude" } | Select-Object -First 1
    }
    $defaultPath = "$env:APPDATA\Claude\claude_desktop_config.json"
    New-Item -Path (Split-Path $defaultPath) -ItemType Directory -Force | Out-Null
    if (-not (Test-Path $defaultPath)) {
        '{"mcpServers":{}}' | Set-Content $defaultPath -Encoding UTF8
    }
    return $defaultPath
}

# ── Desinstalación ────────────────────────────────────────────────────────────

function Uninstall-PipeSecurity {
    Write-Host "`n  Desinstalando pipe-security..." -ForegroundColor Yellow

    # Quitar del config de Claude
    $cfgPath = Get-ClaudeConfig
    if (Test-Path $cfgPath) {
        $cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
        if ($cfg.mcpServers.PSObject.Properties.Name -contains "pipe-security") {
            $cfg.mcpServers.PSObject.Properties.Remove("pipe-security")
            $cfg | ConvertTo-Json -Depth 10 | Set-Content $cfgPath -Encoding UTF8
            Write-Ok "Removido de claude_desktop_config.json"
        }
    }

    # Borrar directorio de instalación
    if (Test-Path $INSTALL_DIR) {
        Remove-Item $INSTALL_DIR -Recurse -Force
        Write-Ok "Directorio $INSTALL_DIR eliminado"
    }

    Write-Host "`n  pipe-security desinstalado correctamente." -ForegroundColor Green
    Write-Warn "Reiniciá Claude Desktop para que los cambios surtan efecto."
}

# ── Instalación ───────────────────────────────────────────────────────────────

function Install-PipeSecurity {
    Show-Banner

    # 1. Verificar Claude Desktop
    Write-Step "Verificando Claude Desktop..."
    $claudeConfig = Get-ClaudeConfig
    Write-Ok "Config de Claude: $claudeConfig"

    # 2. Python
    Write-Step "Verificando Python 3.10+..."
    $python = Get-PythonExe
    if (-not $python) {
        Write-Warn "Python 3.10+ no encontrado"
        if (-not $Silent) {
            $resp = Read-Host "  ¿Instalar Python 3.11 automáticamente? (S/n)"
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

    # 3. Crear venv en INSTALL_DIR
    Write-Step "Creando entorno virtual en $INSTALL_DIR ..."
    if (Test-Path $INSTALL_DIR) {
        Remove-Item $INSTALL_DIR -Recurse -Force
    }
    & $python -m venv $INSTALL_DIR
    $venvPython = "$INSTALL_DIR\Scripts\python.exe"
    $venvPip    = "$INSTALL_DIR\Scripts\pip.exe"
    Write-Ok "Entorno virtual creado"

    # 4. Instalar pipe-security
    Write-Step "Instalando pipe-security desde GitHub..."
    try {
        # Intentar instalar desde GitHub (requiere git o soporta zip)
        & $venvPip install --quiet --upgrade pip
        & $venvPip install --quiet "pipe-security @ git+$REPO_URL.git"
        Write-Ok "pipe-security instalado desde GitHub"
    } catch {
        # Fallback: instalar dependencias manualmente si no hay git
        Write-Warn "Instalación desde GitHub falló — instalando dependencias base..."
        $deps = @("mcp>=1.0.0", "ldap3>=2.9.1", "keyring>=24.0.0", "click>=8.1.0", "rich>=13.0.0")
        foreach ($dep in $deps) {
            & $venvPip install --quiet $dep
        }
        Write-Warn "Descargá el código de $REPO_URL y ejecutá: pip install -e ."
    }

    # 5. Verificar que el módulo funciona
    Write-Step "Verificando instalación..."
    $testResult = & $venvPython -c "import pipe_security; print('ok')" 2>&1
    if ($testResult -ne "ok") {
        Write-Err "El módulo no cargó correctamente: $testResult"
        exit 1
    }
    Write-Ok "Módulo pipe_security verificado"

    # 6. Configurar Claude Desktop
    Write-Step "Configurando Claude Desktop..."
    $cfg = Get-Content $claudeConfig -Raw | ConvertFrom-Json

    # Asegurar que mcpServers existe
    if (-not $cfg.PSObject.Properties.Name.Contains("mcpServers")) {
        $cfg | Add-Member -NotePropertyName "mcpServers" -NotePropertyValue ([PSCustomObject]@{})
    }

    # Agregar pipe-security
    $serverConfig = [PSCustomObject]@{
        command = $venvPython -replace "\\", "/"
        args    = @("-m", "pipe_security.server")
    }

    $cfg.mcpServers | Add-Member -NotePropertyName "pipe-security" `
        -NotePropertyValue $serverConfig -Force

    $cfg | ConvertTo-Json -Depth 10 | Set-Content $claudeConfig -Encoding UTF8
    Write-Ok "Claude Desktop configurado"

    # 7. Mostrar resumen
    Write-Host ""
    Write-Host "  ╔════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║   ✓  pipe-security instalado correctamente            ║" -ForegroundColor Green
    Write-Host "  ╚════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "  PRÓXIMOS PASOS:" -ForegroundColor White
    Write-Host ""
    Write-Host "  1. Reiniciá Claude Desktop" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  2. Creá una cuenta de auditoría en tu AD (5 segundos):" -ForegroundColor Cyan
    Write-Host "     New-ADUser -Name 'auditoria.mcp' -AccountPassword (Read-Host -AsSecureString) -Enabled `$true" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  3. Decile a Claude:" -ForegroundColor Cyan
    Write-Host '     "agregá el dominio NOMBRE con DC 192.168.1.10, fqdn empresa.local,' -ForegroundColor DarkGray
    Write-Host '      usuario auditoria.mcp, password TuPassword"' -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  4. Pedí el assessment:" -ForegroundColor Cyan
    Write-Host '     "hacé un ad_security_assessment_full"' -ForegroundColor DarkGray
    Write-Host '     "hacé un ad_ransomware_readiness"' -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  HERRAMIENTAS DISPONIBLES:" -ForegroundColor White
    Write-Host "  • domain_add / domain_remove   — gestión multidominio" -ForegroundColor Gray
    Write-Host "  • ad_security_assessment_full  — assessment completo con score A-F" -ForegroundColor Gray
    Write-Host "  • ad_ransomware_readiness      — kill chain anti-ransomware" -ForegroundColor Gray
    Write-Host "  • ad_users_overview            — auditoría de usuarios" -ForegroundColor Gray
    Write-Host "  • ad_privileged_groups         — Domain Admins, Enterprise Admins" -ForegroundColor Gray
    Write-Host "  • ad_kerberoastable            — cuentas vulnerables a Kerberoasting" -ForegroundColor Gray
    Write-Host "  • ad_asrep_roastable           — cuentas AS-REP Roastable" -ForegroundColor Gray
    Write-Host "  • ad_password_policy           — política de contraseñas" -ForegroundColor Gray
    Write-Host "  • ad_gpo_list                  — Group Policy Objects" -ForegroundColor Gray
    Write-Host "  • local_security_summary       — seguridad del equipo local" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Documentación: $REPO_URL" -ForegroundColor DarkGray
    Write-Host "  Licencia: MIT — uso libre incluyendo comercial" -ForegroundColor DarkGray
    Write-Host ""
}

# ── Entry point ───────────────────────────────────────────────────────────────

if ($Uninstall) {
    Uninstall-PipeSecurity
} else {
    Install-PipeSecurity
}
