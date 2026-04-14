"""
Módulo de escaneo de la máquina local (Windows).
No requiere credenciales ni conexión de red.
Todo corre via PowerShell local.
"""

from ..utils.powershell import run_ps, run_ps_raw


def local_machine_overview() -> dict:
    """Información general del sistema."""
    script = """
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$domain_role = switch($cs.DomainRole) {
    0 {"Standalone Workstation"}
    1 {"Member Workstation"}
    2 {"Standalone Server"}
    3 {"Member Server"}
    4 {"Backup Domain Controller"}
    5 {"Primary Domain Controller"}
}
@{
    hostname     = $env:COMPUTERNAME
    os           = $os.Caption
    os_version   = $os.Version
    os_build     = $os.BuildNumber
    architecture = $os.OSArchitecture
    domain       = $cs.Domain
    domain_joined = ($cs.PartOfDomain -eq $true)
    domain_role  = $domain_role
    last_boot    = $os.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss")
    uptime_days  = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
    total_ram_gb = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
    current_user = $env:USERNAME
    logged_users = (Get-CimInstance Win32_LoggedOnUser -ErrorAction SilentlyContinue | Where-Object { $_.Antecedent -match 'Win32_UserAccount' } | Select-Object -Unique).Count
} | ConvertTo-Json -Depth 3
"""
    return run_ps(script)


def local_users_audit() -> dict:
    """Auditoría de usuarios locales."""
    script = """
$users = Get-LocalUser | Select-Object Name, Enabled, PasswordRequired,
    PasswordExpires, PasswordLastSet, LastLogon, Description,
    @{N='IsAdmin';E={
        (Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue |
         Where-Object {$_.Name -like "*$($_.Name)"}) -ne $null
    }}

$admins = (Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue).Name

$result = $users | ForEach-Object {
    @{
        name             = $_.Name
        enabled          = $_.Enabled
        password_required = $_.PasswordRequired
        password_expires = ($_.PasswordExpires -ne $null)
        password_last_set = if($_.PasswordLastSet) {$_.PasswordLastSet.ToString("yyyy-MM-dd")} else {"Never"}
        last_logon       = if($_.LastLogon) {$_.LastLogon.ToString("yyyy-MM-dd")} else {"Never"}
        is_local_admin   = ($admins -contains "$env:COMPUTERNAME\\$($_.Name)")
        description      = $_.Description
    }
}

@{
    total        = ($users | Measure-Object).Count
    enabled      = ($users | Where-Object {$_.Enabled} | Measure-Object).Count
    local_admins = ($admins | Measure-Object).Count
    users        = @($result)
} | ConvertTo-Json -Depth 5
"""
    return run_ps(script)


def local_open_ports() -> dict:
    """Puertos en escucha en la máquina local."""
    script = """
$ports = Get-NetTCPConnection -State Listen | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    @{
        local_address = $_.LocalAddress
        local_port    = $_.LocalPort
        state         = $_.State.ToString()
        pid           = $_.OwningProcess
        process_name  = if($proc) {$proc.Name} else {"Unknown"}
    }
} | Sort-Object {$_.local_port}

@{
    total = ($ports | Measure-Object).Count
    ports = @($ports)
    risky_ports = @($ports | Where-Object {
        $_.local_port -in @(21,23,445,3389,5985,5986,1433,3306,5432,6379,27017) -and
        $_.local_address -in @("0.0.0.0","::")
    })
} | ConvertTo-Json -Depth 5
"""
    return run_ps(script)


def local_smb_config() -> dict:
    """Configuración SMB — detecta SMBv1 y firma."""
    script = """
$smb1 = (Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol)
$smb2 = (Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB2Protocol)
$signing_required = (Get-SmbServerConfiguration | Select-Object -ExpandProperty RequireSecuritySignature)
$encrypt = (Get-SmbServerConfiguration | Select-Object -ExpandProperty EncryptData)

$shares = Get-SmbShare | Where-Object {$_.Name -ne 'IPC$'} | ForEach-Object {
    $perms = Get-SmbShareAccess -Name $_.Name -ErrorAction SilentlyContinue
    $everyone = $perms | Where-Object {$_.AccountName -eq 'Everyone'}
    @{
        name        = $_.Name
        path        = $_.Path
        description = $_.Description
        everyone_access = if($everyone) {$everyone.AccessRight.ToString()} else {"None"}
    }
}

@{
    smb1_enabled        = $smb1
    smb2_enabled        = $smb2
    signing_required    = $signing_required
    encryption_enabled  = $encrypt
    risk_smb1           = $smb1
    shares              = @($shares)
    shares_with_everyone = @($shares | Where-Object {$_.everyone_access -ne "None"})
} | ConvertTo-Json -Depth 5
"""
    return run_ps(script)


def local_rdp_config() -> dict:
    """Configuración de RDP."""
    script = """
$rdp_enabled = (Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections -eq 0
$nla = (Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction SilentlyContinue).UserAuthentication -eq 1
$port = (Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'PortNumber' -ErrorAction SilentlyContinue).PortNumber
$encryption = (Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'MinEncryptionLevel' -ErrorAction SilentlyContinue).MinEncryptionLevel

@{
    rdp_enabled      = $rdp_enabled
    nla_required     = $nla
    port             = if($port) {$port} else {3389}
    default_port     = ($port -eq 3389 -or $port -eq $null)
    risk_no_nla      = ($rdp_enabled -and -not $nla)
    risk_default_port = ($rdp_enabled -and ($port -eq 3389 -or $port -eq $null))
} | ConvertTo-Json -Depth 3
"""
    return run_ps(script)


def local_wdigest_check() -> dict:
    """Verifica si WDigest está habilitado (credenciales en texto claro en memoria)."""
    script = """
$wdigest = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name 'UseLogonCredential' -ErrorAction SilentlyContinue).UseLogonCredential
$lsa_protection = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -ErrorAction SilentlyContinue).RunAsPPL
$credential_guard = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity' -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity

@{
    wdigest_enabled       = ($wdigest -eq 1)
    lsa_protection        = ($lsa_protection -eq 1)
    credential_guard      = ($credential_guard -eq 1)
    risk_wdigest          = ($wdigest -eq 1)
    cleartext_in_memory   = ($wdigest -eq 1 -and $lsa_protection -ne 1)
} | ConvertTo-Json -Depth 3
"""
    return run_ps(script)


def local_windows_defender() -> dict:
    """Estado de Windows Defender."""
    script = """
$def = Get-MpComputerStatus -ErrorAction SilentlyContinue
if (-not $def) {
    @{error = "Windows Defender no disponible o no es administrador"} | ConvertTo-Json
    return
}
@{
    antivirus_enabled        = $def.AntivirusEnabled
    realtime_enabled         = $def.RealTimeProtectionEnabled
    antispyware_enabled      = $def.AntispywareEnabled
    tamper_protection        = $def.IsTamperProtected
    last_scan                = $def.QuickScanEndTime.ToString("yyyy-MM-dd HH:mm:ss")
    signature_version        = $def.AntivirusSignatureVersion
    signature_age_days       = $def.AntivirusSignatureAge
    signature_outdated       = ($def.AntivirusSignatureAge -gt 7)
    threats_active           = $def.NISSignatureAge
    risk_realtime_disabled   = (-not $def.RealTimeProtectionEnabled)
    risk_signature_outdated  = ($def.AntivirusSignatureAge -gt 7)
} | ConvertTo-Json -Depth 3
"""
    return run_ps(script)


def local_pending_updates() -> dict:
    """Parches de seguridad pendientes."""
    script = """
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
try {
    $result = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
    $updates = $result.Updates | ForEach-Object {
        @{
            title      = $_.Title
            severity   = if($_.MsrcSeverity) {$_.MsrcSeverity} else {"N/A"}
            kb         = ($_.KBArticleIDs | Select-Object -First 1)
            categories = @($_.Categories | ForEach-Object {$_.Name})
        }
    }
    $critical = @($updates | Where-Object {$_.severity -in @("Critical","Important")})
    @{
        total_pending   = $result.Updates.Count
        critical        = $critical.Count
        updates         = @($updates | Select-Object -First 20)
    } | ConvertTo-Json -Depth 5
} catch {
    @{error = $_.Exception.Message} | ConvertTo-Json
}
"""
    return run_ps(script, timeout=60)


def local_firewall_status() -> dict:
    """Estado del Firewall de Windows."""
    script = """
$profiles = Get-NetFirewallProfile | ForEach-Object {
    @{
        name    = $_.Name
        enabled = $_.Enabled
        default_inbound  = $_.DefaultInboundAction.ToString()
        default_outbound = $_.DefaultOutboundAction.ToString()
        log_allowed = $_.LogAllowed
        log_blocked = $_.LogBlocked
    }
}
$disabled_profiles = @($profiles | Where-Object {-not $_.enabled})
@{
    profiles         = @($profiles)
    all_enabled      = ($disabled_profiles.Count -eq 0)
    disabled_count   = $disabled_profiles.Count
    risk_fw_disabled = ($disabled_profiles.Count -gt 0)
} | ConvertTo-Json -Depth 5
"""
    return run_ps(script)


def local_password_policy() -> dict:
    """Política de contraseñas local."""
    script = """
$policy = net accounts 2>$null
$result = @{}
$policy | ForEach-Object {
    if ($_ -match "Maximum password age.*?:\\s*(\\d+|Unlimited)") {
        $result.max_age = $Matches[1]
    }
    if ($_ -match "Minimum password age.*?:\\s*(\\d+)") {
        $result.min_age = $Matches[1]
    }
    if ($_ -match "Minimum password length.*?:\\s*(\\d+)") {
        $result.min_length = $Matches[1]
    }
    if ($_ -match "Password history length.*?:\\s*(\\d+|None)") {
        $result.history = $Matches[1]
    }
    if ($_ -match "Lockout threshold.*?:\\s*(\\d+|Never)") {
        $result.lockout_threshold = $Matches[1]
    }
    if ($_ -match "Lockout duration.*?:\\s*(\\d+)") {
        $result.lockout_duration = $Matches[1]
    }
}
$result.risk_no_expiry    = ($result.max_age -eq "Unlimited")
$result.risk_short_pass   = ([int]($result.min_length ?? 0) -lt 8)
$result.risk_no_lockout   = ($result.lockout_threshold -eq "Never" -or $result.lockout_threshold -eq "0")
$result | ConvertTo-Json -Depth 3
"""
    return run_ps(script)


def local_scheduled_tasks_suspicious() -> dict:
    """Tareas programadas sospechosas — fuera de rutas conocidas."""
    script = """
$tasks = Get-ScheduledTask | Where-Object {
    $_.TaskPath -notlike "\\Microsoft\\*" -and
    $_.State -ne "Disabled"
} | ForEach-Object {
    $action = $_.Actions | Select-Object -First 1
    @{
        name      = $_.TaskName
        path      = $_.TaskPath
        state     = $_.State.ToString()
        run_as    = $_.Principal.UserId
        execute   = if($action) {$action.Execute} else {"N/A"}
        arguments = if($action) {$action.Arguments} else {""}
    }
}
@{
    total      = ($tasks | Measure-Object).Count
    tasks      = @($tasks)
    suspicious = @($tasks | Where-Object {
        $_.execute -match "powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32" -or
        $_.execute -match "\\\\Users\\\\|\\\\Temp\\\\|\\\\AppData\\\\"
    })
} | ConvertTo-Json -Depth 5
"""
    return run_ps(script)


def local_laps_status() -> dict:
    """Verifica si LAPS está instalado y configurado."""
    script = """
$laps_cse = Test-Path "C:\\Program Files\\LAPS\\CSE\\AdmPwd.dll" -ErrorAction SilentlyContinue
$laps_new = (Get-WindowsCapability -Online -Name "Rsat.LAPS*" -ErrorAction SilentlyContinue).State -eq "Installed"
$laps_gpo = (Get-ItemProperty "HKLM:\\Software\\Policies\\Microsoft Services\\AdmPwd" -ErrorAction SilentlyContinue)
$laps_new_reg = (Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS" -ErrorAction SilentlyContinue)

@{
    legacy_laps_installed = $laps_cse
    windows_laps_available = $laps_new
    laps_policy_configured = ($laps_gpo -ne $null -or $laps_new_reg -ne $null)
    risk_no_laps = (-not $laps_cse -and -not $laps_new)
} | ConvertTo-Json -Depth 3
"""
    return run_ps(script)
