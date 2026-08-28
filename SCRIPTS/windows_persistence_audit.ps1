<#
.SYNOPSIS
    windows_persistence_audit.ps1

    Audita el Programador de Tareas de Windows buscando indicios de
    persistencia de malware / C2 / backdoor.

    - Compara contra un baseline ("estado normal" aceptado por ti).
    - Aplica heurísticas de sospecha (LOLBins, rutas temporales,
      comandos codificados, descargas remotas, etc.)
    - Extrae IPs públicas y dominios referenciados en las tareas.
    - Genera un informe .txt breve y visual.
    - Envía el informe por correo.

.USO
    Primera vez (crea el baseline, no envía alertas):
        powershell -ExecutionPolicy Bypass -File .\windows_persistence_audit.ps1 -Baseline

    Ejecuciones normales (comparación + heurísticas + email):
        powershell -ExecutionPolicy Bypass -File .\windows_persistence_audit.ps1

    Debe ejecutarse como Administrador.
#>

param(
    [switch]$Baseline
)

# ================== CONFIGURACIÓN ==================
$BaseDir      = "C:\ProgramData\PersistenceAudit"
$BaselineFile = Join-Path $BaseDir "baseline.json"
$ReportDir    = Join-Path $BaseDir "reports"
$Timestamp    = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile   = Join-Path $ReportDir "report_$Timestamp.txt"
$LatestReport = Join-Path $ReportDir "latest_report.txt"

# --- Configuración de correo (rellena con tus datos) ---
$SmtpServer = "smtp.ejemplo.com"
$SmtpPort   = 587
$SmtpUser   = "usuario@ejemplo.com"
$SmtpPass   = "CAMBIA_ESTA_CONTRASENA"
$MailFrom   = "usuario@ejemplo.com"
$MailTo     = "acasa@ejemplo.com"
$SendEmail  = $true   # $false para desactivar el envío de correo
# =====================================================

New-Item -ItemType Directory -Force -Path $BaseDir, $ReportDir | Out-Null

# ---------------------------------------------------------------
# 1. Inventariar tareas programadas
# ---------------------------------------------------------------
$tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\Windows\*" -or $true }
# (Nota: no excluimos las tareas de Microsoft por defecto porque algunos
#  backdoors se disfrazan ahí; si genera demasiado ruido, añade un filtro.)

$inventory = @()
foreach ($t in $tasks) {
    foreach ($action in $t.Actions) {
        $execute = $action.Execute
        $args    = $action.Arguments
        if (-not $execute) { continue }
        $inventory += [PSCustomObject]@{
            TaskName  = $t.TaskName
            TaskPath  = $t.TaskPath
            Execute   = $execute
            Arguments = $args
            Author    = $t.Author
            State     = $t.State.ToString()
            Key       = "$($t.TaskPath)$($t.TaskName)|$execute|$args"
        }
    }
}

$Total = $inventory.Count

# ---------------------------------------------------------------
# 2. Modo baseline: guardar y salir
# ---------------------------------------------------------------
if ($Baseline) {
    $inventory | ConvertTo-Json -Depth 4 | Out-File -FilePath $BaselineFile -Encoding UTF8
    Write-Host "[OK] Baseline creado con $Total entradas en: $BaselineFile"
    Write-Host "A partir de ahora, ejecuta el script sin -Baseline para auditar."
    exit 0
}

if (-not (Test-Path $BaselineFile)) {
    Write-Host "[ERROR] No existe baseline. Ejecuta primero con -Baseline"
    exit 1
}

$baselineData = Get-Content $BaselineFile -Raw | ConvertFrom-Json
$baselineKeys = $baselineData | ForEach-Object { $_.Key }

# ---------------------------------------------------------------
# 3. Detectar entradas NUEVAS respecto al baseline
# ---------------------------------------------------------------
$newEntries = $inventory | Where-Object { $baselineKeys -notcontains $_.Key }
$NewCount = $newEntries.Count

# ---------------------------------------------------------------
# 4. Heurísticas de sospecha
# ---------------------------------------------------------------
$suspiciousPatterns = @(
    '-enc(odedcommand)?\s',
    'iex\s*\(',
    'invoke-expression',
    'downloadstring',
    'downloadfile',
    'net\.webclient',
    'mshta\s',
    'regsvr32.*\/i:http',
    'certutil.*-urlcache',
    'bitsadmin.*\/transfer',
    'wscript|cscript',
    'hidden.*-windowstyle',
    '\\appdata\\local\\temp\\',
    '\\programdata\\[a-z0-9]{6,}\\',
    '\\users\\public\\'
)
$patternRegex = ($suspiciousPatterns -join '|')

$suspicious = @()
foreach ($item in $inventory) {
    $combined = "$($item.Execute) $($item.Arguments)"
    if ($combined -imatch $patternRegex) {
        $suspicious += [PSCustomObject]@{
            TaskName = $item.TaskName
            TaskPath = $item.TaskPath
            Execute  = $item.Execute
            Arguments= $item.Arguments
            Reason   = "coincide con patrón sospechoso (LOLBin / descarga remota / ruta temporal / comando ofuscado)"
        }
    }
}
$SuspiciousCount = $suspicious.Count

# ---------------------------------------------------------------
# 5. Extraer IPs públicas y dominios
# ---------------------------------------------------------------
$ipRegex = '(\d{1,3}\.){3}\d{1,3}'
$domainRegex = '([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}'

$iocs = New-Object System.Collections.Generic.List[string]
$allText = ($inventory | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join "`n"

[regex]::Matches($allText, $ipRegex) | ForEach-Object {
    $ip = $_.Value
    if ($ip -notmatch '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)') {
        if (-not $iocs.Contains("IP pública: $ip")) { $iocs.Add("IP pública: $ip") }
    }
}
[regex]::Matches($allText, $domainRegex) | ForEach-Object {
    $d = $_.Value
    if ($d -notin @("localhost")) {
        $line = "Dominio: $d"
        if (-not $iocs.Contains($line)) { $iocs.Add($line) }
    }
}
$IocCount = $iocs.Count

# ---------------------------------------------------------------
# 6. Generar informe visual
# ---------------------------------------------------------------
$Now  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$Host_ = $env:COMPUTERNAME

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("==================================================")
[void]$sb.AppendLine("  INFORME DE ANALISIS DE PERSISTENCIA - WINDOWS")
[void]$sb.AppendLine("  Equipo: $Host_")
[void]$sb.AppendLine("  Fecha:  $Now")
[void]$sb.AppendLine("==================================================")
[void]$sb.AppendLine("")

if ($SuspiciousCount -eq 0 -and $NewCount -eq 0) {
    [void]$sb.AppendLine("[OK] El análisis ha sido correcto.")
    [void]$sb.AppendLine("[OK] No se identificó persistencia sospechosa.")
} else {
    [void]$sb.AppendLine("[!] ALERTA: se han detectado hallazgos que requieren revisión.")
}

[void]$sb.AppendLine("")
[void]$sb.AppendLine("Resumen:")
[void]$sb.AppendLine("  - Tareas revisadas ................ $Total")
[void]$sb.AppendLine("  - Nuevas respecto al baseline ...... $NewCount")
[void]$sb.AppendLine("  - Marcadas como sospechosas ........ $SuspiciousCount")
[void]$sb.AppendLine("  - IPs públicas / dominios hallados . $IocCount")
[void]$sb.AppendLine("")

if ($NewCount -gt 0) {
    [void]$sb.AppendLine("--------------------------------------------------")
    [void]$sb.AppendLine("TAREAS NUEVAS (no estaban en el baseline)")
    [void]$sb.AppendLine("--------------------------------------------------")
    $i = 1
    foreach ($e in $newEntries) {
        [void]$sb.AppendLine("$i. [$($e.TaskPath)$($e.TaskName)]")
        [void]$sb.AppendLine("   Ejecutable: $($e.Execute)")
        [void]$sb.AppendLine("   Argumentos: $($e.Arguments)")
        $i++
    }
    [void]$sb.AppendLine("")
}

if ($SuspiciousCount -gt 0) {
    [void]$sb.AppendLine("--------------------------------------------------")
    [void]$sb.AppendLine("TAREAS SOSPECHOSAS (heurísticas)")
    [void]$sb.AppendLine("--------------------------------------------------")
    $i = 1
    foreach ($s in $suspicious) {
        [void]$sb.AppendLine("$i. [$($s.TaskPath)$($s.TaskName)]")
        [void]$sb.AppendLine("   Ejecutable: $($s.Execute)")
        [void]$sb.AppendLine("   Argumentos: $($s.Arguments)")
        [void]$sb.AppendLine("   Motivo:     $($s.Reason)")
        $i++
    }
    [void]$sb.AppendLine("")
}

if ($IocCount -gt 0) {
    [void]$sb.AppendLine("--------------------------------------------------")
    [void]$sb.AppendLine("IPs PUBLICAS / DOMINIOS DETECTADOS")
    [void]$sb.AppendLine("--------------------------------------------------")
    foreach ($line in $iocs) { [void]$sb.AppendLine($line) }
    [void]$sb.AppendLine("")
}

[void]$sb.AppendLine("==================================================")
[void]$sb.AppendLine("Nota: este análisis se basa en heurísticas y en la")
[void]$sb.AppendLine("comparación con un baseline. No sustituye a un EDR.")
[void]$sb.AppendLine("Revisa manualmente cualquier hallazgo antes de actuar.")
[void]$sb.AppendLine("==================================================")

$sb.ToString() | Out-File -FilePath $ReportFile -Encoding UTF8
Copy-Item $ReportFile $LatestReport -Force

Write-Host "Informe generado en: $ReportFile"

# ---------------------------------------------------------------
# 7. Enviar por correo
# ---------------------------------------------------------------
if ($SendEmail) {
    if ($SuspiciousCount -eq 0 -and $NewCount -eq 0) {
        $Subject = "[OK] Auditoria persistencia $Host_ - Sin hallazgos ($Now)"
    } else {
        $Subject = "[ALERTA] Auditoria persistencia $Host_ - Revisar ($Now)"
    }

    try {
        $securePass = ConvertTo-SecureString $SmtpPass -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential ($SmtpUser, $securePass)

        Send-MailMessage -From $MailFrom -To $MailTo -Subject $Subject `
            -Body $sb.ToString() -SmtpServer $SmtpServer -Port $SmtpPort `
            -UseSsl -Credential $cred -Encoding UTF8

        Write-Host "[OK] Correo enviado correctamente."
    } catch {
        Write-Host "[ERROR] No se pudo enviar el correo: $_"
    }
}
