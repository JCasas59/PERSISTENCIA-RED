#!/usr/bin/env bash
#
# linux_persistence_audit.sh
# ---------------------------------------------------------------
# Audita las tareas cron del sistema (usuarios, /etc/crontab,
# /etc/cron.d, /etc/cron.{hourly,daily,weekly,monthly}) buscando
# indicios de persistencia de malware / C2 / backdoor.
#
# - Compara contra un baseline ("estado normal" aceptado por ti).
# - Aplica heurísticas de sospecha.
# - Extrae IPs públicas y dominios referenciados.
# - Genera un informe .txt breve y visual.
# - Envía el informe por correo (SMTP vía python3, sin dependencias extra).
#
# USO:
#   Primera vez (crea el baseline, no envía alertas):
#     sudo ./linux_persistence_audit.sh --baseline
#
#   Ejecuciones normales (comparación + heurísticas + email):
#     sudo ./linux_persistence_audit.sh
#
# Debe ejecutarse como root para poder leer el crontab de todos
# los usuarios.
# ---------------------------------------------------------------

set -uo pipefail

# ================== CONFIGURACIÓN ==================
BASE_DIR="/var/lib/persistence-audit"
REPORT_DIR="/var/log/persistence-audit"
BASELINE_FILE="${BASE_DIR}/baseline.txt"
REPORT_FILE="${REPORT_DIR}/report_$(date +%Y%m%d_%H%M%S).txt"
LATEST_REPORT="${REPORT_DIR}/latest_report.txt"

# --- Configuración de correo (rellena con tus datos) ---
SMTP_SERVER="smtp.ejemplo.com"
SMTP_PORT="587"
SMTP_USER="usuario@ejemplo.com"
SMTP_PASS="CAMBIA_ESTA_CONTRASENA"
MAIL_FROM="usuario@ejemplo.com"
MAIL_TO="user@ejemplo.com"
SEND_EMAIL=true   # pon "false" para desactivar el envío de correo
# =====================================================

mkdir -p "$BASE_DIR" "$REPORT_DIR"

MODE="normal"
if [[ "${1:-}" == "--baseline" ]]; then
    MODE="baseline"
fi

TMP_INVENTORY=$(mktemp)
TMP_SUSPICIOUS=$(mktemp)
TMP_NEW=$(mktemp)
trap 'rm -f "$TMP_INVENTORY" "$TMP_SUSPICIOUS" "$TMP_NEW"' EXIT

# ---------------------------------------------------------------
# 1. Recolectar todas las entradas cron del sistema
#    Formato de cada línea de inventario:
#    FUENTE|USUARIO|COMANDO_COMPLETO
# ---------------------------------------------------------------

# crontabs de usuario
if command -v getent >/dev/null 2>&1; then
    USERS=$(getent passwd | cut -d: -f1)
else
    USERS=$(cut -d: -f1 /etc/passwd)
fi

for u in $USERS; do
    crontab -l -u "$u" 2>/dev/null | grep -vE '^\s*(#|$)' | while IFS= read -r line; do
        echo "user_crontab:${u}|${u}|${line}" >> "$TMP_INVENTORY"
    done
done

# /etc/crontab y /etc/cron.d/*
for f in /etc/crontab /etc/cron.d/*; do
    [[ -f "$f" ]] || continue
    grep -vE '^\s*(#|$)' "$f" | while IFS= read -r line; do
        # formato típico: min hour dom mon dow user comando...
        run_user=$(echo "$line" | awk '{print $6}')
        echo "$(basename "$f")|${run_user:-root}|${line}" >> "$TMP_INVENTORY"
    done
done

# cron.hourly / cron.daily / cron.weekly / cron.monthly
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*; do
        [[ -f "$f" ]] || continue
        echo "$(basename "$d")|root|${f}" >> "$TMP_INVENTORY"
    done
done

TOTAL=$(wc -l < "$TMP_INVENTORY" 2>/dev/null || echo 0)

# ---------------------------------------------------------------
# 2. Modo baseline: guardar tal cual y salir
# ---------------------------------------------------------------
if [[ "$MODE" == "baseline" ]]; then
    sort "$TMP_INVENTORY" -o "$BASELINE_FILE"
    echo "[OK] Baseline creado con ${TOTAL} entradas en: $BASELINE_FILE"
    echo "A partir de ahora, ejecuta el script sin --baseline para auditar."
    exit 0
fi

if [[ ! -f "$BASELINE_FILE" ]]; then
    echo "[ERROR] No existe baseline. Ejecuta primero: sudo $0 --baseline"
    exit 1
fi

# ---------------------------------------------------------------
# 3. Detectar entradas NUEVAS respecto al baseline
# ---------------------------------------------------------------
sort "$TMP_INVENTORY" > "${TMP_INVENTORY}.sorted"
comm -23 "${TMP_INVENTORY}.sorted" "$BASELINE_FILE" > "$TMP_NEW"
NEW_COUNT=$(wc -l < "$TMP_NEW" 2>/dev/null || echo 0)

# ---------------------------------------------------------------
# 4. Heurísticas de sospecha sobre TODAS las entradas actuales
# ---------------------------------------------------------------
# Patrones de riesgo típicos de C2/backdoors/reverse shells
SUSPICIOUS_REGEX='(base64 -d|base64 --decode|/dev/tcp/|/dev/udp/|nc -e|ncat .*-e|bash -i|sh -i|curl .*\| *sh|curl .*\| *bash|wget .*\| *sh|wget .*\| *bash|python.*socket\.|perl.*socket\(|mkfifo|reverse.?shell|\.onion|certutil .*-urlcache|powershell.*-enc)'
TEMP_PATH_REGEX='(/tmp/|/dev/shm/|/var/tmp/|/\.\S+/)'

while IFS='|' read -r src user cmd; do
    reasons=""
    echo "$cmd" | grep -qiE "$SUSPICIOUS_REGEX" && reasons="${reasons}patrón tipo C2/reverse-shell; "
    echo "$cmd" | grep -qE "$TEMP_PATH_REGEX" && reasons="${reasons}ejecuta desde ruta temporal/oculta; "

    if [[ -n "$reasons" ]]; then
        echo "${src}|${user}|${cmd}|${reasons}" >> "$TMP_SUSPICIOUS"
    fi
done < "${TMP_INVENTORY}.sorted"

SUSPICIOUS_COUNT=$(wc -l < "$TMP_SUSPICIOUS" 2>/dev/null || echo 0)

# ---------------------------------------------------------------
# 5. Extraer IPs públicas y dominios de TODAS las entradas
# ---------------------------------------------------------------
IP_REGEX='([0-9]{1,3}\.){3}[0-9]{1,3}'
DOMAIN_REGEX='([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}'

IOCS_FILE=$(mktemp)
grep -oE "$IP_REGEX" "${TMP_INVENTORY}.sorted" | sort -u | while read -r ip; do
    # descarta rangos privados/loopback/link-local
    if [[ "$ip" =~ ^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.) ]]; then
        continue
    fi
    echo "IP pública: $ip" >> "$IOCS_FILE"
done
grep -oE "$DOMAIN_REGEX" "${TMP_INVENTORY}.sorted" | sort -u | grep -viE '^(localhost|example\.(com|org))$' >> "$IOCS_FILE" 2>/dev/null || true
IOC_COUNT=$(wc -l < "$IOCS_FILE" 2>/dev/null || echo 0)

# ---------------------------------------------------------------
# 6. Generar informe visual
# ---------------------------------------------------------------
NOW=$(date '+%Y-%m-%d %H:%M:%S')
HOST=$(hostname)

{
echo "=================================================="
echo "  INFORME DE ANÁLISIS DE PERSISTENCIA - LINUX"
echo "  Equipo: ${HOST}"
echo "  Fecha:  ${NOW}"
echo "=================================================="
echo ""

if [[ "$SUSPICIOUS_COUNT" -eq 0 && "$NEW_COUNT" -eq 0 ]]; then
    echo "[OK] El análisis ha sido correcto."
    echo "[OK] No se identificó persistencia sospechosa."
else
    echo "[!] ALERTA: se han detectado hallazgos que requieren revisión."
fi

echo ""
echo "Resumen:"
echo "  - Entradas cron revisadas ........ ${TOTAL}"
echo "  - Nuevas respecto al baseline ..... ${NEW_COUNT}"
echo "  - Marcadas como sospechosas ....... ${SUSPICIOUS_COUNT}"
echo "  - IPs públicas / dominios hallados  ${IOC_COUNT}"
echo ""

if [[ "$NEW_COUNT" -gt 0 ]]; then
    echo "--------------------------------------------------"
    echo "ENTRADAS NUEVAS (no estaban en el baseline)"
    echo "--------------------------------------------------"
    n=1
    while IFS='|' read -r src user cmd; do
        echo "${n}. [Fuente: ${src}] [Usuario: ${user}]"
        echo "   Comando: ${cmd}"
        n=$((n+1))
    done < "$TMP_NEW"
    echo ""
fi

if [[ "$SUSPICIOUS_COUNT" -gt 0 ]]; then
    echo "--------------------------------------------------"
    echo "ENTRADAS SOSPECHOSAS (heurísticas)"
    echo "--------------------------------------------------"
    n=1
    while IFS='|' read -r src user cmd reasons; do
        echo "${n}. [Fuente: ${src}] [Usuario: ${user}]"
        echo "   Comando: ${cmd}"
        echo "   Motivo:  ${reasons}"
        n=$((n+1))
    done < "$TMP_SUSPICIOUS"
    echo ""
fi

if [[ "$IOC_COUNT" -gt 0 ]]; then
    echo "--------------------------------------------------"
    echo "IPs PÚBLICAS / DOMINIOS DETECTADOS EN CRON"
    echo "--------------------------------------------------"
    cat "$IOCS_FILE"
    echo ""
fi

echo "=================================================="
echo "Nota: este análisis se basa en heurísticas y en la"
echo "comparación con un baseline. No sustituye a un EDR."
echo "Revisa manualmente cualquier hallazgo antes de actuar."
echo "=================================================="
} > "$REPORT_FILE"

cp "$REPORT_FILE" "$LATEST_REPORT"
rm -f "$IOCS_FILE"

echo "Informe generado en: $REPORT_FILE"

# ---------------------------------------------------------------
# 7. Enviar por correo
# ---------------------------------------------------------------
if [[ "$SEND_EMAIL" == "true" ]]; then
    if [[ "$SUSPICIOUS_COUNT" -eq 0 && "$NEW_COUNT" -eq 0 ]]; then
        SUBJECT="[OK] Auditoría persistencia ${HOST} - Sin hallazgos (${NOW})"
    else
        SUBJECT="[ALERTA] Auditoría persistencia ${HOST} - Revisar (${NOW})"
    fi

    python3 - "$REPORT_FILE" "$SUBJECT" <<'PYEOF'
import sys, smtplib, ssl
from email.mime.text import MIMEText

report_path, subject = sys.argv[1], sys.argv[2]

SMTP_SERVER = "smtp.ejemplo.com"
SMTP_PORT = 587
SMTP_USER = "usuario@ejemplo.com"
SMTP_PASS = "CAMBIA_ESTA_CONTRASENA"
MAIL_FROM = "usuario@ejemplo.com"
MAIL_TO = "acasa@ejemplo.com"

with open(report_path, "r", encoding="utf-8") as f:
    body = f.read()

msg = MIMEText(body, "plain", "utf-8")
msg["Subject"] = subject
msg["From"] = MAIL_FROM
msg["To"] = MAIL_TO

try:
    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls(context=context)
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(MAIL_FROM, [MAIL_TO], msg.as_string())
    print("[OK] Correo enviado correctamente.")
except Exception as e:
    print(f"[ERROR] No se pudo enviar el correo: {e}")
PYEOF
fi

exit 0
