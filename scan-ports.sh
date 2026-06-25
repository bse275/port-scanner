#!/usr/bin/env bash
# Port compliance scanner — checks servers for unexpected open ports.
# Usage: ./scan-ports.sh [--test-config] [--test|-t] [host1 host2 ...]  (ohne Argumente: liest servers.conf)

set -euo pipefail

# ---------------------------------------------------------------------------
# Flags auslesen (vor allem anderen)
# ---------------------------------------------------------------------------
TEST_CONFIG=0
TEST_MODE=0
MAIL_TEST=0
HC_TEST=0
HC_FAIL=0
ARGS=()
for arg in "$@"; do
  case "$arg" in
    --test-config) TEST_CONFIG=1 ;;
    --test|-t)     TEST_MODE=1 ;;
    --mail-test)   MAIL_TEST=1 ;;
    --hc-test)     HC_TEST=1 ;;
    --hc-fail)     HC_TEST=1; HC_FAIL=1 ;;
    *)             ARGS+=("$arg") ;;
  esac
done
set -- "${ARGS[@]+"${ARGS[@]}"}"

# ---------------------------------------------------------------------------
# Fallback-Ports für Hosts ohne eigenen Eintrag in servers.conf
# (greift nur bei direkter Übergabe per Kommandozeile)
# ---------------------------------------------------------------------------
ALLOWED_PORTS=(
  80    # HTTP
  443   # HTTPS
)

# ---------------------------------------------------------------------------
# healthchecks.io — Zugangsdaten aus hc.conf laden (optional)
# ---------------------------------------------------------------------------
HC_ENABLED="true"
HC_UUID=""
HC_BASE="https://hc-ping.com"

# ---------------------------------------------------------------------------
# Log — Maximale Anzahl Zeilen (schützt SD-Karte vor unbegrenztem Wachstum)
# ---------------------------------------------------------------------------
MAX_LOG_LINES=500

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/servers.conf"
LOG_FILE="${SCRIPT_DIR}/scan-ports.log"

# ---------------------------------------------------------------------------
# --mail-test: Testmail senden und beenden
# ---------------------------------------------------------------------------
if [[ $MAIL_TEST -eq 1 ]]; then
  MAIL_CONF="${SCRIPT_DIR}/mail.conf"
  if [[ ! -f "$MAIL_CONF" ]]; then
    echo -e "${RED}Fehler: mail.conf nicht gefunden (${MAIL_CONF})${RESET}" >&2
    echo -e "Vorlage: mail.conf.example" >&2
    exit 1
  fi
  # shellcheck source=/dev/null
  source "$MAIL_CONF"
  echo -e "${BOLD}${CYAN}  Sende Testmail an ${MAIL_TO} ...${RESET}"
  MAIL_TMP=$(mktemp)
  trap 'rm -f "$MAIL_TMP"' EXIT
  {
    printf "From: Port Scanner <%s>\r\n" "$MAIL_FROM"
    printf "To: %s\r\n" "$MAIL_TO"
    printf "Subject: [Port Scanner] Testmail\r\n"
    printf "Content-Type: text/plain; charset=utf-8\r\n"
    printf "MIME-Version: 1.0\r\n"
    printf "\r\n"
    printf "Das ist eine Testmail vom Port Scanner.\r\n"
    printf "Server: %s\r\n" "$(hostname)"
    printf "Datum:  %s\r\n" "$(date '+%Y-%m-%d %H:%M:%S')"
  } > "$MAIL_TMP"
  if curl -fsS --retry 2 --max-time 30 \
      --url "smtps://${MAIL_HOST}:${MAIL_PORT}" \
      --user "${MAIL_USER}:${MAIL_PASS}" \
      --mail-from "$MAIL_FROM" \
      --mail-rcpt "$MAIL_TO" \
      --upload-file "$MAIL_TMP"; then
    echo -e "${GREEN}${BOLD}  ✓ Testmail erfolgreich gesendet.${RESET}"
  else
    echo -e "${RED}${BOLD}  ✗ Fehler beim Senden — SMTP-Zugangsdaten prüfen.${RESET}" >&2
    exit 1
  fi
  exit 0
fi

# ---------------------------------------------------------------------------
# --hc-test / --hc-fail: Testping an healthchecks.io senden und beenden
# ---------------------------------------------------------------------------
if [[ $HC_TEST -eq 1 ]]; then
  HC_CONF="${SCRIPT_DIR}/hc.conf"
  if [[ ! -f "$HC_CONF" ]]; then
    echo -e "${RED}Fehler: hc.conf nicht gefunden (${HC_CONF})${RESET}" >&2
    echo -e "Vorlage: hc.conf.example" >&2
    exit 1
  fi
  # shellcheck source=/dev/null
  source "$HC_CONF"
  if [[ -z "$HC_UUID" ]]; then
    echo -e "${RED}Fehler: HC_UUID ist leer in hc.conf${RESET}" >&2
    exit 1
  fi
  if [[ $HC_FAIL -eq 1 ]]; then
    HC_ENDPOINT="${HC_BASE}/${HC_UUID}/fail"
    echo -e "${BOLD}${YELLOW}  Simuliere FAIL-Ping an healthchecks.io ...${RESET}"
  else
    HC_ENDPOINT="${HC_BASE}/${HC_UUID}"
    echo -e "${BOLD}${CYAN}  Sende Testping an healthchecks.io ...${RESET}"
  fi
  HC_BODY="Testping vom Port Scanner.
Server: $(hostname)
Datum:  $(date '+%Y-%m-%d %H:%M:%S')"
  if curl -fsS --retry 3 --max-time 10 \
      --data-binary "$HC_BODY" \
      "$HC_ENDPOINT" > /dev/null 2>&1; then
    echo -e "${GREEN}${BOLD}  ✓ healthchecks.io hat geantwortet — UUID ist gültig.${RESET}"
  else
    echo -e "${RED}${BOLD}  ✗ Fehler — UUID oder Verbindung prüfen.${RESET}" >&2
    exit 1
  fi
  exit 0
fi

if ! command -v nmap &>/dev/null; then
  echo "Fehler: nmap ist nicht installiert. Bitte mit 'sudo apt install nmap' nachinstallieren." >&2
  exit 1
fi

# hc.conf laden falls vorhanden
HC_CONF="${SCRIPT_DIR}/hc.conf"
if [[ -f "$HC_CONF" ]]; then
  # shellcheck source=/dev/null
  source "$HC_CONF"
fi

# Alle Ausgaben in Tempfile mitschreiben (für healthchecks.io Body bei Fehler)
TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT
exec > >(tee "$TMPFILE") 2>&1

# ---------------------------------------------------------------------------
# Hosts, CIDR-Ranges und per-Host-Ports einlesen
# ---------------------------------------------------------------------------
KNOWN_HOSTS=()
CIDR_RANGES=()
declare -A HOST_PORTS   # HOST_PORTS["ip"] = "80,443" | "-" | "" (leer = global fallback)
declare -A HOST_TEST    # HOST_TEST["ip"] = 1  wenn als "test" markiert
declare -A HOST_SKIP    # HOST_SKIP["ip"] = 1  wenn als "skip" markiert (bekannt, kein Scan)

if [[ $# -eq 0 ]]; then
  if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Fehler: Keine Argumente und keine servers.conf gefunden (erwartet: ${CONFIG_FILE})" >&2
    echo "Verwendung: $0 <host_oder_ip> [host2 ...]" >&2
    exit 1
  fi
  while IFS= read -r line; do
    host=$(echo "$line" | awk '{print $1}')
    ports=$(echo "$line" | awk '{print $2}')
    flag=$(echo "$line" | awk '{print $3}')
    if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
      CIDR_RANGES+=("$host")
    else
      KNOWN_HOSTS+=("$host")
      HOST_PORTS["$host"]="${ports:-"-"}"
      [[ "$flag" == "test" ]] && HOST_TEST["$host"]=1
      [[ "$flag" == "skip" ]] && HOST_SKIP["$host"]=1
    fi
  done < <(grep -v '^\s*#' "$CONFIG_FILE" | grep -v '^\s*$')

  if [[ ${#KNOWN_HOSTS[@]} -eq 0 && ${#CIDR_RANGES[@]} -eq 0 ]]; then
    echo "Fehler: servers.conf ist leer oder enthält nur Kommentare." >&2
    exit 1
  fi
else
  KNOWN_HOSTS=("$@")
fi

# ---------------------------------------------------------------------------
# --test-config: Config-Dateien prüfen und beenden
# ---------------------------------------------------------------------------
if [[ $TEST_CONFIG -eq 1 ]]; then
  CONFIG_OK=0

  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
  echo -e "${BOLD}  Config-Prüfung${RESET}"
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
  echo ""

  # --- servers.conf ---
  echo -e "${BOLD}servers.conf${RESET}"
  if [[ ! -f "$CONFIG_FILE" ]]; then
    echo -e "  ${RED}✗ Datei nicht gefunden: ${CONFIG_FILE}${RESET}"
    CONFIG_OK=1
  else
    echo -e "  ${GREEN}✓ Datei gefunden${RESET}"

    # Jede Zeile validieren
    LINE_NUM=0
    while IFS= read -r line; do
      (( LINE_NUM++ )) || true
      host=$(echo "$line" | awk '{print $1}')
      ports=$(echo "$line" | awk '{print $2}')
      flag=$(echo "$line" | awk '{if (NF >= 3 && $3 !~ /^#/) print $3; else print ""}')

      # CIDR-Format prüfen
      if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        echo -e "  ${GREEN}✓ CIDR: ${host}${RESET}"
        continue
      fi

      # IP-Format prüfen
      if ! [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "  ${RED}✗ Zeile ${LINE_NUM}: Ungültiges IP-Format: '${host}'${RESET}"
        CONFIG_OK=1
        continue
      fi

      # Ports prüfen
      if [[ "$ports" == "-" || -z "$ports" ]]; then
        PORT_OK=1
      else
        PORT_OK=1
        IFS=',' read -ra _ports <<< "$ports"
        for p in "${_ports[@]}"; do
          if ! [[ "$p" =~ ^[0-9]+$ ]] || (( p < 1 || p > 65535 )); then
            echo -e "  ${RED}✗ Zeile ${LINE_NUM}: Ungültiger Port '${p}' bei Host ${host}${RESET}"
            CONFIG_OK=1
            PORT_OK=0
          fi
        done
      fi

      # Flag prüfen
      if [[ -n "$flag" && "$flag" != "test" && "$flag" != "skip" ]]; then
        echo -e "  ${RED}✗ Zeile ${LINE_NUM}: Unbekannter Flag '${flag}' bei Host ${host} (erlaubt: 'test', 'skip')${RESET}"
        CONFIG_OK=1
      fi

      TEST_MARKER=""
      [[ "$flag" == "test" ]] && TEST_MARKER=" ${YELLOW}[test]${RESET}"
      [[ "$flag" == "skip" ]] && TEST_MARKER=" ${YELLOW}[skip]${RESET}"
      [[ $PORT_OK -eq 1 ]] && echo -e "  ${GREEN}✓ ${host}  ${ports:-"-"}${TEST_MARKER}${RESET}"

    done < <(grep -v '^\s*#' "$CONFIG_FILE" | grep -v '^\s*$')

    echo -e "  → ${#KNOWN_HOSTS[@]} Hosts, ${#CIDR_RANGES[@]} CIDR-Range(s), ${#HOST_TEST[@]} Test-Host(s)"
  fi
  echo ""

  # --- mail.conf ---
  echo -e "${BOLD}mail.conf${RESET}"
  MAIL_CONF="${SCRIPT_DIR}/mail.conf"
  if [[ ! -f "$MAIL_CONF" ]]; then
    echo -e "  ${YELLOW}⚠ Nicht gefunden — keine Mail-Benachrichtigung${RESET}"
  else
    echo -e "  ${GREEN}✓ Datei gefunden${RESET}"
    # shellcheck source=/dev/null
    source "$MAIL_CONF"
    for var in MAIL_HOST MAIL_PORT MAIL_USER MAIL_PASS MAIL_FROM MAIL_TO; do
      if [[ -z "${!var:-}" ]]; then
        echo -e "  ${RED}✗ ${var} ist leer${RESET}"
        CONFIG_OK=1
      else
        # Passwort nicht anzeigen
        if [[ "$var" == "MAIL_PASS" ]]; then
          echo -e "  ${GREEN}✓ ${var} = ***${RESET}"
        else
          echo -e "  ${GREEN}✓ ${var} = ${!var}${RESET}"
        fi
      fi
    done
  fi
  echo ""

  # --- hc.conf ---
  echo -e "${BOLD}hc.conf${RESET}"
  if [[ ! -f "$HC_CONF" ]]; then
    echo -e "  ${YELLOW}⚠ Nicht gefunden — kein healthchecks.io Ping${RESET}"
  else
    echo -e "  ${GREEN}✓ Datei gefunden${RESET}"
    # shellcheck source=/dev/null
    source "$HC_CONF"
    if [[ "$HC_ENABLED" != "true" ]]; then
      echo -e "  ${YELLOW}⚠ HC_ENABLED = ${HC_ENABLED} — healthchecks.io deaktiviert, keine weiteren Prüfungen${RESET}"
    else
      echo -e "  ${GREEN}✓ HC_ENABLED = true${RESET}"
      if [[ -z "$HC_UUID" ]]; then
        echo -e "  ${RED}✗ HC_UUID ist leer${RESET}"
        CONFIG_OK=1
      elif ! [[ "$HC_UUID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
        echo -e "  ${RED}✗ HC_UUID hat kein gültiges UUID-Format: ${HC_UUID}${RESET}"
        CONFIG_OK=1
      else
        echo -e "  ${GREEN}✓ HC_UUID = ${HC_UUID}${RESET}"
      fi
      echo -e "  ${GREEN}✓ HC_BASE = ${HC_BASE}${RESET}"
    fi
  fi
  echo ""

  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
  if [[ $CONFIG_OK -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}  ✓ Alle Configs sind gültig.${RESET}"
  else
    echo -e "${RED}${BOLD}  ✗ Config-Fehler gefunden — bitte korrigieren.${RESET}"
  fi
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
  echo ""
  exit $CONFIG_OK
fi

# ---------------------------------------------------------------------------
# CIDR-Ranges: Discovery-Scan — unbekannte Hosts finden
# ---------------------------------------------------------------------------
UNKNOWN_HOSTS=()

for CIDR in "${CIDR_RANGES[@]}"; do
  echo ""
  echo -e "${BOLD}${YELLOW}  Discovery-Scan: ${CIDR}${RESET}"
  if [[ $TEST_MODE -eq 1 ]]; then
    echo -e "  ${YELLOW}[TEST] Discovery-Scan übersprungen.${RESET}"
    continue
  fi
  while IFS= read -r ip; do
    is_known=0
    for known in "${KNOWN_HOSTS[@]}"; do
      [[ "$ip" == "$known" ]] && is_known=1 && break
    done
    if [[ $is_known -eq 0 ]]; then
      UNKNOWN_HOSTS+=("$ip")
    else
      echo -e "  ${GREEN}✓ Bekannt: ${ip}${RESET}"
    fi
  done < <(nmap -Pn --open -p 80,443,22,25,465,587,993,9876 -T4 "$CIDR" -oG - 2>/dev/null \
    | grep "^Host:" | awk '{print $2}')
done

# ---------------------------------------------------------------------------
# Scan-Ziele zusammenstellen: bekannte + unbekannte Hosts
# Im Test-Modus: nur als "test" markierte Hosts
# ---------------------------------------------------------------------------
TARGETS=()
if [[ $TEST_MODE -eq 1 ]]; then
  for h in "${KNOWN_HOSTS[@]}"; do
    [[ -v HOST_TEST[$h] ]] && TARGETS+=("$h")
  done
  if [[ ${#TARGETS[@]} -eq 0 ]]; then
    echo -e "${RED}Fehler: Keine Test-Hosts in servers.conf gefunden (dritte Spalte: 'test').${RESET}" >&2
    exit 1
  fi
  echo -e "${BOLD}${YELLOW}  TEST-MODUS — nur markierte Hosts:${RESET}"
  for h in "${TARGETS[@]}"; do
    echo -e "  ${CYAN}→ ${h}${RESET}"
  done
  echo ""
else
  for h in "${KNOWN_HOSTS[@]}"; do
    [[ -v HOST_SKIP[$h] ]] || TARGETS+=("$h")
  done
  for h in "${UNKNOWN_HOSTS[@]}"; do
    TARGETS+=("$h")
  done
fi

declare -A UNKNOWN_SET
for h in "${UNKNOWN_HOSTS[@]}"; do
  UNKNOWN_SET["$h"]=1
done

echo ""
echo -e "  Bekannte Hosts:    ${#KNOWN_HOSTS[@]}"
echo -e "  CIDR-Ranges:       ${#CIDR_RANGES[@]}"

if [[ -n "$HC_UUID" && $TEST_MODE -eq 0 && "$HC_ENABLED" == "true" ]]; then
  curl -fsS --retry 3 --max-time 10 "${HC_BASE}/${HC_UUID}/start" > /dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
ALLOWED_SET=$(IFS=, ; echo "${ALLOWED_PORTS[*]}")

is_allowed() {
  local host="$1"
  local port="$2"

  if [[ -v HOST_PORTS[$host] ]]; then
    local host_ports="${HOST_PORTS[$host]}"
    [[ "$host_ports" == "-" ]] && return 1
    IFS=',' read -ra _list <<< "$host_ports"
    for p in "${_list[@]}"; do
      [[ "$p" == "$port" ]] && return 0
    done
    return 1
  else
    # Host nicht in servers.conf (Kommandozeile) — globale Liste
    for p in "${ALLOWED_PORTS[@]}"; do
      [[ "$p" == "$port" ]] && return 0
    done
    return 1
  fi
}

check_dns_recursive() {
  local host="$1"
  local result
  if command -v dig &>/dev/null; then
    result=$(dig @"$host" google.com A +short +time=3 +tries=1 2>/dev/null || true)
  elif command -v nslookup &>/dev/null; then
    result=$(nslookup -timeout=3 google.com "$host" 2>/dev/null \
      | awk '/^Address: / && !/^Address: '"$host"'/ {print}' || true)
  else
    echo -e "  ${YELLOW}⚠ DNS-Port 53 offen — Rekursionsprüfung übersprungen (dig/nslookup fehlt)${RESET}"
    return
  fi
  if [[ -n "$result" ]]; then
    echo -e "  ${RED}${BOLD}  ⚠ OFFENER REKURSIVER DNS: ${host} löst externe Domains auf!${RESET}"
    echo -e "  ${RED}    Risiko: DNS-Amplification / offener Resolver${RESET}"
    FINDINGS+=("OFFENER REKURSIVER DNS  ${host}  (löst externe Domains auf — DNS-Amplification-Risiko)")
    HOST_STATUS=1
    OVERALL_STATUS=1
  else
    echo -e "  ${YELLOW}⚠ DNS-Port 53 offen — keine externe Rekursion festgestellt.${RESET}"
  fi
}

send_mail() {
  local subject="$1"
  local body="$2"
  local mail_conf="${SCRIPT_DIR}/mail.conf"

  [[ ! -f "$mail_conf" ]] && return 0
  # shellcheck source=/dev/null
  source "$mail_conf"

  local mail_tmp
  mail_tmp=$(mktemp)
  trap 'rm -f "$mail_tmp"' RETURN

  {
    printf "From: Port Scanner <%s>\r\n" "$MAIL_FROM"
    printf "To: %s\r\n" "$MAIL_TO"
    printf "Subject: %s\r\n" "$subject"
    printf "Content-Type: text/plain; charset=utf-8\r\n"
    printf "MIME-Version: 1.0\r\n"
    printf "\r\n"
    echo "$body"
  } > "$mail_tmp"

  curl -fsS --retry 2 --max-time 30 --connect-timeout 10 \
    --url "smtps://${MAIL_HOST}:${MAIL_PORT}" \
    --user "${MAIL_USER}:${MAIL_PASS}" \
    --mail-from "$MAIL_FROM" \
    --mail-rcpt "$MAIL_TO" \
    --upload-file "$mail_tmp" > /dev/null 2>&1 || true
}

OVERALL_STATUS=0
FINDINGS=()
HOST_COUNT=0

# ---------------------------------------------------------------------------
# Pre-flight Konnektivitätstests — nur im Test-Modus
# ---------------------------------------------------------------------------
if [[ $TEST_MODE -eq 1 ]]; then
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
  echo -e "${BOLD}  Pre-flight Konnektivitätstests${RESET}"
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
  echo ""

  if [[ "$(uname -s)" == "Darwin" ]]; then
    _PING="ping -c 1 -t 3"
  else
    _PING="ping -c 1 -W 3"
  fi

  # 1. Internet erreichbar?
  if $_PING 8.8.8.8 &>/dev/null; then
    echo -e "  ${GREEN}✓ Internet erreichbar (8.8.8.8)${RESET}"
  else
    echo -e "  ${RED}✗ Internet nicht erreichbar (8.8.8.8)${RESET}"
  fi

  # 2. DNS + healthchecks.io
  HC_HOST="${HC_BASE#*://}"
  if $_PING "$HC_HOST" &>/dev/null; then
    echo -e "  ${GREEN}✓ DNS funktioniert, ${HC_HOST} erreichbar${RESET}"
  else
    echo -e "  ${RED}✗ ${HC_HOST} nicht auflösbar oder nicht erreichbar${RESET}"
  fi

  # 3. Test-Hosts erreichbar?
  for h in "${TARGETS[@]}"; do
    if nmap -sn "$h" 2>/dev/null | grep -q "Host is up"; then
      echo -e "  ${GREEN}✓ Test-Host erreichbar: ${h}${RESET}"
    else
      echo -e "  ${RED}✗ Test-Host nicht erreichbar: ${h}${RESET}"
    fi
  done

  echo ""
fi

for TARGET in "${TARGETS[@]}"; do
  IS_UNKNOWN=${UNKNOWN_SET[$TARGET]:-}
  TARGET_PORTS="${HOST_PORTS[$TARGET]:-}"

  # Unbekannte Hosts: nur scannen wenn sie tatsächlich antworten
  if [[ -n "$IS_UNKNOWN" ]]; then
    echo -e "  ${RED}${BOLD}⚠ Unbekannter Host gefunden: ${TARGET}${RESET}"
  fi

  (( HOST_COUNT++ )) || true

  echo ""
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
  if [[ -n "$IS_UNKNOWN" ]]; then
    echo -e "${BOLD}  Scanne: ${TARGET}  ${RED}[UNBEKANNTER HOST]${RESET}"
  else
    echo -e "${BOLD}  Scanne: ${TARGET}${RESET}"
  fi
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"

  if [[ "$TARGET_PORTS" == "-" ]]; then
    echo -e "  Erlaubte Ports: ${RED}keine — darf nicht erreichbar sein${RESET}"
  elif [[ -n "$TARGET_PORTS" ]]; then
    echo -e "  Erlaubte Ports: ${TARGET_PORTS}"
  else
    echo -e "  Erlaubte Ports: ${ALLOWED_SET} (global)"
  fi
  echo ""

  NMAP_TMP=$(mktemp)
  nmap -v --open -p 1-10000 -T4 --stats-every 30s "$TARGET" 2>&1 | tee "$NMAP_TMP"
  NMAP_OUTPUT=$(cat "$NMAP_TMP")
  rm -f "$NMAP_TMP"

  if echo "$NMAP_OUTPUT" | grep -q "Host seems down"; then
    [[ -z "$IS_UNKNOWN" ]] && echo -e "  ${YELLOW}⚠ Host antwortet nicht oder ist nicht erreichbar.${RESET}"
    continue
  fi

  OPEN_PORTS=$(echo "$NMAP_OUTPUT" | grep -E '^[0-9]+/(tcp|udp)\s+open' || true)

  if [[ -z "$OPEN_PORTS" ]]; then
    if [[ -n "$IS_UNKNOWN" ]]; then
      echo -e "  ${YELLOW}⚠ Hinweis: Unbekannter Host entdeckt. servers.conf aktuell?${RESET}"
      FINDINGS+=("UNBEKANNTER HOST  ${TARGET}  (aktiv, keine offenen Ports)")
      OVERALL_STATUS=1
    elif [[ "$TARGET_PORTS" == "-" ]]; then
      echo -e "  ${GREEN}✓ Keine offenen Ports — korrekt so.${RESET}"
    else
      echo -e "  ${GREEN}✓ Keine offenen Ports gefunden.${RESET}"
    fi
    continue
  fi

  HOST_STATUS=0

  echo -e "  ${BOLD}Offene Ports:${RESET}"
  while IFS= read -r line; do
    PORT=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
    if [[ -n "$IS_UNKNOWN" ]]; then
      echo -e "  ${RED}✗ UNBEKANNTER HOST: ${line}${RESET}"
      FINDINGS+=("UNBEKANNTER HOST  ${TARGET}  ${line}")
      HOST_STATUS=1
      OVERALL_STATUS=1
    elif is_allowed "$TARGET" "$PORT"; then
      echo -e "  ${GREEN}✓ ${line}${RESET}"
    else
      echo -e "  ${RED}✗ UNERLAUBT: ${line}${RESET}"
      FINDINGS+=("UNERLAUBTER PORT  ${TARGET}  ${line}")
      HOST_STATUS=1
      OVERALL_STATUS=1
    fi
    [[ "$PORT" == "53" ]] && check_dns_recursive "$TARGET"
  done <<< "$OPEN_PORTS"

  echo ""
  if [[ $HOST_STATUS -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}✓ Alle offenen Ports sind erlaubt.${RESET}"
  else
    echo -e "  ${RED}${BOLD}✗ ACHTUNG: Unerlaubte Ports gefunden!${RESET}"
  fi
done

echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
if [[ $OVERALL_STATUS -eq 0 ]]; then
  echo -e "${GREEN}${BOLD}  Ergebnis: Alle Server OK — keine unerlaubten Ports.${RESET}"
else
  echo -e "${RED}${BOLD}  Ergebnis: ACHTUNG — ${#FINDINGS[@]} Problem(e) gefunden!${RESET}"
  echo ""
  printf "  ${BOLD}%-24s  %-22s  %s${RESET}\n" "Art" "Host" "Detail"
  printf "  %s\n" "$(printf '─%.0s' {1..70})"
  for f in "${FINDINGS[@]}"; do
    F_TYPE=$(awk -F'  ' '{print $1}' <<< "$f")
    F_HOST=$(awk -F'  ' '{print $2}' <<< "$f")
    F_DETAIL=$(awk -F'  ' '{for(i=3;i<=NF;i++) printf "%s%s",$i,(i<NF?"  ":""); print ""}' <<< "$f")
    printf "  ${RED}%-24s  %-22s  %s${RESET}\n" "$F_TYPE" "$F_HOST" "$F_DETAIL"
  done
fi
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
echo ""

# ---------------------------------------------------------------------------
# Log-Eintrag schreiben — bei Problemen immer, im Test-Modus auch bei OK
# ---------------------------------------------------------------------------
if [[ $OVERALL_STATUS -ne 0 || $TEST_MODE -eq 1 ]]; then
  {
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    if [[ $OVERALL_STATUS -eq 0 ]]; then
      echo "[${TIMESTAMP}] OK    — ${HOST_COUNT} Host(s) geprüft [TEST], keine Probleme"
    else
      echo "[${TIMESTAMP}] FAIL  — ${HOST_COUNT} Host(s) geprüft${TEST_MODE:+ [TEST]}, ${#FINDINGS[@]} Problem(e):"
      for f in "${FINDINGS[@]}"; do
        echo "    ${f}"
      done
    fi
  } >> "$LOG_FILE"

  if [[ $(wc -l < "$LOG_FILE") -gt $MAX_LOG_LINES ]]; then
    tail -n "$MAX_LOG_LINES" "$LOG_FILE" > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "$LOG_FILE"
  fi
fi

CLEAN_OUTPUT=$(sed 's/\x1B\[[0-9;]*[mK]//g' "$TMPFILE" \
  | grep -v '^Connect Scan Timing:' \
  | grep -v '^Stats: ')
SCAN_DATE=$(date '+%Y-%m-%d %H:%M')

# ---------------------------------------------------------------------------
# healthchecks.io Ping
# ---------------------------------------------------------------------------
if [[ -n "$HC_UUID" && $TEST_MODE -eq 0 && "$HC_ENABLED" == "true" ]]; then
  if [[ $OVERALL_STATUS -eq 0 ]]; then
    curl -fsS --retry 3 --max-time 10 \
      --data-binary "$CLEAN_OUTPUT" \
      "${HC_BASE}/${HC_UUID}" > /dev/null 2>&1 || true
  else
    curl -fsS --retry 3 --max-time 10 \
      --data-binary "$CLEAN_OUTPUT" \
      "${HC_BASE}/${HC_UUID}/fail" > /dev/null 2>&1 || true
  fi
fi

# ---------------------------------------------------------------------------
# Mail-Benachrichtigung
# ---------------------------------------------------------------------------
if [[ $TEST_MODE -eq 1 ]]; then
  MAIL_PREFIX="[Port Scanner][TEST]"
else
  MAIL_PREFIX="[Port Scanner]"
fi

MAIL_BODY="$CLEAN_OUTPUT"

if [[ $OVERALL_STATUS -eq 0 ]]; then
  send_mail "${MAIL_PREFIX} OK - ${HOST_COUNT} Hosts geprueft, ${SCAN_DATE}" "$MAIL_BODY"
else
  send_mail "${MAIL_PREFIX} FAIL - ${#FINDINGS[@]} Problem(e) gefunden, ${SCAN_DATE}" "$MAIL_BODY"
fi

BLACKLIST_SCRIPT="${SCRIPT_DIR}/check-blacklist.sh"
if [[ -f "$BLACKLIST_SCRIPT" && $TEST_MODE -eq 0 ]]; then
  echo ""
  bash "$BLACKLIST_SCRIPT" "${UNKNOWN_HOSTS[@]+"${UNKNOWN_HOSTS[@]}"}"
fi

# Stdout/Stderr schließen damit der tee-Subprozess sauber beendet wird
exec 1>&- 2>&-
wait
exit $OVERALL_STATUS
