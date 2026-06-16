#!/usr/bin/env bash
# Port compliance scanner — checks servers for unexpected open ports.
# Usage: ./scan-ports.sh [host1 host2 ...]  (ohne Argumente: liest servers.conf)

set -euo pipefail

# ---------------------------------------------------------------------------
# Allowed ports (adjust as needed)
# ---------------------------------------------------------------------------
ALLOWED_PORTS=(
  80    # HTTP
  443   # HTTPS
  25    # SMTP
  465   # SMTPS
  587   # SMTP Submission
  143   # IMAP
  993   # IMAPS
  110   # POP3
  995   # POP3S
  4190  # Sieve (Stalwart)
  9876  # SSH — nur Bastion-Host (jump.it.example.com / 203.0.113.40)
)

# ---------------------------------------------------------------------------
# healthchecks.io — UUID eintragen, oder leer lassen um zu deaktivieren
# ---------------------------------------------------------------------------
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

if ! command -v nmap &>/dev/null; then
  echo "Fehler: nmap ist nicht installiert. Bitte mit 'sudo apt install nmap' nachinstallieren." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/servers.conf"
LOG_FILE="${SCRIPT_DIR}/scan-ports.log"

# Alle Ausgaben in Tempfile mitschreiben (für healthchecks.io Body bei Fehler)
TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT
exec > >(tee "$TMPFILE") 2>&1

# ---------------------------------------------------------------------------
# Hosts und CIDR-Ranges einlesen
# ---------------------------------------------------------------------------
KNOWN_HOSTS=()
CIDR_RANGES=()

if [[ $# -eq 0 ]]; then
  if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Fehler: Keine Argumente und keine servers.conf gefunden (erwartet: ${CONFIG_FILE})" >&2
    echo "Verwendung: $0 <host_oder_ip> [host2 ...]" >&2
    exit 1
  fi
  while IFS= read -r line; do
    if [[ "$line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
      CIDR_RANGES+=("$line")
    else
      KNOWN_HOSTS+=("$line")
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
# CIDR-Ranges: Discovery-Scan — unbekannte Hosts finden
# ---------------------------------------------------------------------------
UNKNOWN_HOSTS=()

for CIDR in "${CIDR_RANGES[@]}"; do
  echo ""
  echo -e "${BOLD}${YELLOW}  Discovery-Scan: ${CIDR}${RESET}"
  # TCP-basierter Ping auf häufige Ports — zuverlässiger als ICMP
  while IFS= read -r ip; do
    is_known=0
    for known in "${KNOWN_HOSTS[@]}"; do
      [[ "$ip" == "$known" ]] && is_known=1 && break
    done
    if [[ $is_known -eq 0 ]]; then
      echo -e "  ${RED}${BOLD}⚠ UNBEKANNTER HOST entdeckt: ${ip}${RESET}"
      UNKNOWN_HOSTS+=("$ip")
    else
      echo -e "  ${GREEN}✓ Bekannt: ${ip}${RESET}"
    fi
  done < <(nmap -sn -PS80,443,25,9876 "$CIDR" -oG - 2>/dev/null \
    | grep "^Host:" | awk '{print $2}')
done

# ---------------------------------------------------------------------------
# Scan-Ziele zusammenstellen: bekannte + unbekannte Hosts
# ---------------------------------------------------------------------------
TARGETS=("${KNOWN_HOSTS[@]}")
for h in "${UNKNOWN_HOSTS[@]}"; do
  TARGETS+=("$h")
done

# Lookup-Set für unbekannte Hosts
declare -A UNKNOWN_SET
for h in "${UNKNOWN_HOSTS[@]}"; do
  UNKNOWN_SET["$h"]=1
done

echo ""
echo -e "  Bekannte Hosts:    ${#KNOWN_HOSTS[@]}"
echo -e "  CIDR-Ranges:       ${#CIDR_RANGES[@]}"
echo -e "  Unbekannte Hosts:  ${#UNKNOWN_HOSTS[@]}"

# /start-Ping: healthchecks.io weiß, dass der Job läuft
if [[ -n "$HC_UUID" ]]; then
  curl -fsS --retry 3 --max-time 10 "${HC_BASE}/${HC_UUID}/start" > /dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
ALLOWED_SET=$(IFS=, ; echo "${ALLOWED_PORTS[*]}")

is_allowed() {
  local port="$1"
  for p in "${ALLOWED_PORTS[@]}"; do
    [[ "$p" == "$port" ]] && return 0
  done
  return 1
}

OVERALL_STATUS=0
FINDINGS=()
HOST_COUNT=0

for TARGET in "${TARGETS[@]}"; do
  (( HOST_COUNT++ )) || true
  IS_UNKNOWN=${UNKNOWN_SET[$TARGET]:-}

  echo ""
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
  if [[ -n "$IS_UNKNOWN" ]]; then
    echo -e "${BOLD}  Scanne: ${TARGET}  ${RED}[UNBEKANNTER HOST]${RESET}"
    OVERALL_STATUS=1
  else
    echo -e "${BOLD}  Scanne: ${TARGET}${RESET}"
  fi
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
  echo -e "  Erlaubte Ports: ${ALLOWED_SET}"
  echo ""

  NMAP_OUTPUT=$(nmap -sV --open -p 1-10000 "$TARGET" 2>&1)

  if echo "$NMAP_OUTPUT" | grep -q "Host seems down"; then
    echo -e "  ${YELLOW}⚠ Host antwortet nicht oder ist nicht erreichbar.${RESET}"
    continue
  fi

  OPEN_PORTS=$(echo "$NMAP_OUTPUT" | grep -E '^[0-9]+/(tcp|udp)\s+open' || true)

  if [[ -z "$OPEN_PORTS" ]]; then
    echo -e "  ${GREEN}✓ Keine offenen Ports gefunden.${RESET}"
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
    elif is_allowed "$PORT"; then
      echo -e "  ${GREEN}✓ ${line}${RESET}"
    else
      echo -e "  ${RED}✗ UNERLAUBT: ${line}${RESET}"
      FINDINGS+=("UNERLAUBTER PORT  ${TARGET}  ${line}")
      HOST_STATUS=1
      OVERALL_STATUS=1
    fi
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
  echo -e "${RED}${BOLD}  Ergebnis: ACHTUNG — Probleme gefunden!${RESET}"
fi
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
echo ""

# ---------------------------------------------------------------------------
# Log-Eintrag schreiben
# ---------------------------------------------------------------------------
{
  TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
  if [[ $OVERALL_STATUS -eq 0 ]]; then
    echo "[${TIMESTAMP}] OK    — ${HOST_COUNT} Hosts geprüft, keine Probleme"
  else
    echo "[${TIMESTAMP}] FAIL  — ${HOST_COUNT} Hosts geprüft, ${#FINDINGS[@]} Problem(e):"
    for f in "${FINDINGS[@]}"; do
      echo "    ${f}"
    done
  fi
} >> "$LOG_FILE"

if [[ $(wc -l < "$LOG_FILE") -gt $MAX_LOG_LINES ]]; then
  tail -n "$MAX_LOG_LINES" "$LOG_FILE" > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "$LOG_FILE"
fi

# ---------------------------------------------------------------------------
# healthchecks.io Ping
# ---------------------------------------------------------------------------
if [[ -n "$HC_UUID" ]]; then
  HC_BODY=$(sed 's/\x1B\[[0-9;]*[mK]//g' "$TMPFILE")
  if [[ $OVERALL_STATUS -eq 0 ]]; then
    curl -fsS --retry 3 --max-time 10 \
      --data-binary "$HC_BODY" \
      "${HC_BASE}/${HC_UUID}" > /dev/null 2>&1 || true
  else
    curl -fsS --retry 3 --max-time 10 \
      --data-binary "$HC_BODY" \
      "${HC_BASE}/${HC_UUID}/fail" > /dev/null 2>&1 || true
  fi
fi

exit $OVERALL_STATUS
