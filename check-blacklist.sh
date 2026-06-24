#!/usr/bin/env bash
# Blacklist-Checker — prüft öffentliche Server-IPs gegen gängige DNSBLs.
# Usage: ./check-blacklist.sh [--test-config] [--mail-test] [--dry-run]

set -euo pipefail

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------
TEST_CONFIG=0
MAIL_TEST=0
DRY_RUN=0
EXTRA_IPS=()
for arg in "$@"; do
  case "$arg" in
    --test-config) TEST_CONFIG=1 ;;
    --mail-test)   MAIL_TEST=1 ;;
    --dry-run)     DRY_RUN=1 ;;
    *)
      [[ "$arg" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && EXTRA_IPS+=("$arg")
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/servers.conf"
LOG_FILE="${SCRIPT_DIR}/check-blacklist.log"
MAX_LOG_LINES=200

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ---------------------------------------------------------------------------
# DNSBLs die geprüft werden
# ---------------------------------------------------------------------------
DNSBL_LIST=(
  "zen.spamhaus.org"
  "bl.spamcop.net"
  "dnsbl.sorbs.net"
  "b.barracudacentral.org"
  "dnsbl-1.uceprotect.net"
  "psbl.surriel.com"
  "spam.dnsbl.sorbs.net"
)

# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------
reverse_ip() {
  local ip="$1"
  echo "$ip" | awk -F. '{print $4"."$3"."$2"."$1}'
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
    printf "From: Blacklist Checker <%s>\r\n" "$MAIL_FROM"
    printf "To: %s\r\n" "$MAIL_TO"
    printf "Subject: %s\r\n" "$subject"
    printf "Content-Type: text/plain; charset=utf-8\r\n"
    printf "MIME-Version: 1.0\r\n"
    printf "\r\n"
    echo "$body"
  } > "$mail_tmp"
  curl -fsS --retry 2 --max-time 30 \
    --url "smtps://${MAIL_HOST}:${MAIL_PORT}" \
    --user "${MAIL_USER}:${MAIL_PASS}" \
    --mail-from "$MAIL_FROM" \
    --mail-rcpt "$MAIL_TO" \
    --upload-file "$mail_tmp" > /dev/null 2>&1 || true
}

append_log() {
  local log="$1"
  local max="$2"
  local tmp
  tmp=$(mktemp)
  {
    echo "=== $(date '+%Y-%m-%d %H:%M:%S') ==="
    cat
  } >> "$log"
  # Log auf MAX_LOG_LINES begrenzen
  local lines
  lines=$(wc -l < "$log")
  if (( lines > max )); then
    tail -n "$max" "$log" > "$tmp"
    mv "$tmp" "$log"
  fi
}

# ---------------------------------------------------------------------------
# --mail-test
# ---------------------------------------------------------------------------
if [[ $MAIL_TEST -eq 1 ]]; then
  MAIL_CONF="${SCRIPT_DIR}/mail.conf"
  if [[ ! -f "$MAIL_CONF" ]]; then
    echo -e "${RED}Fehler: mail.conf nicht gefunden${RESET}" >&2
    exit 1
  fi
  # shellcheck source=/dev/null
  source "$MAIL_CONF"
  echo -e "${BOLD}${CYAN}  Sende Testmail an ${MAIL_TO} ...${RESET}"
  send_mail "[Blacklist Checker] Testmail" "Das ist eine Testmail vom Blacklist Checker.
Server: $(hostname)
Datum:  $(date '+%Y-%m-%d %H:%M:%S')"
  echo -e "${GREEN}${BOLD}  ✓ Testmail gesendet.${RESET}"
  exit 0
fi

# ---------------------------------------------------------------------------
# --test-config
# ---------------------------------------------------------------------------
if [[ $TEST_CONFIG -eq 1 ]]; then
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
  echo -e "${BOLD}  Config-Prüfung${RESET}"
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
  echo ""

  if [[ -f "$CONFIG_FILE" ]]; then
    echo -e "  ${GREEN}✓ servers.conf gefunden${RESET}"
  else
    echo -e "  ${RED}✗ servers.conf nicht gefunden: ${CONFIG_FILE}${RESET}"
  fi

  if command -v dig &>/dev/null; then
    echo -e "  ${GREEN}✓ dig verfügbar${RESET}"
  else
    echo -e "  ${RED}✗ dig nicht gefunden (bitte bind-utils oder dnsutils installieren)${RESET}"
  fi

  if [[ -f "${SCRIPT_DIR}/mail.conf" ]]; then
    echo -e "  ${GREEN}✓ mail.conf gefunden${RESET}"
  else
    echo -e "  ${YELLOW}⚠ mail.conf fehlt — keine E-Mail-Benachrichtigung${RESET}"
  fi

  echo ""
  echo -e "  ${BOLD}Öffentliche IPs (werden geprüft):${RESET}"
  while IFS= read -r line; do
    ip=$(echo "$line" | awk '{print $1}')
    ports=$(echo "$line" | awk '{print $2}')
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
    [[ "$ports" == "-" || -z "$ports" ]] && continue
    comment=$(echo "$line" | sed 's/^[^#]*#//' | xargs)
    echo -e "  ${CYAN}→ ${ip}${RESET}  (${ports})  ${comment:+# $comment}"
  done < <(grep -v '^\s*#' "$CONFIG_FILE" | grep -v '^\s*$')
  echo ""
  exit 0
fi

# ---------------------------------------------------------------------------
# Voraussetzungen prüfen
# ---------------------------------------------------------------------------
if ! command -v dig &>/dev/null; then
  echo "Fehler: dig ist nicht installiert (bitte bind-utils oder dnsutils installieren)" >&2
  exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Fehler: servers.conf nicht gefunden: ${CONFIG_FILE}" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Öffentliche IPs aus servers.conf einlesen (nur Einträge mit Ports != "-")
# ---------------------------------------------------------------------------
PUBLIC_IPS=()
declare -A IP_COMMENT

while IFS= read -r line; do
  ip=$(echo "$line" | awk '{print $1}')
  ports=$(echo "$line" | awk '{print $2}')
  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
  [[ "$ports" == "-" || -z "$ports" ]] && continue
  PUBLIC_IPS+=("$ip")
  IP_COMMENT["$ip"]=$(echo "$line" | sed 's/^[^#]*#//' | xargs 2>/dev/null || true)
done < <(grep -v '^\s*#' "$CONFIG_FILE" | grep -v '^\s*$')

for ip in "${EXTRA_IPS[@]}"; do
  PUBLIC_IPS+=("$ip")
  IP_COMMENT["$ip"]="unbekannter Host"
done

if [[ ${#PUBLIC_IPS[@]} -eq 0 ]]; then
  echo "Keine öffentlichen IPs in servers.conf gefunden." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Scan-Ausgabe starten
# ---------------------------------------------------------------------------
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Blacklist-Check — $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  IPs:       ${#PUBLIC_IPS[@]}"
echo -e "  DNSBLs:    ${#DNSBL_LIST[@]}"
[[ $DRY_RUN -eq 1 ]] && echo -e "  ${YELLOW}DRY-RUN — keine Mail wird verschickt${RESET}"
echo ""

FINDINGS=()
OVERALL_STATUS=0

# ---------------------------------------------------------------------------
# Pro IP alle DNSBLs abfragen
# ---------------------------------------------------------------------------
for ip in "${PUBLIC_IPS[@]}"; do
  comment="${IP_COMMENT[$ip]:-}"
  echo -e "${BOLD}  ${ip}${RESET}${comment:+  ${CYAN}# ${comment}${RESET}}"

  rev=$(reverse_ip "$ip")
  IP_CLEAN=1

  for dnsbl in "${DNSBL_LIST[@]}"; do
    query="${rev}.${dnsbl}"
    result=$(dig +short +time=5 +tries=1 "$query" A 2>/dev/null || true)

    if [[ -n "$result" ]]; then
      # Spamhaus-Fehlercodes abfangen (keine echten Treffer)
      if [[ "$result" == "127.255.255.255" || "$result" == "127.255.255.254" ]]; then
        echo -e "    ${YELLOW}⚠ ${dnsbl}  →  Abfrage abgelehnt (Spamhaus-Limit/Autorisierung — kein echter Treffer)${RESET}"
        continue
      fi

      # Bedeutung des Return-Codes nachschlagen (Spamhaus-spezifisch)
      meaning=""
      if [[ "$dnsbl" == "zen.spamhaus.org" ]]; then
        case "$result" in
          127.0.0.2) meaning=" (SBL — direktes Spamming)" ;;
          127.0.0.3) meaning=" (SBL CSS — kompromittierter Host)" ;;
          127.0.0.4|127.0.0.5|127.0.0.6|127.0.0.7) meaning=" (XBL — Exploit/Botnet)" ;;
          127.0.0.10|127.0.0.11) meaning=" (PBL — dynamische IP)" ;;
        esac
      fi
      echo -e "    ${RED}✗ GELISTET${RESET}  ${dnsbl}  →  ${result}${meaning}"
      FINDINGS+=("${ip}  |  ${dnsbl}  |  ${result}${meaning}")
      IP_CLEAN=0
      OVERALL_STATUS=1
    fi
  done

  if [[ $IP_CLEAN -eq 1 ]]; then
    echo -e "    ${GREEN}✓ Nicht gelistet${RESET}"
  fi
  echo ""
done

# ---------------------------------------------------------------------------
# Ergebnis-Zusammenfassung
# ---------------------------------------------------------------------------
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
if [[ $OVERALL_STATUS -eq 0 ]]; then
  echo -e "${BOLD}${GREEN}  ✓ Alle IPs sauber — keine Blacklist-Einträge.${RESET}"
else
  echo -e "${BOLD}${RED}  ✗ ${#FINDINGS[@]} Blacklist-Treffer gefunden!${RESET}"
  echo ""
  printf "  ${BOLD}%-18s  %-32s  %s${RESET}\n" "IP" "DNSBL" "Ergebnis"
  printf "  %s\n" "$(printf '─%.0s' {1..72})"
  for f in "${FINDINGS[@]}"; do
    F_IP=$(awk -F'  [|]  ' '{print $1}' <<< "$f")
    F_DNSBL=$(awk -F'  [|]  ' '{print $2}' <<< "$f")
    F_RESULT=$(awk -F'  [|]  ' '{print $3}' <<< "$f")
    printf "  ${RED}%-18s  %-32s  %s${RESET}\n" "$F_IP" "$F_DNSBL" "$F_RESULT"
  done
fi
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"

# ---------------------------------------------------------------------------
# Mail bei Treffern
# ---------------------------------------------------------------------------
if [[ $OVERALL_STATUS -ne 0 && $DRY_RUN -eq 0 ]]; then
  _BL_HEADER=$(printf '  %-18s  %-32s  %s\n' 'IP' 'DNSBL' 'Ergebnis')
  _BL_SEP="  $(printf '─%.0s' {1..72})"
  _BL_ROWS=""
  for f in "${FINDINGS[@]}"; do
    F_IP=$(awk -F'  [|]  ' '{print $1}' <<< "$f")
    F_DNSBL=$(awk -F'  [|]  ' '{print $2}' <<< "$f")
    F_RESULT=$(awk -F'  [|]  ' '{print $3}' <<< "$f")
    _BL_ROWS+="$(printf '  %-18s  %-32s  %s\n' "$F_IP" "$F_DNSBL" "$F_RESULT")"
  done
  MAIL_BODY="Blacklist-Check: ${#FINDINGS[@]} Treffer gefunden!

Server: $(hostname)
Datum:  $(date '+%Y-%m-%d %H:%M:%S')

Treffer:
${_BL_HEADER}
${_BL_SEP}
${_BL_ROWS}
Bitte sofort prüfen und ggf. Delisting beantragen.
Spamhaus:   https://www.spamhaus.org/lookup/
Barracuda:  https://www.barracudacentral.org/lookups
SORBS:      http://www.sorbs.net/lookup.shtml
SpamCop:    https://www.spamcop.net/bl.shtml"

  send_mail "[Blacklist Checker] ALARM: ${#FINDINGS[@]} IP(s) auf Blacklist" "$MAIL_BODY"
fi

# ---------------------------------------------------------------------------
# Log schreiben
# ---------------------------------------------------------------------------
{
  if [[ $OVERALL_STATUS -eq 0 ]]; then
    echo "OK — alle ${#PUBLIC_IPS[@]} IPs sauber"
  else
    echo "ALARM — ${#FINDINGS[@]} Treffer:"
    printf '  %s\n' "${FINDINGS[@]}"
  fi
} | append_log "$LOG_FILE" "$MAX_LOG_LINES"

exit $OVERALL_STATUS
