# Port Scanner

Überwacht Server auf unerlaubte offene Ports.  
Läuft automatisch per Cron-Job (z.B. auf einem Raspberry Pi) und meldet Probleme per Mail und an healthchecks.io.

---

## Hintergrund

Öffentliche Server ohne vorgelagerte Perimeter-Firewall sind direkt aus dem Internet erreichbar. Der Scanner läuft von außen und prüft was das Internet tatsächlich sieht — so fällt auf wenn eine Firewall-Regel fehlt oder falsch konfiguriert ist.

Erlaubt sind grundsätzlich nur:
- **80 / 443** — HTTP/HTTPS (alle Webserver)
- **25, 465, 587, 143, 993, 110, 995, 4190** — Mailports (nur Mailserver)
- **9876** — SSH (nur Bastion-Host / Jump-Server)

Alles andere ist ein Fund und löst eine Warnung aus.

---

## DNS-Rekursionsprüfung

Wird bei einem Host **Port 53 (DNS) offen** gefunden, prüft der Scanner automatisch ob der Server als **offener rekursiver Resolver** betrieben wird — d.h. ob er DNS-Anfragen für beliebige externe Domains beantwortet.

Ein offener Resolver ist ein ernstes Sicherheitsproblem:
- Er kann für **DNS-Amplification-Angriffe** missbraucht werden (DDoS-Verstärker)
- Er verstößt gegen Best Practices und führt oft zur Aufnahme in Blacklists

**Verhalten des Scanners:**

Port 53 wird zuerst wie jeder andere Port bewertet (erlaubt oder nicht erlaubt). Die Rekursionsprüfung läuft danach immer zusätzlich — unabhängig davon ob der Port erlaubt ist:

| Situation | Port-Bewertung | Rekursionsbefund | Wirkung |
|---|---|---|---|
| Port 53 offen, **nicht erlaubt**, keine Rekursion | `✗ UNERLAUBTER PORT` | `⚠ keine Rekursion` (gelb) | HC-Fail + Mail |
| Port 53 offen, **nicht erlaubt**, Rekursion | `✗ UNERLAUBTER PORT` + `✗ OFFENER REKURSIVER DNS` | (rot) | HC-Fail + Mail (2 Findings) |
| Port 53 offen, **erlaubt**, keine Rekursion | `✓ OK` | `⚠ keine Rekursion` (gelb) | kein Alarm |
| Port 53 offen, **erlaubt**, Rekursion | `✓ OK` | `✗ OFFENER REKURSIVER DNS` (rot) | HC-Fail + Mail |
| Port 53 offen, dig/nslookup fehlt | erlaubt oder nicht | `⚠ Rekursionsprüfung übersprungen` (gelb) | je nach Port-Bewertung |

**Voraussetzung:** `dig` aus dem Paket `dnsutils` (Fallback: `nslookup`):
```bash
sudo apt install dnsutils
```

---

## Blacklist-Check

Nach jedem Port-Scan startet `scan-ports.sh` automatisch `check-blacklist.sh`. Das Script prüft alle öffentlichen IPs aus `servers.conf` (Hosts mit Ports ≠ `-`) sowie alle im CIDR-Scan neu entdeckten unbekannten Hosts gegen gängige **DNSBL-Blacklists**:

| DNSBL | Schwerpunkt |
|---|---|
| `bl.spamcop.net` | Spam-Quellen |
| `dnsbl.sorbs.net` | Spam + offene Proxies |
| `b.barracudacentral.org` | Spam-Quellen |
| `dnsbl-1.uceprotect.net` | Spam-Quellen |
| `psbl.surriel.com` | Passive Spam-Blockliste |
| `spam.dnsbl.sorbs.net` | SORBS Spam-spezifisch |

Bei einem Treffer wird eine Mail verschickt. Das Script kann auch eigenständig ausgeführt werden:

```bash
# Manueller Blacklist-Check:
./check-blacklist.sh

# Dry-Run — kein Mailversand:
./check-blacklist.sh --dry-run

# Config prüfen:
./check-blacklist.sh --test-config
```

> Im `--test` Modus von `scan-ports.sh` wird `check-blacklist.sh` **nicht** gestartet.

---

## Dateien

| Datei | Zweck |
|---|---|
| `scan-ports.sh` | Hauptscript — führt den Port-Scan durch, startet danach `check-blacklist.sh` |
| `check-blacklist.sh` | Prüft alle öffentlichen IPs gegen DNSBL-Blacklists |
| `servers.conf` | Liste aller Server mit ihren jeweils erlaubten Ports (nicht im Repo, liegt unter `/etc/port-scanner/`) |
| `servers.conf.example` | Vorlage für servers.conf |
| `mail.conf` | SMTP-Zugangsdaten (nicht im Repo, liegt unter `/etc/port-scanner/` — von `mail.conf.example` ableiten) |
| `mail.conf.example` | Vorlage für mail.conf |
| `hc.conf` | healthchecks.io UUID (nicht im Repo, liegt unter `/etc/port-scanner/` — von `hc.conf.example` ableiten) |
| `hc.conf.example` | Vorlage für hc.conf |
| `scan-ports.log` | Wird nur bei Problemen beschrieben, max. 500 Zeilen (SD-Karte!) |
| `check-blacklist.log` | Protokoll der Blacklist-Checks, max. 200 Zeilen |
| `.gitignore` | Hält Logs, servers.conf, mail.conf und hc.conf aus dem Git-Repo raus |

> **Config-Verzeichnis:** `servers.conf`, `mail.conf` und `hc.conf` liegen standardmäßig
> unter `/etc/port-scanner/`, getrennt vom Script-Verzeichnis — analog zu
> `dns-watchdog`/`ssl-watchdog`. Überschreibbar per Umgebungsvariable
> `PORT_SCANNER_CONFIG_DIR` (z. B. für lokale Tests). Logs (`*.log`) bleiben im
> Script-Verzeichnis.

---

## servers.conf — Konfiguration der Server

Jede Zeile definiert einen Server und seine erlaubten Ports:

```
# IP               Erlaubte Ports        Flag    Kommentar
203.0.113.0        -                     skip    # Netzwerkadresse
203.0.113.10       80,443                        # Webserver — nur Web
203.0.113.50       80,443,25,465,...     test    # Mailserver — Test-Host
203.0.113.20       -                             # Datenbankserver — darf gar nichts offen haben
203.0.113.40       9876                          # Bastion — nur SSH
```

**Bedeutung der Port-Spalte:**

| Eintrag | Bedeutung |
|---|---|
| `80,443` | Nur diese Ports sind erlaubt |
| `-` | Kein einziger Port darf offen sein |
| *(leer)* | Globaler Fallback `ALLOWED_PORTS` greift (Standard: 80, 443) |

> **Wichtig:** Eine leere Port-Spalte bedeutet **nicht** "kein Port erlaubt" — sie fällt auf die Variable `ALLOWED_PORTS` am Anfang von `scan-ports.sh` zurück, die aktuell `80` und `443` enthält. Das betrifft in der Praxis nur Hosts die per Kommandozeile direkt übergeben werden (`./scan-ports.sh <ip>`), ohne Eintrag in `servers.conf`. Für alle Hosts in `servers.conf` sollte immer eine explizite Port-Spalte gesetzt sein.

**Dritte Spalte** — optionales Flag pro Host:

| Flag | Bedeutung |
|---|---|
| `test` | Wird im `--test` Modus gescannt — Pre-flight Checks + Einzelscan ohne Discovery |
| `skip` | Wird beim Scan immer übersprungen — sinnvoll für Gateway und Broadcast-Adressen |

**CIDR-Zeilen** (z.B. `203.0.113.0/26`) lösen zusätzlich einen Discovery-Scan aus:  
Alle aktiven Hosts im Subnetz werden gefunden. Der Discovery-Scan prüft die Ports `80, 443, 22, 25, 465, 587, 993, 9876` — Hosts ohne offene Ports in diesem Set gelten nicht als aktiv (`--open`). Hosts die **nicht** in der Liste stehen werden je nach Ergebnis gemeldet:

| Situation | Verhalten |
|---|---|
| Unbekannte IP, keine offenen Ports | still ignoriert |
| Unbekannte IP, offene Ports gefunden | ✗ ALARM — Mail + HC-Fail + Blacklist-Check |

Der Discovery-Scan verwendet `--open` — IPs ohne echte OPEN-Ports (z.B. reine RST-Antworten des Routers) werden nie als "unbekannt" gemeldet.

### Neuen Server hinzufügen

Einfach eine neue Zeile eintragen:
```
203.0.113.60       80,443                # neuer Webserver
```

Ohne diese Zeile würde der Server beim nächsten Scan als "unbekannter Host" auftauchen (weil er per CIDR-Scan entdeckt wird).

---

## Einstellungen

**Globaler Port-Fallback** — greift wenn ein Host keine Port-Spalte in `servers.conf` hat (z.B. bei direktem Aufruf per Kommandozeile):
```bash
ALLOWED_PORTS=(
  80    # HTTP
  443   # HTTPS
)
```
Für alle Hosts in `servers.conf` gilt dieser Fallback **nicht** — dort zählt immer die explizit eingetragene Port-Spalte. Um den Fallback zu deaktivieren (strict deny by default für direkte Aufrufe), einfach leer lassen:
```bash
ALLOWED_PORTS=()
```

**Log-Größe** — aktuell 500 Zeilen (~1,5 Jahre bei täglichem Scan):
```bash
MAX_LOG_LINES=500
```

**servers.conf** — Liste der Server:
```bash
mkdir -p /etc/port-scanner
cp servers.conf.example /etc/port-scanner/servers.conf
# Server und erlaubte Ports eintragen
```

**mail.conf** — SMTP-Zugangsdaten für Mail-Benachrichtigung:
```bash
cp mail.conf.example /etc/port-scanner/mail.conf
# Zugangsdaten eintragen
```

Der Scanner sendet nach jedem Scan eine Mail — bei OK und bei FAIL (im `--test` Modus mit `[TEST]`-Prefix). Um Mail komplett zu deaktivieren: `MAIL_ENABLED="false"` in `mail.conf` setzen.

**hc.conf** — healthchecks.io UUID:
```bash
cp hc.conf.example /etc/port-scanner/hc.conf
# UUID eintragen
```

---

## Ausführen

```bash
# Einmalig manuell (alle Server aus servers.conf):
./scan-ports.sh

# Einzelnen Host direkt prüfen (ohne servers.conf):
./scan-ports.sh 203.0.113.10

# Mehrere Hosts direkt:
./scan-ports.sh 203.0.113.10 203.0.113.50
```

Alle Hosts werden parallel gescannt. Ein Scan aller Server dauert auf dem Pi ca. **20–30 Minuten**.

---

## Test-Flags

| Flag | Beschreibung |
|---|---|
| `--test-config` | Config-Dateien prüfen (servers.conf, mail.conf, hc.conf) und beenden |
| `--test` / `-t` | Nur als `test` markierte Hosts scannen, inkl. Pre-flight Checks |
| `--mail-test` | Testmail senden und beenden (braucht mail.conf) |
| `--hc-test` | Testping an healthchecks.io senden und beenden (braucht hc.conf) |
| `--hc-fail` | Fail-Ping an healthchecks.io simulieren (braucht hc.conf) |

Flags können kombiniert werden:

```bash
# Config-Dateien prüfen:
./scan-ports.sh --test-config

# Nur Test-Hosts scannen (schnell, inkl. Pre-flight Checks):
./scan-ports.sh --test

# Mail-Versand testen:
./scan-ports.sh --mail-test

# healthchecks.io testen:
./scan-ports.sh --hc-test

# Fail-Alarm in healthchecks.io auslösen:
./scan-ports.sh --hc-fail

# Kombination — Config prüfen und danach Test-Scan:
./scan-ports.sh --test-config && ./scan-ports.sh --test
```

Der `--test` Modus führt vor dem Scan automatisch folgende Pre-flight Checks durch:
1. Internet erreichbar? (Ping 8.8.8.8)
2. DNS + healthchecks.io erreichbar?
3. Test-Host(s) erreichbar?

---

## Automatischer Betrieb (Cron)

```bash
crontab -e
```

Beispiel: täglich um 02:00 Uhr nachts:
```
0 2 * * * /home/admin/monitoring/scan-ports.sh
```

---

## healthchecks.io einrichten

healthchecks.io ist ein kostenloser Dienst der Alarm schlägt wenn ein Job **nicht** läuft oder **fehlschlägt**.

1. Account anlegen auf [healthchecks.io](https://healthchecks.io)
2. Neuen Check anlegen:
   - **Period:** 24 hours (oder wie oft der Cron-Job läuft)
   - **Grace Time:** 90 Minuten (Puffer für die Scan-Dauer)
3. Die UUID aus der Check-URL kopieren und in `hc.conf` eintragen
4. Alarmierung per E-Mail, Slack, etc. konfigurieren

Das Script sendet:
- `/start` — wenn der Job beginnt
- Erfolgs-Ping mit Scan-Output — wenn alles OK
- `/fail` mit Scan-Output — wenn unerlaubte Ports gefunden wurden
- Kein Ping — wenn der Raspberry Pi oder das Script selbst ausgefallen ist → healthchecks.io meldet das nach der Grace Time

> Im `--test` Modus werden **keine** Pings an healthchecks.io gesendet.

---

## Log-Datei

`scan-ports.log` im gleichen Verzeichnis:
- **Normalbetrieb:** nur bei Problemen (FAIL)
- **`--test` Modus:** immer, auch bei OK (mit `[TEST]` Markierung)

Wächst maximal auf 500 Zeilen:

```
[2026-06-22 02:00:01] OK    — 1 Host(s) geprüft [TEST], keine Probleme
[2026-06-23 02:00:01] FAIL  — 13 Host(s) geprüft, 3 Problem(e):
    UNERLAUBTER PORT       203.0.113.1    53/tcp  open  domain
    OFFENER REKURSIVER DNS 203.0.113.1    (löst externe Domains auf — DNS-Amplification-Risiko)
    UNBEKANNTER HOST       203.0.113.55   22/tcp  open  ssh
```

---

## Voraussetzungen

- `nmap` — `sudo apt install nmap`
- `curl` — üblicherweise vorinstalliert
- `dig` — `sudo apt install dnsutils` (für DNS-Rekursionsprüfung und Blacklist-Check; Fallback für Rekursionsprüfung: `nslookup`)
- Raspberry Pi oder beliebiger Linux-Rechner mit Internetzugang zu den Ziel-Servern
