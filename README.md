# Port Scanner — example.com Rechenzentrum

Überwacht alle Server im Rechenzentrum auf unerlaubte offene Ports.  
Läuft automatisch per Cron-Job auf dem Raspberry Pi und meldet Probleme an healthchecks.io.

---

## Hintergrund

Die öffentlichen IPs (203.0.113.x) haben **keinen vorgelagerten Perimeter-Firewall** — was auf einem Proxmox-Host oder einer VM offen ist, ist direkt aus dem Internet erreichbar. Schutz auf VM-Ebene bietet ausschließlich die **Proxmox-Firewall**. Die internen Netze (Management, IPMI, VPN, etc.) sind über **MikroTik**-Geräte abgesichert und nicht öffentlich erreichbar.

Der Scanner läuft von außen () und prüft was das Internet tatsächlich sieht — so fällt auf wenn die Proxmox-Firewall einer VM fehlt oder falsch konfiguriert ist.

Erlaubt sind grundsätzlich nur:
- **80 / 443** — HTTP/HTTPS (alle Webserver)
- **25, 465, 587, 143, 993, 110, 995, 4190** — Mailports (nur Stalwart-Mailserver)
- **9876** — SSH (nur Bastion-Host / Jump-Server)

Alles andere ist ein Fund und löst eine Warnung aus.

---

## DNS-Rekursionsprüfung

Wird bei einem Host **Port 53 (DNS) offen** gefunden, prüft der Scanner automatisch ob der Server als **offener rekursiver Resolver** betrieben wird — d.h. ob er DNS-Anfragen für beliebige externe Domains beantwortet.

Ein offener Resolver ist ein ernstes Sicherheitsproblem:
- Er kann für **DNS-Amplification-Angriffe** missbraucht werden (DDoS-Verstärker)
- Er verstößt gegen Best Practices und führt oft zur Aufnahme in Blacklists

**Verhalten des Scanners:**

| Befund | Ausgabe | Wirkung |
|---|---|---|
| Port 53 offen, Rekursion festgestellt | `⚠ OFFENER REKURSIVER DNS` (rot) | FINDINGS + Mail + HC-Fail |
| Port 53 offen, keine Rekursion | `⚠ DNS-Port 53 offen — keine externe Rekursion` (gelb) | nur Hinweis |
| Port 53 offen, dig/nslookup fehlt | `⚠ Rekursionsprüfung übersprungen` (gelb) | nur Hinweis |

Die Prüfung erfolgt zusätzlich zur normalen Portbewertung — Port 53 kann also gleichzeitig als **unerlaubt** und als **rekursiver Resolver** gemeldet werden.

**Voraussetzung:** `dig` aus dem Paket `dnsutils` (Fallback: `nslookup`):
```bash
sudo apt install dnsutils
```

---

## Blacklist-Check

Nach jedem Port-Scan startet `scan-ports.sh` automatisch `check-blacklist.sh`. Das Script prüft alle öffentlichen IPs aus `servers.conf` (Hosts mit Ports ≠ `-`) sowie alle im CIDR-Scan neu entdeckten unbekannten Hosts gegen gängige **DNSBL-Blacklists**:

| DNSBL | Schwerpunkt |
|---|---|
| `zen.spamhaus.org` | Spam, Exploits, Botnets, dynamische IPs |
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
| `servers.conf` | Liste aller Server mit ihren jeweils erlaubten Ports |
| `mail.conf` | SMTP-Zugangsdaten (nicht im Repo — von `mail.conf.example` ableiten) |
| `mail.conf.example` | Vorlage für mail.conf |
| `hc.conf` | healthchecks.io UUID (nicht im Repo — von `hc.conf.example` ableiten) |
| `hc.conf.example` | Vorlage für hc.conf |
| `scan-ports.log` | Wird nur bei Problemen beschrieben, max. 500 Zeilen (SD-Karte!) |
| `check-blacklist.log` | Protokoll der Blacklist-Checks, max. 200 Zeilen |
| `.gitignore` | Hält Logs, mail.conf und hc.conf aus dem Git-Repo raus |

---

## servers.conf — Konfiguration der Server

Jede Zeile definiert einen Server und seine erlaubten Ports:

```
# IP               Erlaubte Ports        Flag    Kommentar
203.0.113.20      80,443                        # docker — nur Web
203.0.113.35      80,443,25,465,...      test   # Mailserver — Test-Host
203.0.113.30      -                             # postgres — darf gar nichts offen haben
203.0.113.40      9876                          # Bastion — nur SSH
```

**Bedeutung der Port-Spalte:**

| Eintrag | Bedeutung |
|---|---|
| `80,443` | Nur diese Ports sind erlaubt |
| `-` | Kein einziger Port darf offen sein |
| *(leer)* | Wie `-` — kein Port erlaubt (deny by default) |

**Dritte Spalte `test`** — markiert einen Host als Test-Host für `--test` Modus (schneller Einzelscan ohne Discovery).

**Kommentare** können VM-ID, Hostname und DNS-Name enthalten — rein informativ, haben keinen Einfluss auf den Scan:
```
203.0.113.20  80,443  # VM 101 — docker
203.0.113.40  9876    # CT 200 — bastion01 / SSH-Jump (jump.it.example.com)
```

**CIDR-Zeilen** (z.B. `203.0.113.0/26`) lösen zusätzlich einen Discovery-Scan aus:  
Alle aktiven Hosts im Subnetz werden gefunden. Hosts die **nicht** in der Liste stehen werden je nach Ergebnis gemeldet:

| Situation | Verhalten |
|---|---|
| Unbekannte IP, keine offenen Ports | still ignoriert |
| Unbekannte IP, offene Ports gefunden | ✗ ALARM — Mail + HC-Fail + Blacklist-Check |

Der Discovery-Scan verwendet `--open` — IPs ohne echte OPEN-Ports (z.B. reine RST-Antworten des Routers) werden nie als "unbekannt" gemeldet.

### Neuen Server hinzufügen

Einfach eine neue Zeile eintragen:
```
203.0.113.50      80,443                # neuer Webserver
```

Ohne diese Zeile würde der Server beim nächsten Scan als "unbekannter Host" auftauchen (weil er per CIDR-Scan entdeckt wird).

---

## Einstellungen

**Log-Größe** — aktuell 500 Zeilen (~1,5 Jahre bei täglichem Scan):
```bash
MAX_LOG_LINES=500
```

**mail.conf** — SMTP-Zugangsdaten für Mail-Benachrichtigung:
```bash
cp mail.conf.example mail.conf
# Zugangsdaten eintragen
```

**hc.conf** — healthchecks.io UUID:
```bash
cp hc.conf.example hc.conf
# UUID eintragen
```

---

## Ausführen

```bash
# Einmalig manuell (alle Server aus servers.conf):
./scan-ports.sh

# Einzelnen Host direkt prüfen (ohne servers.conf):
./scan-ports.sh 203.0.113.35

# Mehrere Hosts direkt:
./scan-ports.sh 203.0.113.20 203.0.113.35
```

Ein Scan aller Server dauert auf dem Pi ca. **20–30 Minuten**.

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
0 2 * * * /port-scanner/scan-ports.sh
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
    UNERLAUBTER PORT       203.0.113.2   53/tcp  open  domain
    OFFENER REKURSIVER DNS 203.0.113.2   (löst externe Domains auf — DNS-Amplification-Risiko)
    UNBEKANNTER HOST       203.0.113.55  22/tcp  open  ssh
```

---

## GitHub

Repo: **https://github.com/bse275/port-scanner** (privat)

Änderungen pushen:
```bash
git add scan-ports.sh servers.conf
git commit -m "Kurze Beschreibung"
git push
```

> `scan-ports.log`, `mail.conf` und `hc.conf` sind in `.gitignore` — werden nie ins Repo eingecheckt.

---

## Voraussetzungen

- `nmap` — `sudo apt install nmap`
- `curl` — üblicherweise vorinstalliert
- `dig` — `sudo apt install dnsutils` (für DNS-Rekursionsprüfung und Blacklist-Check; Fallback für Rekursionsprüfung: `nslookup`)
- Raspberry Pi (oder beliebiger Linux-Rechner) mit Internetzugang Richtung RZ
