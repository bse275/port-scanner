# Port Scanner — example.com Rechenzentrum

Überwacht alle Server im Rechenzentrum auf unerlaubte offene Ports.  
Läuft automatisch per Cron-Job auf dem Raspberry Pi und meldet Probleme an healthchecks.io.

---

## Hintergrund

Unser Uplink im RZ hat **keine eigene Firewall** — jeder Port der auf einem Server offen ist, ist direkt aus dem Internet erreichbar. Dieses Script prüft regelmäßig ob das noch dem entspricht was wir erlaubt haben.

Erlaubt sind grundsätzlich nur:
- **80 / 443** — HTTP/HTTPS (alle Webserver)
- **25, 465, 587, 143, 993, 110, 995, 4190** — Mailports (nur Stalwart-Mailserver)
- **9876** — SSH (nur Bastion-Host / Jump-Server)

Alles andere ist ein Fund und löst eine Warnung aus.

---

## Dateien

| Datei | Zweck |
|---|---|
| `scan-ports.sh` | Hauptscript — führt den Scan durch |
| `servers.conf` | Liste aller Server mit ihren jeweils erlaubten Ports |
| `mail.conf` | SMTP-Zugangsdaten (nicht im Repo — von `mail.conf.example` ableiten) |
| `mail.conf.example` | Vorlage für mail.conf |
| `hc.conf` | healthchecks.io UUID (nicht im Repo — von `hc.conf.example` ableiten) |
| `hc.conf.example` | Vorlage für hc.conf |
| `scan-ports.log` | Wird nur bei Problemen beschrieben, max. 500 Zeilen (SD-Karte!) |
| `.gitignore` | Hält Log, mail.conf und hc.conf aus dem Git-Repo raus |

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
| Unbekannte IP, antwortet nicht | still ignoriert |
| Unbekannte IP, antwortet, keine Ports offen | ⚠ Hinweis — Mail + HC-Fail |
| Unbekannte IP, antwortet, Ports offen | ✗ ALARM — Mail + HC-Fail |

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

# Kombination — Test-Hosts ohne Scan:
./scan-ports.sh --test --dry-run
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
0 2 * * * /home/benny/port-scanner/scan-ports.sh
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
[2026-06-23 02:00:01] FAIL  — 13 Host(s) geprüft, 2 Problem(e):
    UNERLAUBTER PORT  203.0.113.2   53/tcp  open  domain
    UNBEKANNTER HOST  203.0.113.55  22/tcp  open  ssh
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
- Raspberry Pi (oder beliebiger Linux-Rechner) mit Internetzugang Richtung RZ
