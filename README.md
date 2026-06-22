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
| `scan-ports.log` | Wird nur bei Problemen beschrieben, max. 500 Zeilen (SD-Karte!) |
| `.gitignore` | Hält Log und mail.conf aus dem Git-Repo raus |

---

## servers.conf — Konfiguration der Server

Jede Zeile definiert einen Server und seine erlaubten Ports:

```
# IP               Erlaubte Ports        Kommentar
203.0.113.20      80,443                # docker — nur Web
203.0.113.35      80,443,25,465,587,143,993,110,995,4190   # Mailserver
203.0.113.30      -                     # postgres — darf gar nichts offen haben
203.0.113.40      9876                  # Bastion — nur SSH
```

**Bedeutung der Port-Spalte:**

| Eintrag | Bedeutung |
|---|---|
| `80,443` | Nur diese Ports sind erlaubt |
| `-` | Kein einziger Port darf offen sein |
| *(leer)* | Wie `-` — kein Port erlaubt (deny by default) |

**CIDR-Zeilen** (z.B. `203.0.113.0/26`) lösen zusätzlich einen Discovery-Scan aus:  
Alle aktiven Hosts im Subnetz werden gefunden. Hosts die **nicht** in der Liste stehen werden als **UNBEKANNTER HOST** markiert — das ist ein Fund. Damit fällt z.B. eine vergessene Test-VM auf.

### Neuen Server hinzufügen

Einfach eine neue Zeile eintragen:
```
203.0.113.50      80,443                # neuer Webserver
```

Ohne diese Zeile würde der Server beim nächsten Scan als "unbekannter Host" auftauchen (weil er per CIDR-Scan entdeckt wird).

---

## scan-ports.sh — Einstellungen

Am Anfang des Scripts gibt es zwei Stellen zum Anpassen:

**healthchecks.io UUID** (Zeile ~27):
```bash
HC_UUID=""   # UUID von healthchecks.io eintragen
```

**Log-Größe** (Zeile ~33) — aktuell 500 Zeilen (~1,5 Jahre bei täglichem Scan:
```bash
MAX_LOG_LINES=500
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

Ein Scan aller Server dauert je nach Antwortverhalten der Hosts ca. **15–40 Minuten**.

---

## Test-Flags

| Flag | Beschreibung |
|---|---|
| `--dry-run` / `-n` | Config einlesen und anzeigen, kein Scan, kein Mail, kein Log |
| `--test` / `-t` | Nur als `test` markierte Hosts in servers.conf scannen |
| `--mail-test` | Testmail senden und beenden (braucht mail.conf) |
| `--hc-test` | Testping an healthchecks.io senden und beenden (braucht hc.conf) |
| `--hc-fail` | Fail-Ping an healthchecks.io simulieren (braucht hc.conf) |

Flags können kombiniert werden:

```bash
# Config prüfen ohne zu scannen:
./scan-ports.sh --dry-run

# Nur Test-Hosts scannen (schnell):
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

---

## Automatischer Betrieb (Cron)

```bash
crontab -e
```

Beispiel: täglich um 06:00 Uhr:
```
0 6 * * * /home/benny/port-scanner/scan-ports.sh
```

---

## healthchecks.io einrichten

healthchecks.io ist ein kostenloser Dienst der Alarm schlägt wenn ein Job **nicht** läuft oder **fehlschlägt**.

1. Account anlegen auf [healthchecks.io](https://healthchecks.io)
2. Neuen Check anlegen:
   - **Period:** 24 hours (oder wie oft der Cron-Job läuft)
   - **Grace Time:** 90 Minuten (Puffer für die Scan-Dauer)
3. Die UUID aus der Check-URL kopieren und in `scan-ports.sh` eintragen
4. Alarmierung per E-Mail, Slack, etc. konfigurieren

Das Script sendet:
- `/start` — wenn der Job beginnt
- Erfolgs-Ping mit Scan-Log — wenn alles OK
- `/fail` mit Scan-Log — wenn unerlaubte Ports gefunden wurden
- Kein Ping — wenn der Raspberry Pi oder das Script selbst ausgefallen ist → healthchecks.io meldet das nach der Grace Time

---

## Log-Datei

`scan-ports.log` im gleichen Verzeichnis — wird **nur bei Problemen** beschrieben, wächst maximal auf 500 Zeilen:

```
[2026-06-17 06:00:01] FAIL  — 12 Hosts geprüft, 2 Problem(e):
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

> `scan-ports.log` ist in `.gitignore` — wird nie ins Repo eingecheckt.

---

## Voraussetzungen

- `nmap` — `sudo apt install nmap`
- `curl` — üblicherweise vorinstalliert
- Raspberry Pi (oder beliebiger Linux-Rechner) mit Internetzugang Richtung RZ
