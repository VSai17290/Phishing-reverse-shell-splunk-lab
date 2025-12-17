# Splunk Search Queries (SPL)

## 1. Baseline / Health Checks

### 1.1 Confirm ingestion into endpoint index
```
index=endpoint earliest=-15m
| stats count by sourcetype
```

### 1.2 Events by host
```
index=endpoint earliest=-24h
| stats count by host
| sort - count
```
---

## 2. Detection Queries

### 2.1 Suspicious resume attachment executed
```
index=endpoint earliest=-7d
| search "resume.pdf.exe"
| table _time host User Image ParentImage CommandLine
| sort _time
```

### 2.2 EXE executed from user profile folders (Desktop / Downloads)

```
index=endpoint earliest=-7d
| search Image="\Users\\Downloads\.exe" OR Image="\Users\\Desktop\.exe"
| table _time host User Image ParentImage CommandLine
| sort _time
```

### 2.3 Outbound connection to attacker C2 (Kali IP + port)

```
index=endpoint earliest=-7d
| search "192.168.56.11" "4444"
| table _time host source dest dest_port Image
| sort _time
```

### 2.4 Any process connecting to attacker IP (looser rule)
```
index=endpoint earliest=-7d "192.168.56.11"
| table _time host source dest dest_port Image User
| sort _time
```
---

## 3. Investigation Queries

### 3.1 Full context around payload execution
```
index=endpoint earliest=-30m
| search "resume.pdf.exe"
| table _time host User Image ParentImage CommandLine
| sort _time
```

### 3.2 Child processes spawned by the malicious binary
```
index=endpoint earliest=-30m
| search ParentImage="resume.pdf.exe"
| table _time host User Image ParentImage CommandLine
| sort _time
```

### 3.3 Timeline of victim ↔ attacker activity
```
index=endpoint earliest=-30m
| search "192.168.56.10" OR "192.168.56.11"
| table _time host source dest dest_port Image
| sort _time
```

### 3.4 User activity on the victim during the incident window
```
index=endpoint host="WIN10-VICTIM" earliest=-30m
| table _time User sourcetype EventCode Image CommandLine
| sort _time
```

(Replace `WIN10-VICTIM` with your actual Windows host name.)

---

## 4. Hunting Ideas (optional)

### 4.1 Uncommon parent–child relationships involving cmd / powershell
```
index=endpoint earliest=-7d
| search Image="\cmd.exe" OR Image="\powershell.exe"
| stats count by ParentImage Image
| sort - count
```

### 4.2 Top processes making outbound connections
```
index=endpoint earliest=-7d
| search dest!="" dest_port!=""
| stats count by Image dest dest_port
| sort - count
```


