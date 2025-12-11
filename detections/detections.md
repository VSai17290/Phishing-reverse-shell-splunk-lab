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
